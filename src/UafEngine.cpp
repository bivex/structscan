/**
 * @file UafEngine.cpp
 * @brief !uaf — Use-After-Free Object Lifetime Analyzer
 *
 * Formal model enforced:
 *   ALLOC(O) -> LIVE(O) -> FREE(O) -> [REUSE(O)] -> USE(O)
 *                                         ^
 *                       Invariant violation: USE(O) => LIVE(O) must hold
 *
 * Five analysis phases:
 *   1. Pool Header  — checks PoolType, tag validity, free-list linkage
 *   2. OBJECT_HEADER — checks PointerCount / HandleCount reference counts
 *   3. Content      — Shannon entropy + Bayesian field classifier snapshot
 *   4. Dangling Refs — pointer scan in kernel VA range for back-references
 *   5. Risk Report  — weighted score, lifetime verdict, WinDbg BP recipe
 *
 * Usage:
 *   !uaf <sym|addr> [objsize=0x200] [searchbytes=0x8000]
 *
 * Examples:
 *   !uaf nt!PsInitialSystemProcess 0x480
 *   !uaf ffff8001`234abcd0 0x200 0x20000
 *   !uaf win32k!gpdi 0x300
 */

#include "../include/structscan.h"
#include <cwchar>
#include <algorithm>

// ─────────────────────────────────────────────────────────────────────────────
// Internal Structures
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Classic Windows kernel POOL_HEADER (x64, pre-segment-heap interpretation).
 * Located at allocation_VA - 0x10.
 * In Win10 19H1+ segment heap this may be unreliable for some allocators,
 * but ExAllocatePoolWithTag still uses it for non-large allocations.
 */
#pragma pack(push, 1)
struct POOL_HEADER_X64 {
    union {
        struct {
            uint32_t PreviousSize : 8;
            uint32_t PoolIndex    : 8;
            uint32_t BlockSize    : 8;
            uint32_t PoolType     : 8;
        };
        uint32_t Ulong1;
    };
    uint32_t PoolTag;
    uint64_t ExtendedInfo; // ProcessBilled or AllocatorBackTrace hash
};
#pragma pack(pop)
static_assert(sizeof(POOL_HEADER_X64) == 16, "POOL_HEADER_X64 must be 16 bytes");

/**
 * OBJECT_HEADER offsets for x64 Windows 10+ (ntoskrnl, all recent builds).
 * Object body starts at OBJECT_HEADER + 0x30.
 */
static constexpr ULONG kObjBodyOffset      = 0x30;
static constexpr ULONG kObjPtrCountOff     = 0x00; // INT64 PointerCount
static constexpr ULONG kObjHandleCountOff  = 0x08; // INT64 HandleCount
static constexpr ULONG kObjTypeIndexOff    = 0x18; // UINT8 TypeIndex
static constexpr ULONG kObjInfoMaskOff     = 0x1A; // UINT8 InfoMask
static constexpr ULONG kObjFlagsOff        = 0x1B; // UINT8 Flags

// Maximum dangling references to collect before stopping (keeps scan fast)
static constexpr size_t kMaxDanglingRefs = 32;

// ─────────────────────────────────────────────────────────────────────────────
// Lifetime State
// ─────────────────────────────────────────────────────────────────────────────

enum class LifetimeState : uint8_t {
    Unknown = 0,
    Live    = 1, // Object appears alive, references valid
    Suspect = 2, // Ambiguous signals — needs deeper investigation
    Freed   = 3, // High confidence the object has been freed
};

static const wchar_t* LifetimeStateName(LifetimeState s) {
    switch (s) {
        case LifetimeState::Live:    return L"LIVE";
        case LifetimeState::Suspect: return L"SUSPECT";
        case LifetimeState::Freed:   return L"FREED";
        default:                     return L"UNKNOWN";
    }
}

static bool IsKernelVA(uint64_t v) {
    return (v >= 0xFFFF000000000000ULL && v < 0xFFFFFFFFFFFFFFFFULL);
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 1 — Pool Header
// ─────────────────────────────────────────────────────────────────────────────

struct PoolAnalysis {
    bool     readable       = false;
    bool     tagPrintable   = false;
    bool     suspectFree    = false; // true => evidence of freed state
    uint32_t tag            = 0;
    uint32_t poolType       = 0;
    uint32_t blockSize      = 0;     // in 16-byte granules
    uint32_t previousSize   = 0;
};

static PoolAnalysis AnalyzePoolHeader(IDebugDataSpaces4* ds, ULONG64 objAddr) {
    PoolAnalysis pa{};
    if (objAddr < 0x10) return pa;

    const ULONG64 hdrAddr = objAddr - 0x10;
    POOL_HEADER_X64 hdr{};
    ULONG rd = 0;
    if (FAILED(ds->ReadVirtual(hdrAddr, &hdr, sizeof(hdr), &rd)) || rd < sizeof(hdr))
        return pa;

    pa.readable      = true;
    pa.tag           = hdr.PoolTag;
    pa.poolType      = (hdr.Ulong1 >> 24) & 0xFF;
    pa.blockSize     = (hdr.Ulong1 >> 16) & 0xFF;
    pa.previousSize  = (hdr.Ulong1)        & 0xFF;

    // Pool tag validity: all 4 bytes must be printable ASCII (or 0 = space padding)
    bool tagOk = true;
    for (int i = 0; i < 4; i++) {
        uint8_t b = (hdr.PoolTag >> (i * 8)) & 0xFF;
        if (b != 0 && (b < 0x20 || b > 0x7E)) { tagOk = false; break; }
    }
    pa.tagPrintable = tagOk && (hdr.PoolTag != 0);

    // Free-list linkage heuristic: when a pool chunk is freed it gets linked
    // into a lookaside/freelist via Flink/Blink at offset 0 of the user data.
    // Both values will be valid kernel VAs pointing elsewhere.
    uint64_t w0 = 0, w8 = 0;
    ULONG rd2 = 0;
    ds->ReadVirtual(objAddr,     &w0, 8, &rd2);
    ds->ReadVirtual(objAddr + 8, &w8, 8, &rd2);
    bool firstWordsAreFreeLinks = IsKernelVA(w0) && IsKernelVA(w8) &&
                                  (w0 != objAddr) && (w8 != objAddr) &&
                                  (w0 != w8);

    // Known free tag markers: 'Free', 'Frag', 'Zero'
    bool isKnownFreeTag = (hdr.PoolTag == 0x65657246 /* 'Free' */ ||
                           hdr.PoolTag == 0x67617246 /* 'Frag' */ ||
                           hdr.PoolTag == 0x6F65725A /* 'Zero' */);

    // A chunk is ONLY marked suspectFree if payload has freelist pointers
    // or if a valid pool tag explicitly indicates a free/fragmented chunk.
    // Non-printable tag alone at objAddr - 0x10 simply means no standard POOL_HEADER
    // at offset -0x10 (e.g. Big Pool, Segment Heap, or optional OBJECT_HEADER).
    pa.suspectFree = firstWordsAreFreeLinks || (pa.tagPrintable && isKnownFreeTag);

    return pa;
}

static const wchar_t* PoolTypeName(uint32_t pt) {
    switch (pt) {
        case 0:    return L"0 (NonPagedPool)";
        case 1:    return L"1 (PagedPool)";
        case 2:    return L"2 (NonPagedPoolMustSucceed)";
        case 3:    return L"3 (PagedPool Session)";
        case 0x20: return L"0x20 (NonPagedPoolNx)";
        case 0x21: return L"0x21 (PagedPoolNx)";
        default:   return L"Other";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2 — OBJECT_HEADER
// ─────────────────────────────────────────────────────────────────────────────

struct ObjHdrAnalysis {
    bool    readable          = false;
    int64_t pointerCount      = 0;
    int64_t handleCount       = 0;
    uint8_t typeIndex         = 0;
    uint8_t infoMask          = 0;
    uint8_t flags             = 0;
    bool    refCountsSuspect  = false; // true => freed or corrupt
};

static ObjHdrAnalysis AnalyzeObjectHeader(IDebugDataSpaces4* ds, ULONG64 objAddr) {
    ObjHdrAnalysis oa{};
    if (objAddr < kObjBodyOffset) return oa;

    const ULONG64 hdrAddr = objAddr - kObjBodyOffset;
    uint8_t hdrBuf[kObjBodyOffset] = {};
    ULONG rd = 0;
    if (FAILED(ds->ReadVirtual(hdrAddr, hdrBuf, kObjBodyOffset, &rd)) || rd < kObjBodyOffset)
        return oa;

    oa.readable      = true;
    oa.pointerCount  = *reinterpret_cast<int64_t*>(hdrBuf + kObjPtrCountOff);
    oa.handleCount   = *reinterpret_cast<int64_t*>(hdrBuf + kObjHandleCountOff);
    oa.typeIndex     = hdrBuf[kObjTypeIndexOff];
    oa.infoMask      = hdrBuf[kObjInfoMaskOff];
    oa.flags         = hdrBuf[kObjFlagsOff];

    // PointerCount <= 0 means object was fully dereferenced (freed path).
    // HandleCount < 0 is the encoded "closed" state in some object managers.
    oa.refCountsSuspect = (oa.pointerCount <= 0)
                       || (oa.handleCount  < 0);

    return oa;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3 — Content Entropy + Classifier Snapshot
// ─────────────────────────────────────────────────────────────────────────────

struct ContentAnalysis {
    bool   readable              = false;
    double overallEntropy        = 0.0;
    ULONG  longestZeroRunOffset  = 0;
    ULONG  longestZeroRunLen     = 0;
    bool   looksCorrupted        = false; // very low entropy or majority zeros
};

static ContentAnalysis AnalyzeContent(IDebugDataSpaces4* ds, ULONG64 addr, ULONG size) {
    ContentAnalysis ca{};
    std::vector<uint8_t> buf(size);
    ULONG rd = 0;
    if (FAILED(ds->ReadVirtual(addr, buf.data(), size, &rd)) || rd < 16)
        return ca;

    ca.readable        = true;
    ca.overallEntropy  = SmartFieldAnalyzer::ComputeEntropy(buf.data(), rd);

    // Find longest zero run
    ULONG runStart = 0, runLen = 0, maxStart = 0, maxLen = 0;
    bool inRun = false;
    for (ULONG i = 0; i < rd; i++) {
        if (buf[i] == 0) {
            if (!inRun) { runStart = i; runLen = 0; inRun = true; }
            if (++runLen > maxLen) { maxLen = runLen; maxStart = runStart; }
        } else {
            inRun = false;
        }
    }
    ca.longestZeroRunOffset = maxStart;
    ca.longestZeroRunLen    = maxLen;

    // Freed/zeroed memory: very low entropy across a large region,
    // or more than half the bytes are zero.
    ca.looksCorrupted = (ca.overallEntropy < 1.0 && rd > 64)
                     || (maxLen > rd / 2);

    return ca;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 4 — Dangling Reference Scan
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Scans [scanStart, scanStart+scanBytes) in 4KB chunks looking for any
 * 8-byte aligned value equal to targetAddr. Returns addresses of all matches.
 * Caps at kMaxDanglingRefs to avoid long output.
 */
static std::vector<ULONG64> ScanDanglingRefs(
    IDebugControl4*    ctrl,
    IDebugDataSpaces4* ds,
    ULONG64            targetAddr,
    ULONG64            scanStart,
    ULONG              scanBytes
) {
    std::vector<ULONG64> refs;
    constexpr ULONG kChunk = 0x1000;
    uint8_t chunk[kChunk] = {};

    for (ULONG64 pos = scanStart; pos < scanStart + scanBytes; pos += kChunk) {
        // Respect Ctrl+C
        if (ctrl->GetInterrupt() == S_OK) break;

        ULONG rd = 0;
        if (FAILED(ds->ReadVirtual(pos, chunk, kChunk, &rd)) || rd < 8)
            continue; // page not resident — skip

        for (ULONG i = 0; i + 8 <= rd; i += 8) {
            uint64_t v = *reinterpret_cast<const uint64_t*>(chunk + i);
            if (v == targetAddr) {
                refs.push_back(pos + i);
                if (refs.size() >= kMaxDanglingRefs) return refs;
            }
        }
    }
    return refs;
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper — separator line
// ─────────────────────────────────────────────────────────────────────────────
static void Sep(IDebugControl4* ctrl, const wchar_t* title) {
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n[=== %s ===]\n", title);
}

// ─────────────────────────────────────────────────────────────────────────────
// DoUafAnalysis — main entry point called from Main.cpp
// ─────────────────────────────────────────────────────────────────────────────

HRESULT DoUafAnalysis(
    IDebugControl4*    ctrl,
    IDebugSymbols4*    sym,
    IDebugDataSpaces4* ds,
    const wchar_t*     target,
    ULONG              objSize,
    ULONG              searchBytes
) {
    // ── Banner ──────────────────────────────────────────────────────────────
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n"
        L"================================================================\n"
        L"  StructScan !uaf v4.0  --  Object Lifetime Analyzer\n"
        L"  Model: ALLOC->LIVE->FREE->[REUSE]->USE  |  USE=>LIVE must hold\n"
        L"================================================================\n\n");

    // ── Resolve target ──────────────────────────────────────────────────────
    ULONG64 addr = ResolveTarget(ctrl, sym, target, nullptr, nullptr, 0, nullptr);
    if (addr == 0) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"[-] Cannot resolve target: %s\n", target);
        return E_FAIL;
    }

    // Try reverse lookup for a friendly symbol label
    wchar_t symLabel[256] = {};
    ULONG64 disp = 0;
    bool hasSym = SUCCEEDED(sym->GetNameByOffsetWide(addr, symLabel, _countof(symLabel), nullptr, &disp));

    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  Target   : %s\n", target);
    if (hasSym) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  Symbol   : %s", symLabel);
        if (disp > 0) ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"+0x%llx", disp);
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"\n");
    }
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  Address  : 0x%016llx\n"
        L"  ObjSize  : 0x%lx bytes\n"
        L"  Search   : 0x%lx bytes (centered on object)\n\n",
        static_cast<unsigned long long>(addr),
        static_cast<unsigned long>(objSize),
        static_cast<unsigned long>(searchBytes));

    // ── Scoring state ────────────────────────────────────────────────────────
    // Each phase contributes evidence for/against UAF.
    // riskScore 0-100: >= 70 = Freed, >= 35 = Suspect, < 35 = Live
    int riskScore      = 0;
    int evidenceItems  = 0;

    // ── PHASE 1: Pool Header ─────────────────────────────────────────────────
    Sep(ctrl, L"PHASE 1 · Pool Header Analysis  (object - 0x10)");

    auto pool = AnalyzePoolHeader(ds, addr);
    if (!pool.readable) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  [!] Pool header at 0x%016llx is NOT readable\n"
            L"      (memory may be paged out, or this is not a pool allocation)\n",
            static_cast<unsigned long long>(addr - 0x10));
    } else {
        // Format pool tag as 4 ASCII chars
        wchar_t tagChars[8] = {};
        for (int i = 0; i < 4; i++) {
            uint8_t b = (pool.tag >> (i * 8)) & 0xFF;
            tagChars[i] = (b >= 0x20 && b <= 0x7E) ? static_cast<wchar_t>(b) : L'?';
        }
        // Look up known tag
        const PoolTagInfo* ti = SmartFieldAnalyzer::FindPoolTag(pool.tag);

        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  PoolHeader : 0x%016llx\n",
            static_cast<unsigned long long>(addr - 0x10));
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  PoolTag    : '%c%c%c%c' (0x%08x)%s%S%s\n",
            tagChars[0], tagChars[1], tagChars[2], tagChars[3],
            pool.tag,
            ti ? L" -> " : L"",
            ti ? ti->description : "",
            pool.tagPrintable ? L"" : L"  [!] NON-PRINTABLE TAG");
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  PoolType   : %s\n", PoolTypeName(pool.poolType));
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  BlockSize  : 0x%02x  (-> 0x%lx bytes allocation)\n",
            pool.blockSize,
            static_cast<unsigned long>(pool.blockSize) * 16UL);

        if (pool.suspectFree) {
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"  [!] Pool header/payload suggests FREED state:\n");
            {
                uint64_t w0 = 0, w8 = 0; ULONG rd2 = 0;
                ds->ReadVirtual(addr,     &w0, 8, &rd2);
                ds->ReadVirtual(addr + 8, &w8, 8, &rd2);
                if (IsKernelVA(w0) && IsKernelVA(w8) && w0 != addr && w8 != addr && w0 != w8) {
                    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                        L"      - Object[+0]  = 0x%016llx  (free-list Flink?)\n"
                        L"      - Object[+8]  = 0x%016llx  (free-list Blink?)\n",
                        static_cast<unsigned long long>(w0),
                        static_cast<unsigned long long>(w8));
                }
            }
            riskScore    += 40;
            evidenceItems++;
        } else if (pool.tagPrintable) {
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"  [+] Pool header consistent with LIVE allocation\n");
        } else {
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"  [*] No standard POOL_HEADER at -0x10 (BigPool / SegmentHeap / Optional OBJECT_HEADER)\n");
        }
    }

    // ── PHASE 2: OBJECT_HEADER ───────────────────────────────────────────────
    Sep(ctrl, L"PHASE 2 · OBJECT_HEADER Analysis  (object - 0x30)");

    auto oh = AnalyzeObjectHeader(ds, addr);
    if (!oh.readable) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  [!] OBJECT_HEADER at 0x%016llx not readable\n"
            L"      (target may not be a kernel object, or header is paged out)\n",
            static_cast<unsigned long long>(addr - kObjBodyOffset));
    } else {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  ObjHeader  : 0x%016llx\n",
            static_cast<unsigned long long>(addr - kObjBodyOffset));
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  PointerCnt : %lld%s\n",
            static_cast<long long>(oh.pointerCount),
            oh.pointerCount <= 0 ? L"  [!] <= 0 (FREED/fully dereferenced)" : L"");
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  HandleCnt  : %lld%s\n",
            static_cast<long long>(oh.handleCount),
            oh.handleCount < 0 ? L"  [!] < 0 (closed/freed encoding)" : L"");
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  TypeIndex  : 0x%02x   Flags: 0x%02x   InfoMask: 0x%02x\n",
            oh.typeIndex, oh.flags, oh.infoMask);

        if (oh.refCountsSuspect) {
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"  [!] Reference counts are SUSPECT — object may be freed/corrupted\n");
            riskScore    += 30;
            evidenceItems++;
        } else if (oh.pointerCount > 0 && oh.handleCount >= 0 && oh.typeIndex > 0) {
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"  [+] Reference counts indicate LIVE Object (PointerCount=%lld, HandleCount=%lld)\n",
                static_cast<long long>(oh.pointerCount),
                static_cast<long long>(oh.handleCount));
            // Strong counter-evidence for live objects: reduce risk score
            riskScore = (std::max)(0, riskScore - 25);
        } else {
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"  [+] Reference counts look LIVE (PointerCount > 0)\n");
            riskScore = (std::max)(0, riskScore - 10);
        }
    }

    // ── PHASE 3: Content Analysis ────────────────────────────────────────────
    Sep(ctrl, L"PHASE 3 · Content Analysis (entropy + field classifier)");

    auto ca = AnalyzeContent(ds, addr, objSize);
    if (!ca.readable) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  [!] Object content not readable\n");
    } else {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  Entropy    : %.3f bits  (8.0 = random, 0.0 = all-zero)\n",
            ca.overallEntropy);
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  Zero run   : 0x%lx bytes @ +0x%04lx\n",
            static_cast<unsigned long>(ca.longestZeroRunLen),
            static_cast<unsigned long>(ca.longestZeroRunOffset));

        if (ca.looksCorrupted) {
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"  [!] Very low entropy / large zero region — content SUSPECT\n"
                L"      (freed allocator may zero memory or leave freelist ptrs)\n");
            riskScore    += 20;
            evidenceItems++;
        } else {
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"  [+] Content entropy normal for a live object\n");
            riskScore = (std::max)(0, riskScore - 5);
        }

        // Bayesian field snapshot (first min(objSize, 0x80) bytes)
        SmartFieldAnalyzer analyzer;
        analyzer.DataSpaces = ds;
        analyzer.Symbols    = sym;

        std::vector<uint8_t> objBuf(objSize);
        ULONG rd3 = 0;
        if (SUCCEEDED(ds->ReadVirtual(addr, objBuf.data(), objSize, &rd3)) && rd3 >= 8) {
            ULONG snapshotBytes = std::min(rd3, static_cast<ULONG>(0x80));
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"\n  Field snapshot (first 0x%lx bytes, confidence > 30%%):\n",
                static_cast<unsigned long>(snapshotBytes));
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"  Offset    Address               Type              "
                L"Entropy  Confidence  Annotation\n"
                L"  --------  --------------------  ----------------  "
                L"-------  ----------  ------------------------------\n");

            ULONG fieldCount = 0;
            for (ULONG off = 0; off + 8 <= snapshotBytes; ) {
                auto fa = analyzer.Analyze(objBuf.data(), rd3, off, addr);
                if (fa.type != FieldType::Unknown &&
                    fa.type != FieldType::Padding  &&
                    fa.confidence > 0.30)
                {
                    PrintField(ctrl, fa);
                    fieldCount++;
                }
                off += (fa.size > 0) ? fa.size : 8;
                if (fieldCount >= 8) break;
            }
            if (fieldCount == 0) {
                ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                    L"  (no high-confidence fields — object may be zeroed or freed)\n");
                riskScore    += 10;
                evidenceItems++;
            }
        }
    }

    // ── PHASE 4: Dangling Reference Scan ─────────────────────────────────────
    Sep(ctrl, L"PHASE 4 · Dangling Reference Scan");

    // Center the scan window on the object address
    ULONG64 scanStart = (addr > static_cast<ULONG64>(searchBytes) / 2)
                        ? addr - searchBytes / 2
                        : addr;

    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  Scanning 0x%016llx .. 0x%016llx\n"
        L"  Looking for 8-byte aligned pointers == 0x%016llx\n"
        L"  (Ctrl+C aborts scan early)\n\n",
        static_cast<unsigned long long>(scanStart),
        static_cast<unsigned long long>(scanStart + searchBytes),
        static_cast<unsigned long long>(addr));

    auto refs = ScanDanglingRefs(ctrl, ds, addr, scanStart, searchBytes);

    if (refs.empty()) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  [+] No back-references found in scanned range\n"
            L"      (try wider search: !uaf %s 0x%lx 0x%lx)\n",
            target,
            static_cast<unsigned long>(objSize),
            static_cast<unsigned long>(searchBytes * 4));
    } else {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  Found %llu pointer(s) referencing 0x%016llx:\n\n",
            static_cast<unsigned long long>(refs.size()),
            static_cast<unsigned long long>(addr));

        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  Ref Address           Symbol\n"
            L"  --------------------  --------------------------------------------------\n");

        for (ULONG64 refAddr : refs) {
            wchar_t sn[256] = {}; ULONG64 sd = 0;
            std::wstring label;
            if (SUCCEEDED(sym->GetNameByOffsetWide(refAddr, sn, _countof(sn), nullptr, &sd))) {
                label = sn;
                if (sd > 0) {
                    wchar_t db[32] = {};
                    swprintf_s(db, L"+0x%llx", static_cast<unsigned long long>(sd));
                    label += db;
                }
            } else {
                label = L"<no symbol>";
            }
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"  0x%016llx    %s\n",
                static_cast<unsigned long long>(refAddr),
                label.c_str());
        }

        // If pool state already suggests freed OR object header ref counts are suspect
        if (pool.suspectFree || oh.refCountsSuspect) {
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"\n  [!!] FREED object with %llu dangling pointer(s) -- STRONG UAF SIGNAL\n",
                static_cast<unsigned long long>(refs.size()));
            riskScore    += 50;
            evidenceItems += 2;
        } else {
            // Live object referenced from nearby structures
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"\n  [+] Object has %llu active reference(s) from nearby kernel structures.\n",
                static_cast<unsigned long long>(refs.size()));
        }
    }

    // ── PHASE 5: Risk Report ─────────────────────────────────────────────────
    // Clamp score
    if (riskScore > 100) riskScore = 100;
    if (riskScore < 0)   riskScore = 0;

    LifetimeState state;
    if      (riskScore >= 70) state = LifetimeState::Freed;
    else if (riskScore >= 35) state = LifetimeState::Suspect;
    else                      state = LifetimeState::Live;

    // ASCII risk bar (40 chars)
    constexpr int kBarW = 40;
    wchar_t riskBar[kBarW + 1] = {};
    int barFill = (riskScore * kBarW) / 100;
    for (int i = 0; i < kBarW; i++) {
        if (i < barFill) {
            riskBar[i] = (riskScore >= 70) ? L'#' :
                         (riskScore >= 35) ? L'=' : L'-';
        } else {
            riskBar[i] = L'.';
        }
    }
    riskBar[kBarW] = L'\0';

    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n"
        L"================================================================\n"
        L"  PHASE 5 -- UAF Risk Report\n"
        L"================================================================\n"
        L"\n"
        L"  Object  : 0x%016llx\n"
        L"  State   : %s\n"
        L"  Score   : %d / 100   (evidence items: %d)\n"
        L"  Risk    : [%s] %d%%\n"
        L"\n",
        static_cast<unsigned long long>(addr),
        LifetimeStateName(state),
        riskScore, evidenceItems,
        riskBar, riskScore);

    switch (state) {
    case LifetimeState::Freed:
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  [!!!] HIGH RISK -- LIKELY USE-AFTER-FREE\n"
            L"\n"
            L"  Evidence:\n"
            L"    - Pool header / free-list linkage indicate FREED state\n"
            L"    - %llu dangling pointer(s) still reference this address\n"
            L"    - Object content entropy / ref-counts are SUSPECT\n"
            L"\n"
            L"  WinDbg Breakpoint Recipe:\n"
            L"    ba r8 0x%016llx   <- break on any READ of freed object\n"
            L"    ba w8 0x%016llx   <- break on re-use/overwrite by allocator\n"
            L"\n"
            L"  Formal model at this address:\n"
            L"    t_free < t_use  =>  UAF(O) proven\n"
            L"    Lifetime(O) = [t_alloc, t_free)\n"
            L"    t_use NOT IN Lifetime(O)  =>  USE-AFTER-FREE\n"
            L"\n"
            L"  Next Steps:\n"
            L"    1. !structscan 0x%016llx 0x%lx   -- deep field analysis\n"
            L"    2. Check dangling ref addresses above for caller context\n"
            L"    3. kb / k to correlate with current call stack\n",
            static_cast<unsigned long long>(refs.size()),
            static_cast<unsigned long long>(addr),
            static_cast<unsigned long long>(addr),
            static_cast<unsigned long long>(addr),
            static_cast<unsigned long>(objSize));
        break;

    case LifetimeState::Suspect:
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  [!]  MODERATE RISK -- AMBIGUOUS LIFETIME STATE\n"
            L"\n"
            L"  Some signals suggest UAF but evidence is not conclusive.\n"
            L"\n"
            L"  Next Steps:\n"
            L"    1. Widen the search: !uaf %s 0x%lx 0x%lx\n"
            L"    2. Inspect field detail: !structscan 0x%016llx 0x%lx\n"
            L"    3. Check if address was previously freed: !pool 0x%016llx\n"
            L"    4. Set a conditional bp on the object: ba r8 0x%016llx\n",
            target,
            static_cast<unsigned long>(objSize),
            static_cast<unsigned long>(searchBytes * 4),
            static_cast<unsigned long long>(addr),
            static_cast<unsigned long>(objSize),
            static_cast<unsigned long long>(addr),
            static_cast<unsigned long long>(addr));
        break;

    default: // Live
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  [+]  LOW RISK -- Object appears LIVE\n"
            L"\n"
            L"  No strong UAF indicators found in scanned range.\n"
            L"\n"
            L"  If you suspect UAF at a specific call site:\n"
            L"    - Set a bp BEFORE the suspected free: bp <free_site>\n"
            L"    - Note the VA of the object at that point\n"
            L"    - Then: !uaf <VA> 0x%lx 0x%lx  after free returns\n"
            L"    - Compare the lifetime model: t_free < t_use\n",
            static_cast<unsigned long>(objSize),
            static_cast<unsigned long>(searchBytes));
        break;
    }

    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n"
        L"  UAF Lifetime Model:\n"
        L"    ALLOC(O) -> LIVE(O) -> FREE(O) -> [REUSE(O)] -> USE(O)\n"
        L"    Violation: USE(O) requires LIVE(O) -- t_use in [t_alloc, t_free)\n"
        L"\n"
        L"================================================================\n\n");

    return S_OK;
}
