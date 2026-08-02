/**
 * @file structscan.h
 * @brief StructScan v3.5 — Intelligent Multi-Algorithm Structure Reconstruction Engine
 * @author Joseph Ryan Ries (2022) / Modernized & AI-Enhanced by Antigravity AI (2026)
 *
 * Algorithms:
 *   1. Shannon Entropy field confidence scoring
 *   2. Bayesian multi-feature type classifier
 *   3. Multi-instance LIST_ENTRY cross-reference analysis
 *   4. Pool tag forensics (50+ known NT object types)
 */

#ifndef STRUCTSCAN_H
#define STRUCTSCAN_H

#define NOMINMAX   // Prevent Windows.h from defining min/max macros
#define INITGUID
#include <windows.h>
#include <dbgeng.h>
#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <array>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <map>
#include <unordered_map>
#include <optional>

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllexport) HRESULT CALLBACK DebugExtensionInitialize(_Out_ PULONG Version, _Out_ PULONG Flags);
__declspec(dllexport) HRESULT CALLBACK structscan(_In_ IDebugClient* Client, _In_opt_ PCSTR Args);

#ifdef __cplusplus
}
#endif

// Helper macro to construct Little-Endian 4-byte uint32_t Pool Tag
constexpr uint32_t MAKE_TAG(char a, char b, char c, char d) {
    return static_cast<uint32_t>(static_cast<uint8_t>(a))        |
          (static_cast<uint32_t>(static_cast<uint8_t>(b)) << 8)  |
          (static_cast<uint32_t>(static_cast<uint8_t>(c)) << 16) |
          (static_cast<uint32_t>(static_cast<uint8_t>(d)) << 24);
}

// ─────────────────────────────────────────────────────────────────────────────
// Field Type Classification System
// ─────────────────────────────────────────────────────────────────────────────

enum class FieldType : uint8_t {
    Unknown       = 0,
    Pointer       = 1,   // Kernel-space pointer, resolves to symbol
    ListEntry     = 2,   // Circular doubly-linked LIST_ENTRY
    UnicodeString = 3,   // Windows UNICODE_STRING structure
    AsciiString   = 4,   // Inline ASCII character buffer
    PoolTag       = 5,   // 4-byte NT pool tag (e.g. 'Proc', 'Thre')
    Integer       = 6,   // ULONG / ULONG64 counter or PID
    Flags         = 7,   // Bitmask / flags word (sparse bits set)
    Handle        = 8,   // Windows HANDLE value
    Padding       = 9,   // Zero-filled or entropy-zero padding
};

static const wchar_t* FieldTypeName(FieldType t) {
    switch (t) {
        case FieldType::Pointer:       return L"Pointer";
        case FieldType::ListEntry:     return L"LIST_ENTRY";
        case FieldType::UnicodeString: return L"UNICODE_STRING";
        case FieldType::AsciiString:   return L"ASCII";
        case FieldType::PoolTag:       return L"PoolTag";
        case FieldType::Integer:       return L"Integer";
        case FieldType::Flags:         return L"Flags";
        case FieldType::Handle:        return L"Handle";
        case FieldType::Padding:       return L"Padding";
        default:                       return L"Unknown";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Field Analysis Result
// ─────────────────────────────────────────────────────────────────────────────

struct FieldAnalysis {
    ULONG        offset;
    ULONG64      address;
    uint64_t     rawValue;      // 8-byte raw value at offset
    FieldType    type;
    double       confidence;    // Bayesian confidence score [0.0 – 1.0]
    double       entropy;       // Shannon entropy of 8-byte field
    std::wstring annotation;    // Symbol name / string content
    ULONG64      ptrTarget;     // For pointers: resolved target address
    bool         isListEntry;   // Detected LIST_ENTRY (Flink + Blink)
};

// ─────────────────────────────────────────────────────────────────────────────
// Multi-Instance Cross-Reference (for list mode)
// ─────────────────────────────────────────────────────────────────────────────

struct OffsetProfile {
    ULONG                  offset;
    std::vector<FieldType> observedTypes;   // type per instance
    std::vector<double>    confidences;     // confidence per instance
    std::vector<uint64_t>  rawValues;       // raw values per instance
    FieldType              dominantType;    // most frequent type
    double                 typeConsistency; // fraction of instances agreeing on dominantType
    bool                   isInteresting;  // worth reporting
};

// ─────────────────────────────────────────────────────────────────────────────
// Known NT Pool Tags (55+ Kernel Object Pool Tags)
// ─────────────────────────────────────────────────────────────────────────────

struct PoolTagInfo {
    uint32_t    tag;
    const char* description;
    ULONG       estimatedSize;  // typical object size in bytes (0 = unknown)
};

static constexpr PoolTagInfo kKnownPoolTags[] = {
    // Executive Objects & Processes
    { MAKE_TAG('P','r','o','c'), "EPROCESS (Process)",         0xB80 },
    { MAKE_TAG('T','h','r','e'), "ETHREAD (Thread)",           0x5C0 },
    { MAKE_TAG('F','i','l','e'), "FILE_OBJECT (File)",         0x120 },
    { MAKE_TAG('D','r','i','v'), "DRIVER_OBJECT (Driver)",     0x150 },
    { MAKE_TAG('D','e','v','i'), "DEVICE_OBJECT (Device)",     0x200 },
    { MAKE_TAG('T','o','k','e'), "TOKEN (Security Token)",    0x300 },
    { MAKE_TAG('P','o','r','t'), "ALPC_PORT (LPC/ALPC Port)", 0x180 },
    { MAKE_TAG('J','o','b',' '), "JOB (Job Object)",          0x280 },
    { MAKE_TAG('E','v','n','t'), "KEVENT (Kernel Event)",     0x18  },
    { MAKE_TAG('M','u','t','x'), "KMUTANT (Mutex)",           0x38  },
    { MAKE_TAG('S','e','m',' '), "KSEMAPHORE (Semaphore)",    0x20  },
    { MAKE_TAG('T','i','m','r'), "KTIMER (Timer)",            0x40  },
    { MAKE_TAG('S','e','c','t'), "SECTION (Memory Section)", 0x90  },
    { MAKE_TAG('S','y','m','b'), "OBJECT_SYMBOLIC_LINK",     0x48  },
    { MAKE_TAG('D','i','r',' '), "OBJECT_DIRECTORY (Folder)", 0x200 },

    // Registry & I/O Subsystem
    { MAKE_TAG('K','e','y',' '), "CMKEY_BODY (Registry Key)",  0x68  },
    { MAKE_TAG(' ','I','n','T'), "IRP (I/O Request Packet)",   0x118 },
    { MAKE_TAG('I','o',' ',' '), "IO_STATUS_BLOCK",            0x10  },
    { MAKE_TAG('N','F','s',' '), "NTFS Control Block",         0x100 },
    { MAKE_TAG('F','L','t',' '), "Filter Manager Callback",    0x40  },
    { MAKE_TAG('F','l','y',' '), "Filter Manager Data",        0x80  },

    // Memory Manager & Paging
    { MAKE_TAG('P','o','o','l'), "Pool Descriptor",            0     },
    { MAKE_TAG('N','t','V','m'), "NtVm Region",                0     },
    { MAKE_TAG('H','e','a','p'), "Heap Allocation",            0     },
    { MAKE_TAG('M','m','M','l'), "MDL (Memory Descriptor)",    0x30  },
    { MAKE_TAG('M','m','L','k'), "Mm Locked Pages",            0     },
    { MAKE_TAG('M','m','V','w'), "Mm View (MMVIEW)",           0     },
    { MAKE_TAG('S','W','a','p'), "Paging File / Swap",         0     },
    { MAKE_TAG('P','t','e',' '), "PTE (Page Table Entry)",     0x8   },

    // Security & Access Control
    { MAKE_TAG('A','c','l',' '), "ACL (Access Control List)",  0     },
    { MAKE_TAG('S','e','c','u'), "SECURITY_DESCRIPTOR",        0     },

    // Executive System & Threads
    { MAKE_TAG('S','y','s','m'), "System Memory Allocation",   0     },
    { MAKE_TAG('k','W','x',' '), "WORK_QUEUE_ITEM",            0x20  },
    { MAKE_TAG('C','D','S',' '), "Code Integrity / CI",        0     },
    { MAKE_TAG('A','m','D','g'), "DMA Adapter",                0     },

    // Networking (TCB, NDIS, NetBT)
    { MAKE_TAG('D','N','d',' '), "NDIS Driver Block",          0x200 },
    { MAKE_TAG('N','T','k',' '), "NetBT Network Buffer",       0     },
    { MAKE_TAG('C','T','c',' '), "TCP Connection Block (TCB)", 0x300 },
    { MAKE_TAG('U','T','p',' '), "UDP Endpoint Block",         0x100 },
    { MAKE_TAG('I','F','s',' '), "RDBSS / IFS Mini-Redirector",0     },

    // ETW & Telemetry
    { MAKE_TAG('E','M','e','t'), "ETW_GUID_ENTRY",             0x50  },
    { MAKE_TAG('E','C','t',' '), "ETW Trace Session",          0x100 },
    { MAKE_TAG('E','T','p',' '), "ETW Provider Object",        0x80  },
    { MAKE_TAG('E','C','r',' '), "ETW Realtime Consumer",      0x80  },

    // WMI Diagnostics
    { MAKE_TAG('W','K','b',' '), "WMI Buffer",                 0x1000},
    { MAKE_TAG('W','K','g',' '), "WMI GUID Object",            0x60  },
    { MAKE_TAG('W','C','l',' '), "WPP Trace Log",              0     },

    // Plug and Play (PnP) & Power Manager
    { MAKE_TAG('P','K','a',' '), "PnP Auto-Play / Arrival",    0     },
    { MAKE_TAG('P','K','d',' '), "DEVICE_NODE (PnP DevNode)",  0x1c0 },
    { MAKE_TAG('P','K','r',' '), "PnP Relation List",          0     },
    { MAKE_TAG('P','V','d',' '), "Power Manager State",        0     },
    { MAKE_TAG('P','R','i',' '), "Power Request Object",       0x80  },

    // Hyper-V & Virtualization
    { MAKE_TAG('W','v','h',' '), "Hyper-V Hypervisor Call",    0     },
    { MAKE_TAG('H','V','s',' '), "Hyper-V Synthetic Device",   0     },
    { MAKE_TAG('H','S','m',' '), "Hyper-V Shared Memory",      0     },
    { MAKE_TAG('H','V','r',' '), "Hyper-V Root Partition",     0     },
};

// ─────────────────────────────────────────────────────────────────────────────
// Smart Field Analyzer — Core Intelligence Engine
// ─────────────────────────────────────────────────────────────────────────────

class SmartFieldAnalyzer {
public:
    IDebugDataSpaces4* DataSpaces;
    IDebugSymbols4*    Symbols;

    // ── 1. Shannon Entropy ───────────────────────────────────────────────────
    static double ComputeEntropy(const uint8_t* data, size_t len) {
        if (len == 0) return 0.0;
        uint32_t freq[256] = {};
        for (size_t i = 0; i < len; i++) freq[data[i]]++;
        double H = 0.0;
        for (auto f : freq) {
            if (f) {
                double p = static_cast<double>(f) / static_cast<double>(len);
                H -= p * log2(p);
            }
        }
        return H;
    }

    // Count set bits (popcount) — flag fields have sparse bits
    static int PopCount(uint64_t v) {
        int count = 0;
        while (v) { count += (v & 1); v >>= 1; }
        return count;
    }

    // ── 2. Pool Tag Check ────────────────────────────────────────────────────
    static const PoolTagInfo* FindPoolTag(uint32_t tagVal) {
        for (auto& pt : kKnownPoolTags) {
            if (pt.tag == tagVal) return &pt;
        }
        return nullptr;
    }

    static bool IsValidPoolTag(uint32_t tagVal) {
        // All 4 bytes should be printable ASCII
        for (int i = 0; i < 4; i++) {
            uint8_t b = (tagVal >> (i * 8)) & 0xFF;
            if (b < 0x20 || b > 0x7E) return false;
        }
        return true;
    }

    // ── 3. Bayesian Field Classification ─────────────────────────────────────
    FieldAnalysis Analyze(
        const uint8_t* buf, size_t bufSize,
        ULONG offset,
        ULONG64 baseAddr
    ) {
        FieldAnalysis result{};
        result.offset  = offset;
        result.address = baseAddr + offset;
        result.type    = FieldType::Unknown;
        result.confidence = 0.0;

        if (offset + 8 > bufSize) return result;

        const uint8_t* ptr = buf + offset;
        result.rawValue = *reinterpret_cast<const uint64_t*>(ptr);
        result.entropy  = ComputeEntropy(ptr, 8);

        // ── Feature extraction ──────────────────────────────────────────────
        bool f_allZero      = (result.rawValue == 0);
        bool f_kernelPtr    = (result.rawValue > 0xFFFF000000000000ULL);
        bool f_lowEntropy   = (result.entropy  < 1.0);
        bool f_highEntropy  = (result.entropy  > 6.5);
        bool f_smallInt     = (result.rawValue < 0x10000ULL && result.rawValue > 0);
        bool f_aligned      = ((result.rawValue & 0x7) == 0);
        bool f_sparsePopcount = false;
        bool f_validPoolTag = false;
        bool f_resolvesSym  = false;
        bool f_isListEntry  = false;
        bool f_isUnicodeStr = false;
        bool f_isAscii      = false;
        ULONG asciiLen      = 0;

        // Popcount check for flag fields (1–12 bits set in 64-bit word)
        {
            int pop = PopCount(result.rawValue);
            f_sparsePopcount = (pop >= 1 && pop <= 12 && !f_smallInt);
        }

        // Pool tag check (lower 32 bits)
        {
            uint32_t tagVal = static_cast<uint32_t>(result.rawValue & 0xFFFFFFFF);
            f_validPoolTag  = IsValidPoolTag(tagVal);
        }

        // Symbol resolution (only if kernel ptr)
        wchar_t symName[256] = {};
        ULONG64 displacement = 0;
        if (f_kernelPtr && Symbols) {
            if (SUCCEEDED(Symbols->GetNameByOffsetWide(result.rawValue, symName, _countof(symName), nullptr, &displacement))) {
                f_resolvesSym = true;
                result.annotation = symName;
                result.ptrTarget  = result.rawValue;
                if (displacement > 0) {
                    result.annotation += L"+0x";
                    wchar_t dispBuf[32] = {};
                    swprintf_s(dispBuf, L"%llx", displacement);
                    result.annotation += dispBuf;
                }
            }
        }

        // LIST_ENTRY detection: Flink->Blink == self (requires live read)
        if (f_kernelPtr && DataSpaces && offset + 16 <= bufSize) {
            uint64_t flinkVal  = result.rawValue;
            uint64_t blinkVal  = *reinterpret_cast<const uint64_t*>(ptr + 8);
            if (flinkVal > 0xFFFF000000000000ULL && blinkVal > 0xFFFF000000000000ULL) {
                // Read Flink->Blink
                uint64_t flinkBlink = 0;
                ULONG rd = 0;
                if (SUCCEEDED(DataSpaces->ReadVirtual(flinkVal + 8, &flinkBlink, sizeof(uint64_t), &rd)) && rd == 8) {
                    if (flinkBlink == result.address || flinkBlink == blinkVal) {
                        f_isListEntry = true;
                        result.isListEntry = true;
                        wchar_t leBuf[128] = {};
                        swprintf_s(leBuf, L"Flink=0x%llx Blink=0x%llx",
                            static_cast<unsigned long long>(flinkVal),
                            static_cast<unsigned long long>(blinkVal));
                        result.annotation = leBuf;
                    }
                }
            }
        }

        // UNICODE_STRING detection
        if (offset + 16 <= bufSize) {
            uint16_t uLen    = *reinterpret_cast<const uint16_t*>(ptr);
            uint16_t uMaxLen = *reinterpret_cast<const uint16_t*>(ptr + 2);
            uint64_t uBuf    = *reinterpret_cast<const uint64_t*>(ptr + 8);
            if (uLen > 0 && uLen <= uMaxLen && uMaxLen <= 1024 &&
                (uLen % 2) == 0 && uBuf > 0xFFFF000000000000ULL && DataSpaces)
            {
                std::vector<wchar_t> wstr(uLen / 2 + 1, 0);
                ULONG uRead = 0;
                if (SUCCEEDED(DataSpaces->ReadVirtual(uBuf, wstr.data(), uLen, &uRead)) && uRead > 0) {
                    bool valid = true;
                    for (size_t i = 0; i < uLen / 2 && i < 64; i++) {
                        wchar_t wc = wstr[i];
                        if (wc != 0 && (wc < 0x0020 || wc > 0xD7FF) && (wc < 0xE000 || wc > 0xFFFD)) {
                            valid = false; break;
                        }
                    }
                    if (valid) {
                        f_isUnicodeStr = true;
                        result.annotation = std::wstring(wstr.data(), uLen / 2);
                    }
                }
            }
        }

        // ASCII string run detection
        {
            size_t run = 0;
            while (offset + run < bufSize && ptr[run] >= 0x20 && ptr[run] <= 0x7E) run++;
            if (run >= 4) {
                f_isAscii = true;
                asciiLen  = static_cast<ULONG>(run);
            }
        }

        // ── Bayesian Type Decision ──────────────────────────────────────────
        struct TypeScore { FieldType type; double score; };
        std::array<TypeScore, 9> scores = {{
            { FieldType::Padding,       0.0 },
            { FieldType::ListEntry,     0.0 },
            { FieldType::UnicodeString, 0.0 },
            { FieldType::Pointer,       0.0 },
            { FieldType::AsciiString,   0.0 },
            { FieldType::PoolTag,       0.0 },
            { FieldType::Handle,        0.0 },
            { FieldType::Flags,         0.0 },
            { FieldType::Integer,       0.0 },
        }};

        auto& [t_Pad, t_List, t_Uni, t_Ptr, t_Asc, t_Tag, t_Hnd, t_Flg, t_Int] = scores;

        if (f_allZero)          { t_Pad.score  += 4.0; t_Int.score  -= 2.0; t_Ptr.score -= 3.0; }
        if (f_lowEntropy)       { t_Pad.score  += 2.0; t_Asc.score  -= 1.0; }
        if (f_isListEntry)      { t_List.score += 8.0; t_Ptr.score  -= 2.0; }
        if (f_isUnicodeStr)     { t_Uni.score  += 8.0; t_Asc.score  -= 3.0; }
        if (f_kernelPtr)        { t_Ptr.score  += 4.0; t_Int.score  -= 3.0; t_Tag.score -= 3.0; }
        if (f_resolvesSym)      { t_Ptr.score  += 4.0; }
        if (f_highEntropy && f_kernelPtr) { t_Ptr.score += 1.0; }
        if (f_isAscii)          { t_Asc.score  += 3.0 + (asciiLen > 8 ? 2.0 : 0.0); }
        if (f_isAscii && !f_kernelPtr) { t_Asc.score += 2.0; }
        if (f_validPoolTag && !f_kernelPtr && !f_smallInt) { t_Tag.score += 4.0; }
        if (f_aligned && f_smallInt) { t_Hnd.score += 1.5; }
        if ((result.rawValue & 0xFFFFFFFF00000000ULL) == 0xFFFFFFFF00000000ULL) { t_Hnd.score += 2.0; }
        if (f_sparsePopcount && !f_kernelPtr && !f_smallInt) { t_Flg.score += 2.0; }
        if (f_smallInt)         { t_Int.score  += 3.0; t_Flg.score  -= 1.0; }
        if (!f_kernelPtr && !f_isAscii && !f_isUnicodeStr && !f_validPoolTag && !f_isListEntry)
                                { t_Int.score  += 0.5; }

        auto winner = std::max_element(scores.begin(), scores.end(),
            [](const TypeScore& a, const TypeScore& b) { return a.score < b.score; });

        double posSum = 0.0;
        for (auto& s : scores) if (s.score > 0) posSum += s.score;
        result.type       = (winner->score > 0.0) ? winner->type : FieldType::Unknown;
        { double c = (posSum > 0) ? (winner->score / posSum) : 0.0; result.confidence = c < 1.0 ? c : 1.0; }

        if (result.annotation.empty()) {
            wchar_t buf[128] = {};
            switch (result.type) {
                case FieldType::PoolTag: {
                    uint32_t tagVal = static_cast<uint32_t>(result.rawValue & 0xFFFFFFFF);
                    auto* known = FindPoolTag(tagVal);
                    if (known) {
                        swprintf_s(buf, L"'%c%c%c%c' (%S)",
                            (tagVal) & 0xFF, (tagVal >> 8) & 0xFF,
                            (tagVal >> 16) & 0xFF, (tagVal >> 24) & 0xFF,
                            known->description);
                    } else {
                        swprintf_s(buf, L"'%c%c%c%c'",
                            (tagVal) & 0xFF, (tagVal >> 8) & 0xFF,
                            (tagVal >> 16) & 0xFF, (tagVal >> 24) & 0xFF);
                    }
                    result.annotation = buf;
                    break;
                }
                case FieldType::AsciiString: {
                    std::wstring ws;
                    ULONG asciiCap = asciiLen < 64u ? asciiLen : 64u;
                    for (ULONG i = 0; i < asciiCap; i++)
                        ws += static_cast<wchar_t>(ptr[i]);
                    result.annotation = ws;
                    break;
                }
                case FieldType::Integer:
                    swprintf_s(buf, L"0x%llx (%llu)", result.rawValue, result.rawValue);
                    result.annotation = buf;
                    break;
                case FieldType::Flags:
                    swprintf_s(buf, L"0x%llx (popcount=%d)", result.rawValue, PopCount(result.rawValue));
                    result.annotation = buf;
                    break;
                case FieldType::Handle:
                    swprintf_s(buf, L"0x%llx", result.rawValue);
                    result.annotation = buf;
                    break;
                default: break;
            }
        }

        return result;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Multi-Instance Cross-Reference Engine
// ─────────────────────────────────────────────────────────────────────────────

class CrossRefEngine {
public:
    static std::vector<ULONG64> WalkListEntry(
        IDebugDataSpaces4* ds,
        ULONG64 headAddr,
        ULONG   listEntryOffsetInStruct,
        ULONG   maxInstances = 64
    ) {
        std::vector<ULONG64> results;
        if (!ds || headAddr == 0) return results;

        ULONG64 flink = 0;
        ULONG rd = 0;
        if (FAILED(ds->ReadVirtual(headAddr, &flink, 8, &rd)) || rd != 8) return results;

        ULONG64 current = flink;
        while (current != headAddr && current != 0 &&
               current > 0xFFFF000000000000ULL &&
               results.size() < maxInstances)
        {
            ULONG64 structBase = current - listEntryOffsetInStruct;
            results.push_back(structBase);

            ULONG64 nextFlink = 0;
            if (FAILED(ds->ReadVirtual(current, &nextFlink, 8, &rd)) || rd != 8) break;
            current = nextFlink;
        }
        return results;
    }

    static std::vector<OffsetProfile> Analyze(
        IDebugDataSpaces4*  ds,
        IDebugSymbols4*     sym,
        const std::vector<ULONG64>& instances,
        ULONG scanWindow
    ) {
        if (instances.empty() || !ds) return {};

        std::map<ULONG, OffsetProfile> profiles;

        SmartFieldAnalyzer analyzer;
        analyzer.DataSpaces = ds;
        analyzer.Symbols    = sym;

        for (ULONG64 base : instances) {
            std::vector<uint8_t> buf(scanWindow);
            ULONG bytesRead = 0;
            if (FAILED(ds->ReadVirtual(base, buf.data(), scanWindow, &bytesRead)) || bytesRead < 8)
                continue;

            for (ULONG off = 0; off + 8 <= bytesRead; off += 8) {
                auto fa = analyzer.Analyze(buf.data(), bytesRead, off, base);
                auto& prof = profiles[off];
                prof.offset = off;
                prof.observedTypes.push_back(fa.type);
                prof.confidences.push_back(fa.confidence);
                prof.rawValues.push_back(fa.rawValue);
            }
        }

        std::vector<OffsetProfile> result;
        for (auto& [off, prof] : profiles) {
            std::unordered_map<int, int> freq;
            for (auto t : prof.observedTypes) freq[static_cast<int>(t)]++;

            auto domIt = std::max_element(freq.begin(), freq.end(),
                [](auto& a, auto& b) { return a.second < b.second; });

            prof.dominantType    = static_cast<FieldType>(domIt->first);
            prof.typeConsistency = static_cast<double>(domIt->second) / static_cast<double>(prof.observedTypes.size());

            prof.isInteresting = (
                prof.typeConsistency >= 0.6 &&
                prof.dominantType != FieldType::Padding &&
                prof.dominantType != FieldType::Unknown &&
                domIt->second >= 2
            );

            result.push_back(std::move(prof));
        }
        return result;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// RAII Output Capture Callback
// ─────────────────────────────────────────────────────────────────────────────

class OutputCaptureCallback : public IDebugOutputCallbacks2 {
private:
    ULONG m_refCount{1};
    std::wstring m_capturedOutput;
    IDebugClient* m_client{nullptr};
    PDEBUG_OUTPUT_CALLBACKS m_prevCallback{nullptr};

public:
    OutputCaptureCallback() = default;

    HRESULT Initialize(IDebugClient* client) {
        m_client = client;
        if (!m_client) return E_INVALIDARG;
        HRESULT hr = m_client->GetOutputCallbacks(&m_prevCallback);
        if (FAILED(hr)) m_prevCallback = nullptr;
        return m_client->SetOutputCallbacks(reinterpret_cast<PDEBUG_OUTPUT_CALLBACKS>(this));
    }

    void Restore() {
        if (m_client) m_client->SetOutputCallbacks(m_prevCallback);
    }

    ~OutputCaptureCallback() { Restore(); }

    void Clear() { m_capturedOutput.clear(); }
    const std::wstring& GetOutput() const { return m_capturedOutput; }

    STDMETHODIMP QueryInterface(REFIID InterfaceId, PVOID* Interface) override {
        if (InterfaceId == __uuidof(IUnknown) ||
            InterfaceId == __uuidof(IDebugOutputCallbacks) ||
            InterfaceId == __uuidof(IDebugOutputCallbacks2)) {
            *Interface = static_cast<IDebugOutputCallbacks2*>(this);
            AddRef(); return S_OK;
        }
        *Interface = nullptr; return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return ++m_refCount; }
    STDMETHODIMP_(ULONG) Release() override {
        ULONG c = --m_refCount;
        if (c == 0) delete this;
        return c;
    }
    STDMETHODIMP Output(ULONG, PCSTR Text) override {
        if (Text) {
            int n = MultiByteToWideChar(CP_ACP, 0, Text, -1, nullptr, 0);
            if (n > 0) {
                std::vector<wchar_t> wb(n);
                MultiByteToWideChar(CP_ACP, 0, Text, -1, wb.data(), n);
                m_capturedOutput += wb.data();
            }
        }
        return S_OK;
    }
    STDMETHODIMP GetInterestMask(PULONG Mask) override {
        if (Mask) *Mask = DEBUG_OUTCBI_ANY_FORMAT;
        return S_OK;
    }
    STDMETHODIMP Output2(ULONG, ULONG, ULONG64, PCWSTR Text) override {
        if (Text) m_capturedOutput += Text;
        return S_OK;
    }
};

#endif // STRUCTSCAN_H
