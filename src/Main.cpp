/**
 * @file Main.cpp
 * @brief StructScan v3.0 — Intelligent Multi-Algorithm Structure Reconstruction Engine
 * @author Joseph Ryan Ries (2022) / Modernized & AI-Enhanced by Antigravity AI (2026)
 *
 * Commands:
 *   !structscan <sym|addr> [size]          — single-instance smart scan
 *   !structscan list <sym|addr> [size]     — multi-instance LIST_ENTRY cross-reference
 *   !structscan entropy <sym|addr> [size]  — raw entropy heatmap only
 *   !structscan unload                     — safe unload hint
 */

#include "../include/structscan.h"
#include <cwchar>
#include <cstdio>

#define EXTENSION_VERSION_MAJOR 3
#define EXTENSION_VERSION_MINOR 0

// ─────────────────────────────────────────────────────────────────────────────
// Extension lifecycle
// ─────────────────────────────────────────────────────────────────────────────

__declspec(dllexport) HRESULT CALLBACK DebugExtensionInitialize(_Out_ PULONG Version, _Out_ PULONG Flags) {
    if (Version) *Version = DEBUG_EXTENSION_VERSION(EXTENSION_VERSION_MAJOR, EXTENSION_VERSION_MINOR);
    if (Flags)   *Flags   = 0;
    return S_OK;
}

__declspec(dllexport) void CALLBACK DebugExtensionUninitialize(void) {}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// Resolve symbol or hex address → ULONG64
static ULONG64 ResolveTarget(
    IDebugControl4*  ctrl,
    IDebugSymbols4*  sym,
    const wchar_t*   token,
    ULONG64*         outModBase = nullptr,
    wchar_t*         outModName = nullptr,
    size_t           modNameCch = 0,
    ULONG*           outModSize = nullptr
) {
    // Try direct hex parse
    wchar_t* end = nullptr;
    ULONG64 addr = wcstoull(token, &end, 16);
    if (end != token && *end == L'\0' && addr >= 0x10000) return addr;

    // Symbol lookup
    wchar_t modName[128] = {};
    wchar_t* bang = const_cast<wchar_t*>(wcschr(token, L'!'));
    if (bang) {
        wcsncpy_s(modName, token, bang - token);
        ULONG idx = 0; ULONG64 modBase = 0;
        if (SUCCEEDED(sym->GetModuleByModuleNameWide(modName, 0, &idx, &modBase))) {
            if (outModBase) *outModBase = modBase;
            if (outModName && modNameCch) wcsncpy_s(outModName, modNameCch, modName, _TRUNCATE);
            if (outModSize) {
                DEBUG_MODULE_PARAMETERS mp = {};
                sym->GetModuleParameters(1, nullptr, idx, &mp);
                *outModSize = mp.Size;
            }
        }
    }

    ULONG64 searchHandle = 0;
    ULONG64 result = 0;
    if (SUCCEEDED(sym->StartSymbolMatchWide(token, &searchHandle))) {
        sym->GetNextSymbolMatch(searchHandle, nullptr, 0, 0, &result);
        sym->EndSymbolMatch(searchHandle);
    }
    return result;
}

// Confidence bar  [####----]
static std::wstring ConfBar(double conf, int width = 8) {
    std::wstring bar = L"[";
    int filled = static_cast<int>(conf * width + 0.5);
    for (int i = 0; i < width; i++) bar += (i < filled) ? L'#' : L'-';
    bar += L"]";
    return bar;
}

// Print single FieldAnalysis result line
static void PrintField(IDebugControl4* ctrl, const FieldAnalysis& fa) {
    if (fa.type == FieldType::Unknown || fa.type == FieldType::Padding) return;

    wchar_t line[512] = {};
    std::wstring bar = ConfBar(fa.confidence);

    swprintf_s(line,
        L"  +0x%04lx  [0x%016llx]  %-16s  H=%.2f  %s  %s\n",
        fa.offset,
        static_cast<unsigned long long>(fa.address),
        FieldTypeName(fa.type),
        fa.entropy,
        bar.c_str(),
        fa.annotation.c_str()
    );
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"%s", line);
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode 1: Single-Instance Smart Scan
// ─────────────────────────────────────────────────────────────────────────────

static HRESULT DoSingleScan(
    IDebugControl4*    ctrl,
    IDebugSymbols4*    sym,
    IDebugDataSpaces4* ds,
    const wchar_t*     target,
    ULONG              scanWindow
) {
    wchar_t modName[128] = {};
    ULONG64 modBase = 0; ULONG modSize = 0;
    ULONG64 addr = ResolveTarget(ctrl, sym, target, &modBase, modName, _countof(modName), &modSize);

    if (addr == 0) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Cannot resolve: %s\n", target);
        return E_FAIL;
    }

    if (modBase) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"[+] Module: %s | Base: 0x%016llx | Size: 0x%lx\n",
            modName,
            static_cast<unsigned long long>(modBase),
            static_cast<unsigned long>(modSize));
    }
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"[+] Target: 0x%016llx | Scan: 0x%lx bytes\n",
        static_cast<unsigned long long>(addr),
        static_cast<unsigned long>(scanWindow));
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"[+] Algorithm: Bayesian Field Classifier v3.0 (Shannon Entropy + Multi-feature)\n\n");

    // Print header
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  Offset    Address               Type              Entropy  Confidence  Annotation\n");
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  --------  --------------------  ----------------  -------  ----------  ------------------------------\n");

    std::vector<uint8_t> buf(scanWindow);
    ULONG rd = 0;
    if (FAILED(ds->ReadVirtual(addr, buf.data(), scanWindow, &rd)) || rd == 0) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] ReadVirtual failed at 0x%016llx\n",
            static_cast<unsigned long long>(addr));
        return E_FAIL;
    }

    SmartFieldAnalyzer analyzer;
    analyzer.DataSpaces = ds;
    analyzer.Symbols    = sym;

    ULONG count = 0;
    for (ULONG off = 0; off + 8 <= rd; off += 8) {
        if (ctrl->GetInterrupt() == S_OK) {
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"\n[*] Aborted by user (Ctrl+C)\n");
            break;
        }
        auto fa = analyzer.Analyze(buf.data(), rd, off, addr);
        if (fa.type != FieldType::Unknown && fa.type != FieldType::Padding && fa.confidence > 0.25) {
            PrintField(ctrl, fa);
            count++;
        }
    }

    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n[+] Complete: %lu fields identified (confidence > 25%%)\n",
        static_cast<unsigned long>(count));
    return S_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode 2: Multi-Instance LIST_ENTRY Cross-Reference
// ─────────────────────────────────────────────────────────────────────────────

static HRESULT DoListCrossRef(
    IDebugControl4*    ctrl,
    IDebugSymbols4*    sym,
    IDebugDataSpaces4* ds,
    const wchar_t*     target,
    ULONG              scanWindow
) {
    ULONG64 headAddr = ResolveTarget(ctrl, sym, target, nullptr, nullptr, 0, nullptr);
    if (headAddr == 0) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Cannot resolve: %s\n", target);
        return E_FAIL;
    }

    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"[+] LIST_ENTRY head: 0x%016llx\n",
        static_cast<unsigned long long>(headAddr));

    // ── Phase 1: Discover LIST_ENTRY offsets inside first object ─────────────
    // Read the first object and find LIST_ENTRY candidates
    std::vector<uint8_t> buf0(scanWindow);
    ULONG rd0 = 0;
    if (FAILED(ds->ReadVirtual(headAddr, buf0.data(), scanWindow, &rd0)) || rd0 < 16) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Cannot read head object\n");
        return E_FAIL;
    }

    SmartFieldAnalyzer analyzer;
    analyzer.DataSpaces = ds;
    analyzer.Symbols    = sym;

    // Find all LIST_ENTRY offsets in first object
    struct ListEntryCandidate { ULONG offset; ULONG64 flink; ULONG64 blink; };
    std::vector<ListEntryCandidate> listCandidates;

    for (ULONG off = 0; off + 16 <= rd0; off += 8) {
        uint64_t flink = *reinterpret_cast<const uint64_t*>(buf0.data() + off);
        uint64_t blink = *reinterpret_cast<const uint64_t*>(buf0.data() + off + 8);
        if (flink > 0xFFFF000000000000ULL && blink > 0xFFFF000000000000ULL && flink != blink) {
            uint64_t flinkBlink = 0; ULONG rdx = 0;
            if (SUCCEEDED(ds->ReadVirtual(flink + 8, &flinkBlink, 8, &rdx)) && rdx == 8) {
                if (flinkBlink == (headAddr + off) || flinkBlink == blink) {
                    listCandidates.push_back({ off, flink, blink });
                }
            }
        }
    }

    if (listCandidates.empty()) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"[-] No valid LIST_ENTRY found in object. Try !structscan <sym> first to locate list offsets.\n");
        return E_FAIL;
    }

    // Use the first valid LIST_ENTRY found (or try all)
    for (auto& le : listCandidates) {
        wchar_t symBuf[256] = {}; ULONG64 disp = 0;
        std::wstring leAnnot;
        if (SUCCEEDED(sym->GetNameByOffsetWide(le.flink, symBuf, _countof(symBuf), nullptr, &disp)))
            leAnnot = symBuf;

        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"[+] Detected LIST_ENTRY at struct+0x%04lx  Flink->%s\n",
            static_cast<unsigned long>(le.offset),
            leAnnot.empty() ? L"<no symbol>" : leAnnot.c_str());
    }

    // ── Phase 2: Walk the list, collect struct base addresses ─────────────────
    auto& best = listCandidates[0];
    ULONG64 leHead  = headAddr + best.offset;  // addr of LIST_ENTRY in head
    std::vector<ULONG64> instances = CrossRefEngine::WalkListEntry(ds, leHead, best.offset, 64);

    if (instances.empty()) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] List appears empty or head == self (empty list)\n");
        return S_OK;
    }
    // Include head object itself
    instances.insert(instances.begin(), headAddr);

    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"[+] Collected %llu struct instances for cross-reference analysis\n\n",
        static_cast<unsigned long long>(instances.size()));

    // ── Phase 3: Cross-reference analysis ─────────────────────────────────────
    auto profiles = CrossRefEngine::Analyze(ds, sym, instances, scanWindow);

    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  Offset    Type              Consistency  Unique Values  Annotation\n");
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  --------  ----------------  -----------  -------------  --------------------------------\n");

    ULONG reported = 0;
    for (auto& prof : profiles) {
        if (!prof.isInteresting) continue;

        // Count unique values across instances
        std::vector<uint64_t> sorted = prof.rawValues;
        std::sort(sorted.begin(), sorted.end());
        size_t uniqueVals = std::unique(sorted.begin(), sorted.end()) - sorted.begin();

        // Sample annotation from first instance that has a pointer
        std::wstring annotation;
        for (size_t i = 0; i < prof.rawValues.size() && annotation.empty(); i++) {
            uint64_t v = prof.rawValues[i];
            if (v > 0xFFFF000000000000ULL && prof.dominantType == FieldType::Pointer) {
                wchar_t sn[256] = {}; ULONG64 d = 0;
                if (SUCCEEDED(sym->GetNameByOffsetWide(v, sn, _countof(sn), nullptr, &d))) {
                    annotation = sn;
                    if (d) { annotation += L"+..."; }
                    annotation += L" (varies)";
                }
            }
        }
        if (annotation.empty() && prof.dominantType == FieldType::AsciiString) {
            // Show distinct string values
            std::wstring vals;
            size_t shown = 0;
            for (size_t i = 0; i < instances.size() && shown < 3; i++) {
                std::vector<uint8_t> b(8);
                ULONG rr = 0;
                if (SUCCEEDED(ds->ReadVirtual(instances[i] + prof.offset, b.data(), 8, &rr))) {
                    std::wstring s;
                    for (auto c : b) if (c >= 0x20 && c <= 0x7E) s += static_cast<wchar_t>(c); else break;
                    if (!s.empty()) { if (!vals.empty()) vals += L"|"; vals += L"\"" + s + L"\""; shown++; }
                }
            }
            annotation = vals;
        }

        wchar_t line[512] = {};
        swprintf_s(line,
            L"  +0x%04lx   %-16s  %3.0f%%         %llu/%llu          %s\n",
            static_cast<unsigned long>(prof.offset),
            FieldTypeName(prof.dominantType),
            prof.typeConsistency * 100.0,
            static_cast<unsigned long long>(uniqueVals),
            static_cast<unsigned long long>(prof.rawValues.size()),
            annotation.c_str()
        );
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"%s", line);
        reported++;
    }

    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n[+] Cross-reference complete: %lu consistent fields identified across %llu instances\n",
        static_cast<unsigned long>(reported),
        static_cast<unsigned long long>(instances.size()));
    return S_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode 3: Entropy Heatmap
// ─────────────────────────────────────────────────────────────────────────────

static HRESULT DoEntropyMap(
    IDebugControl4*    ctrl,
    IDebugDataSpaces4* ds,
    const wchar_t*     target,
    IDebugSymbols4*    sym,
    ULONG              scanWindow
) {
    ULONG64 addr = ResolveTarget(ctrl, sym, target, nullptr, nullptr, 0, nullptr);
    if (addr == 0) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Cannot resolve: %s\n", target);
        return E_FAIL;
    }

    std::vector<uint8_t> buf(scanWindow);
    ULONG rd = 0;
    if (FAILED(ds->ReadVirtual(addr, buf.data(), scanWindow, &rd)) || rd == 0) return E_FAIL;

    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"[+] Entropy Heatmap for 0x%016llx (%lu bytes)\n\n",
        static_cast<unsigned long long>(addr),
        static_cast<unsigned long>(rd));

    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  Offset    H(bits)  Bar                        Notes\n");
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  --------  -------  -------------------------  ----------------\n");

    // 16-byte windows for entropy heatmap
    for (ULONG off = 0; off + 16 <= rd; off += 16) {
        double H = SmartFieldAnalyzer::ComputeEntropy(buf.data() + off, 16);
        int barW = static_cast<int>(H / 8.0 * 24 + 0.5);

        std::wstring bar;
        bar.reserve(24);
        for (int i = 0; i < 24; i++) {
            if (i < barW)
                bar += (H > 6.5) ? L'#' : (H > 3.5) ? L'*' : (H > 1.5) ? L'+' : L'.';
            else
                bar += L' ';
        }

        const wchar_t* note = L"";
        if (H < 0.5)        note = L"<- Zero/Padding";
        else if (H < 2.0)   note = L"<- Counter/Flag";
        else if (H < 4.0)   note = L"<- String/Tag";
        else if (H > 7.0)   note = L"<- Pointer/Crypto";

        wchar_t line[256] = {};
        swprintf_s(line, L"  +0x%04lx   %5.2f    %s  %s\n",
            static_cast<unsigned long>(off), H, bar.c_str(), note);
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"%s", line);
    }
    return S_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main extension entry point
// ─────────────────────────────────────────────────────────────────────────────

__declspec(dllexport) HRESULT CALLBACK structscan(_In_ IDebugClient* Client, _In_opt_ PCSTR Args) {
    if (!Client) return E_INVALIDARG;

    IDebugControl4*    ctrl = nullptr;
    IDebugSymbols4*    sym  = nullptr;
    IDebugDataSpaces4* ds   = nullptr;
    HRESULT hr = S_OK;

    if (FAILED(Client->QueryInterface(__uuidof(IDebugControl4),    (void**)&ctrl))) return E_FAIL;
    if (FAILED(Client->QueryInterface(__uuidof(IDebugSymbols4),    (void**)&sym)))  { ctrl->Release(); return E_FAIL; }
    if (FAILED(Client->QueryInterface(__uuidof(IDebugDataSpaces4), (void**)&ds)))   { sym->Release(); ctrl->Release(); return E_FAIL; }

    // Parse args
    wchar_t wargs[512] = {};
    if (Args && *Args) {
        size_t c = 0;
        mbstowcs_s(&c, wargs, _countof(wargs), Args, _TRUNCATE);
    }

    // Tokenize: mode, target, [size]
    wchar_t tok0[128] = {}, tok1[128] = {}, tok2[128] = {};
    int tokenCount = swscanf_s(wargs, L"%127s %127s %127s",
        tok0, (unsigned)_countof(tok0),
        tok1, (unsigned)_countof(tok1),
        tok2, (unsigned)_countof(tok2));

    // ── help / empty ────────────────────────────────────────────────────────
    if (tokenCount <= 0 || wcslen(tok0) == 0) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"==============================================================\n");
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L" StructScan v%d.%d - Intelligent Structure Reconstruction Engine\n",
            EXTENSION_VERSION_MAJOR, EXTENSION_VERSION_MINOR);
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"==============================================================\n\n");
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L" USAGE:\n"
            L"   !structscan <sym|addr> [size]          - Bayesian single-instance scan\n"
            L"   !structscan list <sym|addr> [size]     - Multi-instance cross-reference\n"
            L"   !structscan entropy <sym|addr> [size]  - Shannon entropy heatmap\n"
            L"   !structscan unload                     - Unload hint\n\n"
            L" EXAMPLES:\n"
            L"   !structscan nt!PsInitialSystemProcess 0x400\n"
            L"   !structscan list nt!PsActiveProcessHead 0x800\n"
            L"   !structscan entropy fffff802ac809ab0 0x200\n\n");
        goto Exit;
    }

    // ── unload ──────────────────────────────────────────────────────────────
    if (_wcsicmp(tok0, L"unload") == 0) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"[+] Run: .unload structscan\n");
        goto Exit;
    }

    // ── entropy mode ────────────────────────────────────────────────────────
    if (_wcsicmp(tok0, L"entropy") == 0) {
        if (wcslen(tok1) == 0) {
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Usage: !structscan entropy <sym|addr> [size]\n");
            hr = E_INVALIDARG; goto Exit;
        }
        ULONG window = (wcslen(tok2) > 0) ? static_cast<ULONG>(wcstoul(tok2, nullptr, 16)) : 0x200;
        if (!window) window = 0x200;
        hr = DoEntropyMap(ctrl, ds, tok1, sym, window);
        goto Exit;
    }

    // ── list (cross-reference) mode ─────────────────────────────────────────
    if (_wcsicmp(tok0, L"list") == 0) {
        if (wcslen(tok1) == 0) {
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Usage: !structscan list <sym|addr> [size]\n");
            hr = E_INVALIDARG; goto Exit;
        }
        ULONG window = (wcslen(tok2) > 0) ? static_cast<ULONG>(wcstoul(tok2, nullptr, 16)) : 0x400;
        if (!window) window = 0x400;
        hr = DoListCrossRef(ctrl, sym, ds, tok1, window);
        goto Exit;
    }

    // ── default: single scan ─────────────────────────────────────────────────
    {
        ULONG window = (wcslen(tok1) > 0) ? static_cast<ULONG>(wcstoul(tok1, nullptr, 16)) : 0x400;
        if (!window) window = 0x400;
        hr = DoSingleScan(ctrl, sym, ds, tok0, window);
    }

Exit:
    if (ds)   ds->Release();
    if (sym)  sym->Release();
    if (ctrl) ctrl->Release();
    return hr;
}
