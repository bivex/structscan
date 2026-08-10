/**
 * @file Main.cpp
 * @brief StructScan v4.0 — Modular Extension Entry Point & Command Dispatcher
 * @author Joseph Ryan Ries (2022) / Modernized & AI-Enhanced by Antigravity AI (2026)
 */

#include "../include/structscan.h"
#include <cwchar>

#define EXTENSION_VERSION_MAJOR 4
#define EXTENSION_VERSION_MINOR 0

__declspec(dllexport) HRESULT CALLBACK DebugExtensionInitialize(_Out_ PULONG Version, _Out_ PULONG Flags) {
    if (Version) *Version = DEBUG_EXTENSION_VERSION(EXTENSION_VERSION_MAJOR, EXTENSION_VERSION_MINOR);
    if (Flags)   *Flags   = 0;
    return S_OK;
}

__declspec(dllexport) void CALLBACK DebugExtensionUninitialize(void) {}

__declspec(dllexport) HRESULT CALLBACK structscan(_In_ IDebugClient* Client, _In_opt_ PCSTR Args) {
    if (!Client) return E_INVALIDARG;

    IDebugControl4*    ctrl = nullptr;
    IDebugSymbols4*    sym  = nullptr;
    IDebugDataSpaces4* ds   = nullptr;
    HRESULT hr = S_OK;

    if (FAILED(Client->QueryInterface(__uuidof(IDebugControl4),    (void**)&ctrl))) return E_FAIL;
    if (FAILED(Client->QueryInterface(__uuidof(IDebugSymbols4),    (void**)&sym)))  { ctrl->Release(); return E_FAIL; }
    if (FAILED(Client->QueryInterface(__uuidof(IDebugDataSpaces4), (void**)&ds)))   { sym->Release(); ctrl->Release(); return E_FAIL; }

    wchar_t wargs[512] = {};
    if (Args && *Args) {
        size_t c = 0;
        mbstowcs_s(&c, wargs, _countof(wargs), Args, _TRUNCATE);
    }

    wchar_t tok0[128] = {}, tok1[128] = {}, tok2[128] = {};
    int tokenCount = swscanf_s(wargs, L"%127s %127s %127s",
        tok0, (unsigned)_countof(tok0),
        tok1, (unsigned)_countof(tok1),
        tok2, (unsigned)_countof(tok2));

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
            L"   !structscan emit <sym|addr> [size]     - Synthesize C/C++ struct header\n"
            L"   !structscan entropy <sym|addr> [size]  - Shannon entropy heatmap\n"
            L"   !structscan unload                     - Unload hint\n\n"
            L" EXAMPLES:\n"
            L"   !structscan nt!PsInitialSystemProcess 0x400\n"
            L"   !structscan emit nt!KdDebuggerDataBlock 0x400\n"
            L"   !structscan list nt!PsActiveProcessHead 0x800\n"
            L"   !structscan entropy fffff802ac809ab0 0x200\n\n");
        goto Exit;
    }

    if (_wcsicmp(tok0, L"unload") == 0) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"[+] Run: .unload structscan\n");
        goto Exit;
    }

    if (_wcsicmp(tok0, L"emit") == 0) {
        if (wcslen(tok1) == 0) {
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Usage: !structscan emit <sym|addr> [size]\n");
            hr = E_INVALIDARG; goto Exit;
        }
        ULONG window = (wcslen(tok2) > 0) ? static_cast<ULONG>(wcstoul(tok2, nullptr, 16)) : 0x400;
        if (!window) window = 0x400;
        hr = DoEmitHeader(ctrl, sym, ds, tok1, window);
        goto Exit;
    }

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

// ─────────────────────────────────────────────────────────────────────────────
// !uaf <sym|addr> [objsize] [searchbytes]
//
//   objsize     — how many bytes of the suspected object to analyze
//                 default: 0x200
//   searchbytes — kernel VA range (centered on object) to scan for dangling
//                 back-pointers.  default: 0x8000 (32 KB)
//
// Examples:
//   !uaf nt!PsInitialSystemProcess 0x480
//   !uaf ffff8001`234abcd0 0x300 0x20000
//   !uaf win32k!gpdi
// ─────────────────────────────────────────────────────────────────────────────
__declspec(dllexport) HRESULT CALLBACK uaf(_In_ IDebugClient* Client, _In_opt_ PCSTR Args) {
    if (!Client) return E_INVALIDARG;

    IDebugControl4*    ctrl = nullptr;
    IDebugSymbols4*    sym  = nullptr;
    IDebugDataSpaces4* ds   = nullptr;

    if (FAILED(Client->QueryInterface(__uuidof(IDebugControl4),    (void**)&ctrl))) return E_FAIL;
    if (FAILED(Client->QueryInterface(__uuidof(IDebugSymbols4),    (void**)&sym)))  { ctrl->Release(); return E_FAIL; }
    if (FAILED(Client->QueryInterface(__uuidof(IDebugDataSpaces4), (void**)&ds)))   { sym->Release(); ctrl->Release(); return E_FAIL; }

    wchar_t wargs[512] = {};
    if (Args && *Args) {
        size_t c = 0;
        mbstowcs_s(&c, wargs, _countof(wargs), Args, _TRUNCATE);
    }

    wchar_t tok0[128] = {}, tok1[128] = {}, tok2[128] = {};
    int tokenCount = swscanf_s(wargs, L"%127s %127s %127s",
        tok0, (unsigned)_countof(tok0),
        tok1, (unsigned)_countof(tok1),
        tok2, (unsigned)_countof(tok2));

    HRESULT hr = S_OK;

    // No arguments: print usage
    if (tokenCount <= 0 || wcslen(tok0) == 0) {
        ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"================================================================\n"
            L"  StructScan !uaf v4.0  --  Use-After-Free Lifetime Analyzer\n"
            L"================================================================\n\n"
            L"  USAGE:\n"
            L"    !uaf <sym|addr> [objsize] [searchbytes]\n\n"
            L"  PARAMETERS:\n"
            L"    sym|addr    - Symbol name (e.g. nt!PsInitialSystemProcess)\n"
            L"                  or raw virtual address (hex, e.g. ffff8001`1234abcd)\n"
            L"    objsize     - Object size to analyze in bytes  [default: 0x200]\n"
            L"    searchbytes - Kernel VA range to scan for dangling refs [default: 0x8000]\n\n"
            L"  EXAMPLES:\n"
            L"    !uaf nt!PsInitialSystemProcess 0x480\n"
            L"    !uaf ffff8001`234abcd0 0x300 0x20000\n"
            L"    !uaf win32k!gpdi\n\n"
            L"  PHASES:\n"
            L"    1. Pool Header    -- PoolType, tag validity, free-list linkage\n"
            L"    2. OBJECT_HEADER  -- PointerCount / HandleCount ref-counts\n"
            L"    3. Content        -- Shannon entropy, Bayesian field snapshot\n"
            L"    4. Dangling Refs  -- reverse pointer scan in searchbytes range\n"
            L"    5. Risk Report    -- weighted score + WinDbg BP recipe\n\n"
            L"  FORMAL MODEL:\n"
            L"    ALLOC(O) -> LIVE(O) -> FREE(O) -> [REUSE] -> USE(O)\n"
            L"    Invariant: USE(O) requires t_use in [t_alloc, t_free)\n\n");
        goto Exit;
    }

    {
        // objsize: token1, hex; default 0x200
        ULONG objSize = (wcslen(tok1) > 0)
                        ? static_cast<ULONG>(wcstoul(tok1, nullptr, 16))
                        : 0x200u;
        if (!objSize) objSize = 0x200u;

        // searchbytes: token2, hex; default 0x8000
        ULONG searchBytes = (wcslen(tok2) > 0)
                            ? static_cast<ULONG>(wcstoul(tok2, nullptr, 16))
                            : 0x8000u;
        if (!searchBytes) searchBytes = 0x8000u;

        hr = DoUafAnalysis(ctrl, sym, ds, tok0, objSize, searchBytes);
    }

Exit:
    if (ds)   ds->Release();
    if (sym)  sym->Release();
    if (ctrl) ctrl->Release();
    return hr;
}
