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
