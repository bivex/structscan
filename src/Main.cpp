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

struct ScopedDebugInterfaces {
    DebugContext ctx;

    bool Acquire(IDebugClient* client) {
        if (!client) return false;
        if (FAILED(client->QueryInterface(__uuidof(IDebugControl4),    reinterpret_cast<void**>(&ctx.ctrl)))) return false;
        if (FAILED(client->QueryInterface(__uuidof(IDebugSymbols4),    reinterpret_cast<void**>(&ctx.sym))))  return false;
        if (FAILED(client->QueryInterface(__uuidof(IDebugDataSpaces4), reinterpret_cast<void**>(&ctx.ds))))   return false;
        return true;
    }

    ~ScopedDebugInterfaces() {
        if (ctx.ds)   { ctx.ds->Release();   ctx.ds = nullptr; }
        if (ctx.sym)  { ctx.sym->Release();  ctx.sym = nullptr; }
        if (ctx.ctrl) { ctx.ctrl->Release(); ctx.ctrl = nullptr; }
    }
};

struct CommandArgs {
    wchar_t tok0[128]{};
    wchar_t tok1[128]{};
    wchar_t tok2[128]{};
    int     count{0};
};

static CommandArgs ParseCommandArgs(PCSTR args) {
    CommandArgs parsed{};
    wchar_t wargs[512] = {};
    if (args && *args) {
        size_t c = 0;
        mbstowcs_s(&c, wargs, _countof(wargs), args, _TRUNCATE);
    }
    parsed.count = swscanf_s(wargs, L"%127s %127s %127s",
        parsed.tok0, static_cast<unsigned>(_countof(parsed.tok0)),
        parsed.tok1, static_cast<unsigned>(_countof(parsed.tok1)),
        parsed.tok2, static_cast<unsigned>(_countof(parsed.tok2)));
    return parsed;
}

static ULONG ParseHexWithDefault(const wchar_t* tok, ULONG defaultValue) {
    if (!tok || wcslen(tok) == 0) return defaultValue;
    ULONG val = static_cast<ULONG>(wcstoul(tok, nullptr, 16));
    return (val > 0) ? val : defaultValue;
}

static void PrintStructscanUsage(IDebugControl4* ctrl) {
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"==============================================================\n"
        L" StructScan v%d.%d - Intelligent Structure Reconstruction Engine\n"
        L"==============================================================\n\n"
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
        L"   !structscan entropy fffff802ac809ab0 0x200\n\n",
        EXTENSION_VERSION_MAJOR, EXTENSION_VERSION_MINOR);
}

using SubCommandHandler = HRESULT (*)(const DebugContext& ctx, const CommandArgs& args);

static HRESULT HandleUnloadCommand(const DebugContext& ctx, const CommandArgs&) {
    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[+] Run: .unload structscan\n");
    return S_OK;
}

static HRESULT HandleEmitCommand(const DebugContext& ctx, const CommandArgs& args) {
    if (wcslen(args.tok1) == 0) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Usage: !structscan emit <sym|addr> [size]\n");
        return E_INVALIDARG;
    }
    return DoEmitHeader(ctx, args.tok1, ParseHexWithDefault(args.tok2, 0x400));
}

static HRESULT HandleEntropyCommand(const DebugContext& ctx, const CommandArgs& args) {
    if (wcslen(args.tok1) == 0) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Usage: !structscan entropy <sym|addr> [size]\n");
        return E_INVALIDARG;
    }
    return DoEntropyMap(ctx, args.tok1, ParseHexWithDefault(args.tok2, 0x200));
}

static HRESULT HandleListCommand(const DebugContext& ctx, const CommandArgs& args) {
    if (wcslen(args.tok1) == 0) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Usage: !structscan list <sym|addr> [size]\n");
        return E_INVALIDARG;
    }
    return DoListCrossRef(ctx, args.tok1, ParseHexWithDefault(args.tok2, 0x400));
}

struct CommandEntry {
    const wchar_t*    name;
    SubCommandHandler handler;
};

static const CommandEntry kCommandEntries[] = {
    { L"unload",  HandleUnloadCommand },
    { L"emit",    HandleEmitCommand },
    { L"entropy", HandleEntropyCommand },
    { L"list",    HandleListCommand },
};

static HRESULT DispatchStructScanCommand(const DebugContext& ctx, const CommandArgs& args) {
    if (args.count <= 0 || wcslen(args.tok0) == 0) {
        PrintStructscanUsage(ctx.ctrl);
        return S_OK;
    }

    for (const auto& entry : kCommandEntries) {
        if (_wcsicmp(args.tok0, entry.name) == 0) {
            return entry.handler(ctx, args);
        }
    }

    return DoSingleScan(ctx, args.tok0, ParseHexWithDefault(args.tok1, 0x400));
}

__declspec(dllexport) HRESULT CALLBACK structscan(_In_ IDebugClient* Client, _In_opt_ PCSTR Args) {
    ScopedDebugInterfaces dbg;
    if (!dbg.Acquire(Client)) return E_FAIL;
    CommandArgs parsed = ParseCommandArgs(Args);
    return DispatchStructScanCommand(dbg.ctx, parsed);
}

static void PrintUafUsage(IDebugControl4* ctrl) {
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
}

__declspec(dllexport) HRESULT CALLBACK uaf(_In_ IDebugClient* Client, _In_opt_ PCSTR Args) {
    ScopedDebugInterfaces dbg;
    if (!dbg.Acquire(Client)) return E_FAIL;

    CommandArgs parsed = ParseCommandArgs(Args);
    if (parsed.count <= 0 || wcslen(parsed.tok0) == 0) {
        PrintUafUsage(dbg.ctx.ctrl);
        return S_OK;
    }

    UafScanParams params{};
    params.target      = parsed.tok0;
    params.objSize     = ParseHexWithDefault(parsed.tok1, 0x200);
    params.searchBytes = ParseHexWithDefault(parsed.tok2, 0x8000);

    return DoUafAnalysis(dbg.ctx, params);
}
