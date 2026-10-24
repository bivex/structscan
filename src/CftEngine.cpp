/**
 * @file CftEngine.cpp
 * @brief !cft — Control Flow Transfer Auto-Analyzer
 *
 * Subcommands:
 *   !cft                       — all five structural phases
 *   !cft snap                  — live snapshot: RIP + disasm + regs + stack + entropy
 *   !cft watch <sym|addr>      — Bayesian scan target + set hardware exec BP
 *   !cft trap                  — Phase 1: KTRAP_FRAME C/C++ header
 *   !cft syscall               — Phase 2: KiSystemCall64 entropy map
 *   !cft threads               — Phase 3: KTHREAD cross-ref (scheduler state)
 *   !cft cfg                   — Phase 4: CFG bitmap scan + entropy
 *   !cft ldr                   — Phase 5: LDR module list cross-ref
 */

#include "../include/structscan.h"
#include <cwchar>
#include <cstdio>

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

static void PrintPhaseHeader(IDebugControl4* ctrl, int phase, const wchar_t* title) {
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n"
        L"╔══════════════════════════════════════════════════════════════╗\n"
        L"║  PHASE %d · %-51s║\n"
        L"╚══════════════════════════════════════════════════════════════╝\n",
        phase, title);
}

static void PrintSectionHeader(IDebugControl4* ctrl, const wchar_t* title) {
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n  ── %s ──\n\n", title);
}

static void PrintPhaseSkip(IDebugControl4* ctrl, const wchar_t* sym, const wchar_t* reason) {
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  [SKIP] %s — %s\n", sym, reason);
}

static bool SymbolExists(IDebugSymbols4* sym, const wchar_t* name) {
    ULONG64 offset = 0;
    return SUCCEEDED(sym->GetOffsetByNameWide(name, &offset)) && offset != 0;
}

// Format a VA as a wide hex string usable as a target by ResolveTarget
static void FmtAddr(wchar_t* buf, size_t bufsz, ULONG64 addr) {
    swprintf_s(buf, bufsz, L"0x%016llx", static_cast<unsigned long long>(addr));
}

// ─────────────────────────────────────────────────────────────────────────────
// SNAP — live execution snapshot
// ─────────────────────────────────────────────────────────────────────────────
// Reads the current RIP from IDebugRegisters2, resolves it to a symbol,
// then runs:
//   • WinDbg "r"         — full register dump
//   • WinDbg "u @rip L20"— disassemble 20 instructions from RIP
//   • WinDbg "k 20"      — 20-frame call stack
//   • Entropy heatmap    — 0x100 bytes at RIP (code density / obfuscation)
//   • Bayesian scan      — 0x40 bytes before RIP (stack frame / locals context)
//
// Requires a live kernel or user-mode debug session (IDebugRegisters2 present).
// ─────────────────────────────────────────────────────────────────────────────

static HRESULT RunPhaseSnap(const DebugContext& ctx, const wchar_t* /*arg*/) {
    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n"
        L"╔══════════════════════════════════════════════════════════════╗\n"
        L"║  SNAP · Live Execution State at Current RIP                  ║\n"
        L"╚══════════════════════════════════════════════════════════════╝\n");

    if (!ctx.regs) {
        PrintPhaseSkip(ctx.ctrl, L"IDebugRegisters2",
            L"not available — requires live kernel or user-mode session (not dump)");
        return S_OK;
    }

    // ── 1. Read RIP ──────────────────────────────────────────────────────────
    ULONG ripIdx = 0;
    if (FAILED(ctx.regs->GetIndexByName("rip", &ripIdx))) {
        PrintPhaseSkip(ctx.ctrl, L"RIP", L"GetIndexByName failed (32-bit target?)");
        return S_OK;
    }
    DEBUG_VALUE ripVal{};
    if (FAILED(ctx.regs->GetValue(ripIdx, &ripVal))) {
        PrintPhaseSkip(ctx.ctrl, L"RIP", L"GetValue failed");
        return S_OK;
    }
    const ULONG64 rip = ripVal.I64;

    // ── 2. Resolve symbol ────────────────────────────────────────────────────
    wchar_t symName[256]{};
    ULONG64 displacement = 0;
    const bool hasSymbol = SUCCEEDED(
        ctx.sym->GetNameByOffsetWide(rip, symName, _countof(symName), nullptr, &displacement));

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n  RIP : 0x%016llx",
        static_cast<unsigned long long>(rip));
    if (hasSymbol && wcslen(symName) > 0) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  (%s+0x%llx)", symName, static_cast<unsigned long long>(displacement));
    }
    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"\n");

    // ── 3. Registers (r) ─────────────────────────────────────────────────────
    PrintSectionHeader(ctx.ctrl, L"Registers");
    ctx.ctrl->Execute(DEBUG_OUTCTL_ALL_CLIENTS, "r", DEBUG_EXECUTE_DEFAULT);

    // ── 4. Disassembly from RIP (u @rip L20) ─────────────────────────────────
    PrintSectionHeader(ctx.ctrl, L"Disassembly  (u @rip L20)");
    ctx.ctrl->Execute(DEBUG_OUTCTL_ALL_CLIENTS, "u @rip L20", DEBUG_EXECUTE_DEFAULT);

    // ── 5. Call stack (k 20) ─────────────────────────────────────────────────
    PrintSectionHeader(ctx.ctrl, L"Call Stack  (k 20)");
    ctx.ctrl->Execute(DEBUG_OUTCTL_ALL_CLIENTS, "k 20", DEBUG_EXECUTE_DEFAULT);

    // ── 6. Shannon entropy at RIP — detects code obfuscation / trampolines ───
    PrintSectionHeader(ctx.ctrl, L"Entropy heatmap at RIP  (0x100 bytes)");
    wchar_t ripStr[32];
    FmtAddr(ripStr, _countof(ripStr), rip);
    HRESULT hr = DoEntropyMap(ctx, ripStr, 0x100);
    if (FAILED(hr)) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"  [!] Entropy read failed\n");
    }

    // ── 7. Bayesian scan of 0x40 bytes before RIP (local frame / spill area) ─
    if (rip >= 0x40) {
        PrintSectionHeader(ctx.ctrl, L"Bayesian scan  RIP-0x40 context  (0x40 bytes)");
        wchar_t preStr[32];
        FmtAddr(preStr, _countof(preStr), rip - 0x40);
        hr = DoSingleScan(ctx, preStr, 0x40);
        if (FAILED(hr)) {
            ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"  [!] Pre-RIP scan failed\n");
        }
    }

    return S_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// WATCH — set hardware exec BP + profile target
// ─────────────────────────────────────────────────────────────────────────────
// Given a symbol or raw address:
//   1. Resolves and validates the address
//   2. Sets a hardware execution breakpoint (ba e 1 <addr>)
//      — hardware BP fires before the first byte executes; not patching code
//   3. Bayesian field scan of the first 0x100 bytes at target
//      — reveals prologue structure: frame setup, pointer spills, flags
//   4. Entropy heatmap of 0x200 bytes
//      — distinguishes normal code from packed/JOP dispatcher regions
//
// Up to 4 hardware BPs total (x86-64 DR0–DR3 constraint).
// After setting: type "g" to continue; WinDbg will break when RIP = target.
// ─────────────────────────────────────────────────────────────────────────────

static HRESULT RunPhaseWatch(const DebugContext& ctx, const wchar_t* arg) {
    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n"
        L"╔══════════════════════════════════════════════════════════════╗\n"
        L"║  WATCH · Hardware Exec BP + Target Profile                   ║\n"
        L"╚══════════════════════════════════════════════════════════════╝\n");

    if (!arg || wcslen(arg) == 0) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"\n[-] Usage: !cft watch <sym|addr>\n"
            L"    Example: !cft watch nt!KiSystemCall64\n"
            L"    Example: !cft watch 0xfffff802ac809ab0\n");
        return E_INVALIDARG;
    }

    // ── 1. Resolve target ────────────────────────────────────────────────────
    ModuleInfo modInfo{};
    const ULONG64 addr = ResolveTarget(ctx.sym, arg, &modInfo);
    if (addr == 0) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"\n[-] Cannot resolve: %s\n", arg);
        return E_FAIL;
    }

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n  Target : %s\n"
        L"  Addr   : 0x%016llx\n",
        arg, static_cast<unsigned long long>(addr));
    if (modInfo.base) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  Module : %s  (base 0x%016llx)\n",
            modInfo.name, static_cast<unsigned long long>(modInfo.base));
    }

    // ── 2. Set hardware execution breakpoint ─────────────────────────────────
    // "ba e 1 <addr>" — break on execute, 1-byte width (standard for code BPs)
    char bpCmd[80];
    sprintf_s(bpCmd, "ba e 1 0x%016llx", static_cast<unsigned long long>(addr));
    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n  [BP] Setting hardware exec breakpoint:\n"
        L"       %S\n\n", bpCmd);
    ctx.ctrl->Execute(DEBUG_OUTCTL_ALL_CLIENTS, bpCmd, DEBUG_EXECUTE_DEFAULT);

    // Confirm: show breakpoint list
    ctx.ctrl->Execute(DEBUG_OUTCTL_ALL_CLIENTS, "bl", DEBUG_EXECUTE_DEFAULT);

    // ── 3. Bayesian field scan (prologue structure) ───────────────────────────
    PrintSectionHeader(ctx.ctrl, L"Bayesian field scan at target  (0x100 bytes)");
    HRESULT hr = DoSingleScan(ctx, arg, 0x100);
    if (FAILED(hr)) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"  [!] Scan failed\n");
    }

    // ── 4. Entropy heatmap ───────────────────────────────────────────────────
    PrintSectionHeader(ctx.ctrl, L"Entropy heatmap  (0x200 bytes)");
    hr = DoEntropyMap(ctx, arg, 0x200);
    if (FAILED(hr)) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"  [!] Entropy failed\n");
    }

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n  [*] Type 'g' to continue — WinDbg will break when RIP reaches 0x%016llx\n",
        static_cast<unsigned long long>(addr));

    return S_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 1: KTRAP_FRAME — CPU state at ring-3 → ring-0 boundary
// ─────────────────────────────────────────────────────────────────────────────

static HRESULT RunPhaseTrapFrame(const DebugContext& ctx, const wchar_t* /*arg*/) {
    PrintPhaseHeader(ctx.ctrl, 1, L"KTRAP_FRAME  (CPU transfer boundary layout)  ");

    static constexpr struct { const wchar_t* sym; ULONG size; } kCandidates[] = {
        { L"nt!KiTrapFrame",     0x190 },
        { L"nt!KiInitialThread", 0x190 },
    };
    for (auto& c : kCandidates) {
        if (SymbolExists(ctx.sym, c.sym)) {
            ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"  Target : %s  (size 0x%lx)\n\n", c.sym,
                static_cast<unsigned long>(c.size));
            return DoEmitHeader(ctx, c.sym, c.size);
        }
    }
    PrintPhaseSkip(ctx.ctrl, L"nt!KiTrapFrame",
        L"symbol not found (need kernel PDB or live kernel session)");
    return S_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 2: KiSystemCall64 — syscall entry Shannon entropy map
// ─────────────────────────────────────────────────────────────────────────────

static HRESULT RunPhaseSyscall(const DebugContext& ctx, const wchar_t* /*arg*/) {
    PrintPhaseHeader(ctx.ctrl, 2, L"KiSystemCall64  (syscall entry entropy map) ");

    static constexpr const wchar_t* kSym = L"nt!KiSystemCall64";
    if (!SymbolExists(ctx.sym, kSym)) {
        PrintPhaseSkip(ctx.ctrl, kSym, L"symbol not found");
        return S_OK;
    }
    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  Target : %s  (window 0x200)\n\n", kSym);
    return DoEntropyMap(ctx, kSym, 0x200);
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 3: KTHREAD cross-ref via PsActiveProcessHead
// ─────────────────────────────────────────────────────────────────────────────

static HRESULT RunPhaseThreads(const DebugContext& ctx, const wchar_t* /*arg*/) {
    PrintPhaseHeader(ctx.ctrl, 3, L"KTHREAD list  (scheduler / context-switch) ");

    static constexpr const wchar_t* kSym = L"nt!PsActiveProcessHead";
    if (!SymbolExists(ctx.sym, kSym)) {
        PrintPhaseSkip(ctx.ctrl, kSym, L"symbol not found");
        return S_OK;
    }
    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  Target : %s  (window 0x800, up to 64 instances)\n\n", kSym);
    return DoListCrossRef(ctx, kSym, 0x800);
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 4: Control Flow Guard bitmap
// ─────────────────────────────────────────────────────────────────────────────

static HRESULT RunPhaseCfg(const DebugContext& ctx, const wchar_t* /*arg*/) {
    PrintPhaseHeader(ctx.ctrl, 4, L"CFG bitmap  (Control Flow Guard valid targets)");

    static constexpr const wchar_t* kSym = L"nt!MmCfgBitMap";
    if (!SymbolExists(ctx.sym, kSym)) {
        PrintPhaseSkip(ctx.ctrl, kSym,
            L"symbol not found (CFG may be disabled or private symbol required)");
        return S_OK;
    }
    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  Target : %s\n\n", kSym);

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  [4a] Bayesian field scan (descriptor, 0x80 bytes)\n\n");
    HRESULT hr = DoSingleScan(ctx, kSym, 0x80);
    if (FAILED(hr)) return hr;

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n  [4b] Shannon entropy heatmap (0x400 bytes)\n\n");
    return DoEntropyMap(ctx, kSym, 0x400);
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 5: LDR module list — PE entry-point transfer chain
// ─────────────────────────────────────────────────────────────────────────────

static HRESULT RunPhaseLdr(const DebugContext& ctx, const wchar_t* /*arg*/) {
    PrintPhaseHeader(ctx.ctrl, 5, L"LDR module list  (PE entry-point transfer chain)");

    static constexpr const wchar_t* kSym = L"nt!PsLoadedModuleList";
    if (!SymbolExists(ctx.sym, kSym)) {
        PrintPhaseSkip(ctx.ctrl, kSym, L"symbol not found");
        return S_OK;
    }
    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  Target : %s  (window 0x100, up to 64 modules)\n\n", kSym);
    return DoListCrossRef(ctx, kSym, 0x100);
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase dispatch table
// ─────────────────────────────────────────────────────────────────────────────

struct CftPhaseEntry {
    const wchar_t* keyword;
    const wchar_t* label;
    HRESULT (*fn)(const DebugContext&, const wchar_t* arg);
    bool runInAllMode;   // false = only via explicit subcommand (needs user arg)
};

static const CftPhaseEntry kCftPhases[] = {
    // keyword      label                     fn                  runInAllMode
    { L"snap",    L"Live RIP snapshot",      RunPhaseSnap,     true  },
    { L"trap",    L"KTRAP_FRAME",            RunPhaseTrapFrame, true  },
    { L"syscall", L"KiSystemCall64",         RunPhaseSyscall,   true  },
    { L"threads", L"KTHREAD cross-ref",      RunPhaseThreads,   true  },
    { L"cfg",     L"CFG bitmap",             RunPhaseCfg,       true  },
    { L"ldr",     L"LDR module list",        RunPhaseLdr,       true  },
    { L"watch",   L"Hardware exec BP+scan",  RunPhaseWatch,     false }, // needs arg
};

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

HRESULT DoCftAnalysis(const DebugContext& ctx, const wchar_t* subcommand,
                      const wchar_t* arg) {
    const bool runAll = (subcommand == nullptr || wcslen(subcommand) == 0);

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n"
        L"================================================================\n"
        L"  StructScan !cft v4.0  --  Control Flow Transfer Auto-Analyzer\n"
        L"================================================================\n"
        L"\n"
        L"  Structural : trap | syscall | threads | cfg | ldr\n"
        L"  Live       : snap\n"
        L"  Breakpoint : watch <sym|addr>\n"
        L"  (no args   : run all phases except watch)\n");

    if (!runAll) {
        for (const auto& phase : kCftPhases) {
            if (_wcsicmp(subcommand, phase.keyword) == 0) {
                return phase.fn(ctx, arg);
            }
        }
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"\n[-] Unknown subcommand: '%s'\n"
            L"    Valid: snap | trap | syscall | threads | cfg | ldr | watch <sym|addr>\n",
            subcommand);
        return E_INVALIDARG;
    }

    // All-phases mode: sequential, continue on failure, skip watch (needs arg)
    HRESULT worst = S_OK;
    int completed = 0, skipped = 0;

    for (const auto& phase : kCftPhases) {
        if (!phase.runInAllMode) continue;
        if (ctx.ctrl->GetInterrupt() == S_OK) {
            ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"\n[*] Aborted (Ctrl+C)\n");
            break;
        }
        HRESULT hr = phase.fn(ctx, nullptr);
        if (SUCCEEDED(hr)) { completed++; } else { worst = hr; skipped++; }
    }

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n"
        L"================================================================\n"
        L"  !cft complete — %d phases done, %d skipped/failed\n"
        L"================================================================\n\n",
        completed, skipped);

    return worst;
}
