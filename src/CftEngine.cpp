/**
 * @file CftEngine.cpp
 * @brief !cft / !ctf — Control Flow Transfer Auto-Analyzer & ARM CTF Tracer
 *
 * Subcommands:
 *   !cft / !ctf                — all structural phases + live snapshot
 *   !cft trace [sym|addr] [N]  — ARM64 / x64 Control Flow Transfer (CFT/CTF) trace
 *   !cft snap                  — live snapshot: PC/RIP + disasm + regs + stack + entropy
 *   !cft watch <sym|addr>      — Bayesian scan target + set hardware exec BP
 *   !cft trap                  — Phase 1: KTRAP_FRAME / KTHREAD C/C++ header
 *   !cft syscall               — Phase 2: Syscall entry (KiSystemService / KiSystemCall64) entropy map
 *   !cft threads               — Phase 3: KTHREAD cross-ref (scheduler state)
 *   !cft cfg                   — Phase 4: CFG bitmap scan + entropy
 *   !cft ldr                   — Phase 5: LDR module list cross-ref
 */

#include "../include/structscan.h"
#include <cwchar>
#include <cstdio>
#include <vector>
#include <string>

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

static void PrintPhaseHeader(IDebugControl4* ctrl, int phase, const wchar_t* title) {
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n"
        L"+==============================================================+\n"
        L"|  PHASE %d : %-48s |\n"
        L"+==============================================================+\n",
        phase, title);
}

static void PrintSectionHeader(IDebugControl4* ctrl, const wchar_t* title) {
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n  --- %s ---\n\n", title);
}

static void PrintPhaseSkip(IDebugControl4* ctrl, const wchar_t* sym, const wchar_t* reason) {
    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  [SKIP] %s - %s\n", sym, reason);
}

static bool SymbolExists(IDebugSymbols4* sym, const wchar_t* name) {
    ULONG64 offset = 0;
    return SUCCEEDED(sym->GetOffsetByNameWide(name, &offset)) && offset != 0;
}

// Format a VA as a wide hex string usable as a target by ResolveTarget
static void FmtAddr(wchar_t* buf, size_t bufsz, ULONG64 addr) {
    swprintf_s(buf, bufsz, L"0x%016llx", static_cast<unsigned long long>(addr));
}

// Get the architecture-specific name of the Instruction Pointer register
static const wchar_t* GetIpRegisterName(IDebugControl4* ctrl) {
    ULONG procType = 0;
    if (SUCCEEDED(ctrl->GetEffectiveProcessorType(&procType))) {
        switch (procType) {
            case 0xAA64: // IMAGE_FILE_MACHINE_ARM64
            case 0x01C4: // IMAGE_FILE_MACHINE_ARMNT
                return L"PC";
            case 0x8664: // IMAGE_FILE_MACHINE_AMD64
                return L"RIP";
            case 0x014C: // IMAGE_FILE_MACHINE_I386
                return L"EIP";
            default:
                break;
        }
    }
    return L"IP";
}

static bool IsArm64Target(IDebugControl4* ctrl) {
    ULONG procType = 0;
    if (SUCCEEDED(ctrl->GetEffectiveProcessorType(&procType))) {
        return (procType == 0xAA64 || procType == 0x01C4);
    }
    return false;
}

// Query register value from live debug session
static bool QueryRegisterValue(IDebugRegisters2* regs, int regIdx, ULONG64* outVal) {
    if (!regs || regIdx < 0 || regIdx > 31 || !outVal) return false;
    char rname[8];
    if (regIdx == 30) {
        strcpy_s(rname, "lr");
    } else {
        sprintf_s(rname, "x%d", regIdx);
    }
    ULONG idx = 0;
    if (SUCCEEDED(regs->GetIndexByName(rname, &idx))) {
        DEBUG_VALUE val{};
        if (SUCCEEDED(regs->GetValue(idx, &val))) {
            *outVal = val.I64;
            return true;
        }
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// ARM64 Control Flow Transfer (CFT / CTF) Instruction Decoder
// ─────────────────────────────────────────────────────────────────────────────

enum class ArmBranchType {
    None,
    DirectCall,        // BL
    IndirectCall,      // BLR
    PacIndirectCall,   // BLRAA, BLRAB
    DirectJump,        // B
    IndirectJump,      // BR
    PacIndirectJump,   // BRAA, BRAB
    CondBranch,        // B.cond
    CompareBranch,     // CBZ, CBNZ
    TestBitBranch,     // TBZ, TBNZ
    Return,            // RET
    PacReturn,         // RETAA, RETAB
    Syscall,           // SVC
    ExceptionReturn,   // ERET
    DebugBreak,        // BRK
    HypervisorCall,    // HVC, SMC
};

struct ArmDecodedBranch {
    ArmBranchType  type{ArmBranchType::None};
    const wchar_t* typeName{L""};
    ULONG64        targetAddr{0};
    int            regIndex{-1};
    bool           isIndirect{false};
    bool           isPac{false};
    bool           hasTarget{false};
};

static ArmDecodedBranch DecodeArm64Branch(uint32_t insn, ULONG64 pc) {
    ArmDecodedBranch d{};

    // RET (standard x30 or register)
    if ((insn & 0xFFFFFC1F) == 0xD65F0000) {
        d.type = ArmBranchType::Return;
        d.typeName = L"RETURN";
        d.regIndex = (insn >> 5) & 0x1F;
        d.isIndirect = true;
        return d;
    }
    // RETAA / RETAB (PAC authenticated return)
    if (insn == 0xD65F0BFF || insn == 0xD65F0FFF) {
        d.type = ArmBranchType::PacReturn;
        d.typeName = (insn == 0xD65F0BFF) ? L"PAC_RETA" : L"PAC_RETB";
        d.regIndex = 30;
        d.isIndirect = true;
        d.isPac = true;
        return d;
    }
    // BLR (indirect call)
    if ((insn & 0xFFFFFC1F) == 0xD63F0000) {
        d.type = ArmBranchType::IndirectCall;
        d.typeName = L"INDIR_CALL";
        d.regIndex = (insn >> 5) & 0x1F;
        d.isIndirect = true;
        return d;
    }
    // BLRAA / BLRAB (PAC indirect call)
    if ((insn & 0xFE200000) == 0xD6200000 && ((insn >> 10) & 0x1E) == 0x04) {
        d.type = ArmBranchType::PacIndirectCall;
        d.typeName = L"PAC_INDIR_CALL";
        d.regIndex = (insn >> 5) & 0x1F;
        d.isIndirect = true;
        d.isPac = true;
        return d;
    }
    // BR (indirect jump)
    if ((insn & 0xFFFFFC1F) == 0xD61F0000) {
        d.type = ArmBranchType::IndirectJump;
        d.typeName = L"INDIR_JUMP";
        d.regIndex = (insn >> 5) & 0x1F;
        d.isIndirect = true;
        return d;
    }
    // BRAA / BRAB (PAC indirect jump)
    if ((insn & 0xFE200000) == 0xD6200000 && ((insn >> 10) & 0x1E) == 0x00) {
        d.type = ArmBranchType::PacIndirectJump;
        d.typeName = L"PAC_INDIR_JUMP";
        d.regIndex = (insn >> 5) & 0x1F;
        d.isIndirect = true;
        d.isPac = true;
        return d;
    }
    // BL (direct call)
    if ((insn & 0xFC000000) == 0x94000000) {
        d.type = ArmBranchType::DirectCall;
        d.typeName = L"CALL";
        int64_t imm26 = static_cast<int64_t>(insn & 0x03FFFFFF);
        if (imm26 & 0x02000000) imm26 -= 0x04000000;
        d.targetAddr = pc + imm26 * 4;
        d.hasTarget = true;
        return d;
    }
    // B (direct unconditional jump)
    if ((insn & 0xFC000000) == 0x14000000) {
        d.type = ArmBranchType::DirectJump;
        d.typeName = L"JUMP";
        int64_t imm26 = static_cast<int64_t>(insn & 0x03FFFFFF);
        if (imm26 & 0x02000000) imm26 -= 0x04000000;
        d.targetAddr = pc + imm26 * 4;
        d.hasTarget = true;
        return d;
    }
    // B.cond
    if ((insn & 0xFF000010) == 0x54000000) {
        d.type = ArmBranchType::CondBranch;
        d.typeName = L"COND_BRANCH";
        int64_t imm19 = static_cast<int64_t>((insn >> 5) & 0x7FFFF);
        if (imm19 & 0x40000) imm19 -= 0x80000;
        d.targetAddr = pc + imm19 * 4;
        d.hasTarget = true;
        return d;
    }
    // CBZ / CBNZ
    if ((insn & 0x7E000000) == 0x34000000 || (insn & 0x7E000000) == 0x35000000) {
        d.type = ArmBranchType::CompareBranch;
        d.typeName = (insn & 0x01000000) ? L"CBNZ" : L"CBZ";
        d.regIndex = insn & 0x1F;
        int64_t imm19 = static_cast<int64_t>((insn >> 5) & 0x7FFFF);
        if (imm19 & 0x40000) imm19 -= 0x80000;
        d.targetAddr = pc + imm19 * 4;
        d.hasTarget = true;
        return d;
    }
    // TBZ / TBNZ
    if ((insn & 0x7E000000) == 0x36000000 || (insn & 0x7E000000) == 0x37000000) {
        d.type = ArmBranchType::TestBitBranch;
        d.typeName = (insn & 0x01000000) ? L"TBNZ" : L"TBZ";
        d.regIndex = insn & 0x1F;
        int64_t imm14 = static_cast<int64_t>((insn >> 5) & 0x3FFF);
        if (imm14 & 0x2000) imm14 -= 0x4000;
        d.targetAddr = pc + imm14 * 4;
        d.hasTarget = true;
        return d;
    }
    // ERET
    if (insn == 0xD69F03E0) {
        d.type = ArmBranchType::ExceptionReturn;
        d.typeName = L"ERET";
        return d;
    }
    // SVC
    if ((insn & 0xFFE0001F) == 0xD4000001) {
        d.type = ArmBranchType::Syscall;
        d.typeName = L"SYSCALL";
        return d;
    }
    // BRK
    if ((insn & 0xFFE0001F) == 0xD4200000) {
        d.type = ArmBranchType::DebugBreak;
        d.typeName = L"BREAKPOINT";
        return d;
    }
    // HVC / SMC
    if ((insn & 0xFFE0001F) == 0xD4000002 || (insn & 0xFFE0001F) == 0xD4000003) {
        d.type = ArmBranchType::HypervisorCall;
        d.typeName = L"HYPERCALL";
        return d;
    }

    return d;
}

// ─────────────────────────────────────────────────────────────────────────────
// TRACE — ARM / x64 Control Flow Transfer (CFT / CTF) Tracer
// ─────────────────────────────────────────────────────────────────────────────

static HRESULT RunPhaseTrace(const DebugContext& ctx, const wchar_t* arg, const wchar_t* extraArg) {
    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n"
        L"+==============================================================+\n"
        L"|  ARM / x64 CONTROL FLOW TRANSFER TRACER (CFT / CTF)          |\n"
        L"+==============================================================+\n");

    // ── 1. Determine target address ──────────────────────────────────────────
    ULONG64 targetAddr = 0;
    std::wstring targetLabel;

    if (arg && wcslen(arg) > 0) {
        targetAddr = ResolveTarget(ctx.sym, arg);
        if (targetAddr == 0) {
            ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"[-] Cannot resolve target: %s\n", arg);
            return E_FAIL;
        }
        targetLabel = arg;
    } else {
        // Default: use current Instruction Pointer (PC on ARM64, RIP on x64)
        if (ctx.regs && SUCCEEDED(ctx.regs->GetInstructionOffset(&targetAddr)) && targetAddr != 0) {
            wchar_t sname[128]{};
            ULONG64 disp = 0;
            if (SUCCEEDED(ctx.sym->GetNameByOffsetWide(targetAddr, sname, _countof(sname), nullptr, &disp))) {
                targetLabel = sname;
            } else {
                targetLabel = L"Current IP";
            }
        } else {
            ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"[-] No target specified and cannot read live IP.\n"
                L"    Usage: !cft trace <sym|addr> [count]\n"
                L"    Example: !cft trace nt!KiSystemService 32\n");
            return E_INVALIDARG;
        }
    }

    // ── 2. Determine instruction count ───────────────────────────────────────
    ULONG maxInsn = 32;
    if (extraArg && wcslen(extraArg) > 0) {
        ULONG userCount = static_cast<ULONG>(wcstoul(extraArg, nullptr, 10));
        if (userCount > 0 && userCount <= 256) {
            maxInsn = userCount;
        }
    }

    const bool isArm64 = IsArm64Target(ctx.ctrl);

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n  Target       : %s (0x%016llx)\n"
        L"  Instructions : %lu\n"
        L"  Architecture : %s\n\n",
        targetLabel.c_str(),
        static_cast<unsigned long long>(targetAddr),
        static_cast<unsigned long>(maxInsn),
        isArm64 ? L"ARM64 (AArch64)" : L"x64 / x86");

    if (isArm64) {
        // ── ARM64 Control Flow Transfer Trace ────────────────────────────────
        const ULONG byteCount = maxInsn * 4;
        std::vector<uint8_t> codeBuf(byteCount);
        ULONG bytesRead = 0;

        if (FAILED(ctx.ds->ReadVirtual(targetAddr, codeBuf.data(), byteCount, &bytesRead)) || bytesRead < 4) {
            ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"[-] ReadVirtual failed at 0x%016llx\n",
                static_cast<unsigned long long>(targetAddr));
            return E_FAIL;
        }

        const ULONG actualInsnCount = bytesRead / 4;

        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  #   Offset   Address               Type            Instruction & Target\n"
            L"  --  -------  --------------------  --------------  ---------------------------------------------------\n");

        ULONG transferCount = 0;
        ULONG directCalls = 0;
        ULONG indirectCalls = 0;
        ULONG directJumps = 0;
        ULONG indirectJumps = 0;
        ULONG condBranches = 0;
        ULONG returns = 0;
        ULONG pacTransfers = 0;
        ULONG syscalls = 0;

        for (ULONG i = 0; i < actualInsnCount; ++i) {
            if (ctx.ctrl->GetInterrupt() == S_OK) {
                ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"\n[*] Aborted by user (Ctrl+C)\n");
                break;
            }

            const ULONG64 insnAddr = targetAddr + (i * 4);
            const uint32_t insn = *reinterpret_cast<const uint32_t*>(codeBuf.data() + (i * 4));

            ArmDecodedBranch br = DecodeArm64Branch(insn, insnAddr);
            if (br.type == ArmBranchType::None) {
                continue; // Not a control transfer instruction
            }

            transferCount++;

            // Statistics accumulation
            switch (br.type) {
                case ArmBranchType::DirectCall:      directCalls++;   break;
                case ArmBranchType::IndirectCall:
                case ArmBranchType::PacIndirectCall: indirectCalls++; break;
                case ArmBranchType::DirectJump:      directJumps++;   break;
                case ArmBranchType::IndirectJump:
                case ArmBranchType::PacIndirectJump: indirectJumps++; break;
                case ArmBranchType::CondBranch:
                case ArmBranchType::CompareBranch:
                case ArmBranchType::TestBitBranch:   condBranches++;  break;
                case ArmBranchType::Return:
                case ArmBranchType::PacReturn:       returns++;       break;
                case ArmBranchType::Syscall:
                case ArmBranchType::ExceptionReturn:
                case ArmBranchType::DebugBreak:
                case ArmBranchType::HypervisorCall:  syscalls++;      break;
                default: break;
            }
            if (br.isPac) pacTransfers++;

            // Disassemble instruction text from WinDbg
            char disasmBuf[128] = {};
            ULONG64 nextOff = 0;
            ctx.ctrl->Disassemble(insnAddr, 0, disasmBuf, sizeof(disasmBuf), nullptr, &nextOff);

            // Clean trailing newline from WinDbg disasm output
            for (char* p = disasmBuf; *p; ++p) {
                if (*p == '\r' || *p == '\n') { *p = '\0'; break; }
            }

            // Skip module/address prefix if present in disasm string to isolate instruction mnemonic
            const char* insnText = disasmBuf;
            const char* lastTab = strrchr(disasmBuf, '\t');
            if (lastTab) {
                insnText = lastTab + 1;
            }

            // Target destination annotations
            wchar_t targetInfo[256] = {};

            if (br.hasTarget) {
                // Direct branch with known computed target
                wchar_t tgtSym[128] = {};
                ULONG64 tgtDisp = 0;
                if (SUCCEEDED(ctx.sym->GetNameByOffsetWide(br.targetAddr, tgtSym, _countof(tgtSym), nullptr, &tgtDisp))) {
                    if (tgtDisp > 0) {
                        swprintf_s(targetInfo, _countof(targetInfo), L"-> 0x%016llx (%s+0x%llx)",
                            static_cast<unsigned long long>(br.targetAddr), tgtSym, static_cast<unsigned long long>(tgtDisp));
                    } else {
                        swprintf_s(targetInfo, _countof(targetInfo), L"-> 0x%016llx (%s)",
                            static_cast<unsigned long long>(br.targetAddr), tgtSym);
                    }
                } else {
                    swprintf_s(targetInfo, _countof(targetInfo), L"-> 0x%016llx",
                        static_cast<unsigned long long>(br.targetAddr));
                }

                // Check 4-byte ARM64 alignment invariant
                if (br.targetAddr & 0x3) {
                    wcscat_s(targetInfo, L" [!] UNALIGNED DEST");
                }
            } else if (br.isIndirect && br.regIndex >= 0) {
                // Indirect branch via register (e.g. blr x16, ret x30)
                ULONG64 regVal = 0;
                if (QueryRegisterValue(ctx.regs, br.regIndex, &regVal)) {
                    wchar_t rSym[128] = {};
                    ULONG64 rDisp = 0;
                    if (SUCCEEDED(ctx.sym->GetNameByOffsetWide(regVal, rSym, _countof(rSym), nullptr, &rDisp))) {
                        swprintf_s(targetInfo, _countof(targetInfo), L"-> [x%d=0x%016llx %s+0x%llx]",
                            br.regIndex, static_cast<unsigned long long>(regVal), rSym, static_cast<unsigned long long>(rDisp));
                    } else {
                        swprintf_s(targetInfo, _countof(targetInfo), L"-> [x%d=0x%016llx]",
                            br.regIndex, static_cast<unsigned long long>(regVal));
                    }
                } else {
                    swprintf_s(targetInfo, _countof(targetInfo), L"-> [reg x%d]", br.regIndex);
                }

                if (br.isPac) {
                    wcscat_s(targetInfo, L" [PAC-AUTH]");
                } else if (br.type == ArmBranchType::IndirectCall) {
                    wcscat_s(targetInfo, L" [CFG-TARGET]");
                }
            } else if (br.type == ArmBranchType::Return || br.type == ArmBranchType::PacReturn) {
                ULONG64 lrVal = 0;
                if (QueryRegisterValue(ctx.regs, 30, &lrVal)) {
                    wchar_t lrSym[128] = {};
                    ULONG64 lrDisp = 0;
                    if (SUCCEEDED(ctx.sym->GetNameByOffsetWide(lrVal, lrSym, _countof(lrSym), nullptr, &lrDisp))) {
                        swprintf_s(targetInfo, _countof(targetInfo), L"-> [lr=0x%016llx %s+0x%llx]",
                            static_cast<unsigned long long>(lrVal), lrSym, static_cast<unsigned long long>(lrDisp));
                    } else {
                        swprintf_s(targetInfo, _countof(targetInfo), L"-> [lr=0x%016llx]",
                            static_cast<unsigned long long>(lrVal));
                    }
                }
                if (br.isPac) wcscat_s(targetInfo, L" [PAC-RET]");
            }

            ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                L"  %02lu  +0x%04lx  0x%016llx  %-14s  %-24S %s\n",
                static_cast<unsigned long>(transferCount),
                static_cast<unsigned long>(i * 4),
                static_cast<unsigned long long>(insnAddr),
                br.typeName,
                insnText,
                targetInfo);
        }

        // Print CFT summary
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"\n"
            L"  --- Control Flow Transfer Summary ---\n"
            L"  Instructions scanned : %lu\n"
            L"  Control transfers    : %lu (%.1f%% of code)\n"
            L"  Direct Calls (BL)    : %lu\n"
            L"  Indirect Calls (BLR) : %lu\n"
            L"  Direct Jumps (B)     : %lu\n"
            L"  Indirect Jumps (BR)  : %lu\n"
            L"  Cond Branches        : %lu\n"
            L"  Returns (RET/PAC)    : %lu\n"
            L"  PAC Authenticated    : %lu\n"
            L"  Syscalls/Exceptions  : %lu\n\n",
            static_cast<unsigned long>(actualInsnCount),
            static_cast<unsigned long>(transferCount),
            actualInsnCount > 0 ? (transferCount * 100.0 / actualInsnCount) : 0.0,
            static_cast<unsigned long>(directCalls),
            static_cast<unsigned long>(indirectCalls),
            static_cast<unsigned long>(directJumps),
            static_cast<unsigned long>(indirectJumps),
            static_cast<unsigned long>(condBranches),
            static_cast<unsigned long>(returns),
            static_cast<unsigned long>(pacTransfers),
            static_cast<unsigned long>(syscalls));

    } else {
        // ── x64 / x86 Control Flow Transfer Trace via Disassembler ───────────
        ULONG64 cur = targetAddr;
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  #   Address               Instruction\n"
            L"  --  --------------------  ---------------------------------------------------\n");

        ULONG transferCount = 0;
        for (ULONG i = 0; i < maxInsn; ++i) {
            char disBuf[128] = {};
            ULONG64 nextOff = 0;
            if (FAILED(ctx.ctrl->Disassemble(cur, 0, disBuf, sizeof(disBuf), nullptr, &nextOff))) {
                break;
            }
            for (char* p = disBuf; *p; ++p) {
                if (*p == '\r' || *p == '\n') { *p = '\0'; break; }
            }

            // Check if disasm contains transfer mnemonics (call, jmp, jcc, ret, syscall)
            if (strstr(disBuf, "call") || strstr(disBuf, "jmp") || strstr(disBuf, "ret") ||
                strstr(disBuf, "j") || strstr(disBuf, "syscall") || strstr(disBuf, "sysenter")) {
                transferCount++;
                ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
                    L"  %02lu  0x%016llx  %S\n",
                    static_cast<unsigned long>(transferCount),
                    static_cast<unsigned long long>(cur),
                    disBuf);
            }

            if (nextOff <= cur) break;
            cur = nextOff;
        }

        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"\n  [+] Complete: %lu transfers identified across %lu instructions\n\n",
            static_cast<unsigned long>(transferCount),
            static_cast<unsigned long>(maxInsn));
    }

    return S_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// SNAP — live execution snapshot (Cross-Architecture: ARM64 PC / x64 RIP / x86 EIP)
// ─────────────────────────────────────────────────────────────────────────────

static HRESULT RunPhaseSnap(const DebugContext& ctx, const wchar_t* /*arg*/) {
    const wchar_t* ipRegName = GetIpRegisterName(ctx.ctrl);

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n"
        L"+==============================================================+\n"
        L"|  SNAP : Live Execution State at Current %-3s                 |\n"
        L"+==============================================================+\n",
        ipRegName);

    if (!ctx.regs) {
        PrintPhaseSkip(ctx.ctrl, L"IDebugRegisters2",
            L"not available - requires live kernel or user-mode session (not dump)");
        return S_OK;
    }

    // ── 1. Read Instruction Pointer (Universal: ARM64 PC, x64 RIP, x86 EIP) ──
    ULONG64 ip = 0;
    HRESULT hr = ctx.regs->GetInstructionOffset(&ip);

    // Fallback: query named register if GetInstructionOffset fails
    if (FAILED(hr) || ip == 0) {
        static const char* kRegNames[] = { "pc", "rip", "eip" };
        bool found = false;
        for (const char* rname : kRegNames) {
            ULONG idx = 0;
            if (SUCCEEDED(ctx.regs->GetIndexByName(rname, &idx))) {
                DEBUG_VALUE val{};
                if (SUCCEEDED(ctx.regs->GetValue(idx, &val))) {
                    ip = val.I64;
                    found = true;
                    break;
                }
            }
        }
        if (!found || ip == 0) {
            PrintPhaseSkip(ctx.ctrl, ipRegName, L"failed to read instruction pointer register");
            return S_OK;
        }
    }

    // ── 2. Resolve symbol at current IP ──────────────────────────────────────
    wchar_t symName[256]{};
    ULONG64 displacement = 0;
    const bool hasSymbol = SUCCEEDED(
        ctx.sym->GetNameByOffsetWide(ip, symName, _countof(symName), nullptr, &displacement));

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n  %s  : 0x%016llx",
        ipRegName,
        static_cast<unsigned long long>(ip));
    if (hasSymbol && wcslen(symName) > 0) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"  (%s+0x%llx)", symName, static_cast<unsigned long long>(displacement));
    }
    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"\n");

    // ── 3. Registers (r) ─────────────────────────────────────────────────────
    PrintSectionHeader(ctx.ctrl, L"Registers");
    ctx.ctrl->Execute(DEBUG_OUTCTL_ALL_CLIENTS, "r", DEBUG_EXECUTE_DEFAULT);

    // ── 4. Disassembly from current IP (Universal: explicit address) ─────────
    PrintSectionHeader(ctx.ctrl, L"Disassembly (20 instructions from current IP)");
    char uCmd[64];
    sprintf_s(uCmd, "u 0x%016llx L20", static_cast<unsigned long long>(ip));
    ctx.ctrl->Execute(DEBUG_OUTCTL_ALL_CLIENTS, uCmd, DEBUG_EXECUTE_DEFAULT);

    // ── 5. Call stack (k 20) ─────────────────────────────────────────────────
    PrintSectionHeader(ctx.ctrl, L"Call Stack  (k 20)");
    ctx.ctrl->Execute(DEBUG_OUTCTL_ALL_CLIENTS, "k 20", DEBUG_EXECUTE_DEFAULT);

    // ── 6. Shannon entropy at IP — detects code obfuscation / trampolines ───
    PrintSectionHeader(ctx.ctrl, L"Entropy heatmap at IP (0x100 bytes)");
    wchar_t ipStr[32];
    FmtAddr(ipStr, _countof(ipStr), ip);
    hr = DoEntropyMap(ctx, ipStr, 0x100);
    if (FAILED(hr)) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"  [!] Entropy read failed\n");
    }

    // ── 7. Bayesian scan of 0x40 bytes before IP (frame / spill area) ────────
    if (ip >= 0x40) {
        PrintSectionHeader(ctx.ctrl, L"Bayesian scan  IP-0x40 context  (0x40 bytes)");
        wchar_t preStr[32];
        FmtAddr(preStr, _countof(preStr), ip - 0x40);
        hr = DoSingleScan(ctx, preStr, 0x40);
        if (FAILED(hr)) {
            ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"  [!] Pre-IP scan failed\n");
        }
    }

    return S_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// WATCH — set hardware exec BP + profile target
// ─────────────────────────────────────────────────────────────────────────────

static HRESULT RunPhaseWatch(const DebugContext& ctx, const wchar_t* arg) {
    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n"
        L"+==============================================================+\n"
        L"|  WATCH : Hardware Exec BP + Target Profile                   |\n"
        L"+==============================================================+\n");

    if (!arg || wcslen(arg) == 0) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"\n[-] Usage: !cft watch <sym|addr>\n"
            L"    Example: !cft watch nt!KiSystemService\n"
            L"    Example: !cft watch nt!KiSystemCall64\n"
            L"    Example: !cft watch 0xfffff8019da013b0\n");
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
    char bpCmd[80];
    sprintf_s(bpCmd, "ba e 1 0x%016llx", static_cast<unsigned long long>(addr));
    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n  [BP] Setting hardware exec breakpoint:\n"
        L"       %S\n\n", bpCmd);
    ctx.ctrl->Execute(DEBUG_OUTCTL_ALL_CLIENTS, bpCmd, DEBUG_EXECUTE_DEFAULT);
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

    const wchar_t* ipRegName = GetIpRegisterName(ctx.ctrl);
    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n  [*] Type 'g' to continue -- WinDbg will break when %s reaches 0x%016llx\n",
        ipRegName, static_cast<unsigned long long>(addr));

    return S_OK;
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase 1: KTRAP_FRAME / KTHREAD — CPU state at ring-3 → ring-0 boundary
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
// Phase 2: Syscall Entry (ARM64 KiSystemService / x64 KiSystemCall64)
// ─────────────────────────────────────────────────────────────────────────────

static HRESULT RunPhaseSyscall(const DebugContext& ctx, const wchar_t* /*arg*/) {
    PrintPhaseHeader(ctx.ctrl, 2, L"Syscall Entry (entropy map)                 ");

    static constexpr const wchar_t* kSyscallCandidates[] = {
        L"nt!KiSystemService",        // ARM64 primary
        L"nt!KiSystemCall64",        // x64 primary
        L"nt!KiServiceInternal",       // ARM64 alternate
        L"nt!KiSystemServiceExit",     // ARM64 exit
        L"nt!KiSystemCall64Shadow",  // x64 KVA shadow
        L"nt!KiFastSystemCall",      // x86 sysenter
    };

    const wchar_t* targetSym = nullptr;
    for (auto sym : kSyscallCandidates) {
        if (SymbolExists(ctx.sym, sym)) {
            targetSym = sym;
            break;
        }
    }

    if (!targetSym) {
        PrintPhaseSkip(ctx.ctrl, L"Syscall entry", L"no recognized syscall symbol found");
        return S_OK;
    }

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  Target : %s  (window 0x200)\n\n", targetSym);
    return DoEntropyMap(ctx, targetSym, 0x200);
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

    static constexpr const wchar_t* kCfgCandidates[] = {
        L"nt!MmCfgBitMap",
        L"nt!MiPopulateCfgBitMap",
        L"nt!MiSelectCfgBitMap",
        L"nt!MmGetCfgBitMapInformation",
    };

    const wchar_t* targetSym = nullptr;
    for (auto sym : kCfgCandidates) {
        if (SymbolExists(ctx.sym, sym)) {
            targetSym = sym;
            break;
        }
    }

    if (!targetSym) {
        PrintPhaseSkip(ctx.ctrl, L"CFG",
            L"symbol not found (CFG may be disabled or private symbol required)");
        return S_OK;
    }

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  Target : %s\n\n", targetSym);

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  [4a] Bayesian field scan (0x80 bytes)\n\n");
    HRESULT hr = DoSingleScan(ctx, targetSym, 0x80);
    if (FAILED(hr)) return hr;

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n  [4b] Shannon entropy heatmap (0x400 bytes)\n\n");
    return DoEntropyMap(ctx, targetSym, 0x400);
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
    { L"snap",    L"Live IP snapshot",       RunPhaseSnap,     true  },
    { L"trap",    L"KTRAP_FRAME",            RunPhaseTrapFrame, true  },
    { L"syscall", L"Syscall entry",          RunPhaseSyscall,   true  },
    { L"threads", L"KTHREAD cross-ref",      RunPhaseThreads,   true  },
    { L"cfg",     L"CFG bitmap",             RunPhaseCfg,       true  },
    { L"ldr",     L"LDR module list",        RunPhaseLdr,       true  },
    { L"watch",   L"Hardware exec BP+scan",  RunPhaseWatch,     false }, // needs arg
};

// ─────────────────────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────────────────────

HRESULT DoCftAnalysis(const DebugContext& ctx, const wchar_t* subcommand,
                      const wchar_t* arg, const wchar_t* extraArg) {
    const bool runAll = (subcommand == nullptr || wcslen(subcommand) == 0);

    // If user ran `!cft trace` or `!ctf trace`
    if (subcommand && (_wcsicmp(subcommand, L"trace") == 0 || _wcsicmp(subcommand, L"ctf") == 0)) {
        return RunPhaseTrace(ctx, arg, extraArg);
    }

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n"
        L"================================================================\n"
        L"  StructScan !cft / !ctf v4.0  --  Control Flow Transfer Tracer\n"
        L"================================================================\n"
        L"\n"
        L"  Tracing    : trace [sym|addr] [count] (ARM64 CTF branch tracer)\n"
        L"  Live State : snap                     (PC, regs, disasm, stack, entropy)\n"
        L"  Breakpoint : watch <sym|addr>         (Hardware BP + profile)\n"
        L"  Structural : trap | syscall | threads | cfg | ldr\n"
        L"  (no args   : run all 6 phases except watch and trace)\n");

    if (!runAll) {
        for (const auto& phase : kCftPhases) {
            if (_wcsicmp(subcommand, phase.keyword) == 0) {
                return phase.fn(ctx, arg);
            }
        }
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"\n[-] Unknown subcommand: '%s'\n"
            L"    Valid: trace | snap | watch | trap | syscall | threads | cfg | ldr\n",
            subcommand);
        return E_INVALIDARG;
    }

    // All-phases mode: sequential, continue on failure, skip watch and trace
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
        L"  !cft complete -- %d phases done, %d skipped/failed\n"
        L"================================================================\n\n",
        completed, skipped);

    return worst;
}
