/**
 * @file ScanEngine.cpp
 * @brief Mode 1: Single-Instance Bayesian Smart Scan Engine
 */

#include "../include/structscan.h"

HRESULT DoSingleScan(
    const DebugContext& ctx,
    const wchar_t*      target,
    ULONG               scanWindow
) {
    ModuleInfo modInfo{};
    ULONG64 addr = ResolveTarget(ctx.sym, target, &modInfo);

    if (addr == 0) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Cannot resolve: %s\n", target);
        return E_FAIL;
    }

    if (modInfo.base) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
            L"[+] Module: %s | Base: 0x%016llx | Size: 0x%lx\n",
            modInfo.name,
            static_cast<unsigned long long>(modInfo.base),
            static_cast<unsigned long>(modInfo.size));
    }
    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"[+] Target: 0x%016llx | Scan: 0x%lx bytes\n",
        static_cast<unsigned long long>(addr),
        static_cast<unsigned long>(scanWindow));
    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"[+] Algorithm: Bayesian Field Classifier v4.0 (Shannon Entropy + Multi-feature)\n\n");

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  Offset    Address               Type              Entropy  Confidence  Annotation\n"
        L"  --------  --------------------  ----------------  -------  ----------  ------------------------------\n");

    std::vector<uint8_t> buf(scanWindow);
    ULONG rd = 0;
    if (FAILED(ctx.ds->ReadVirtual(addr, buf.data(), scanWindow, &rd)) || rd == 0) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] ReadVirtual failed at 0x%016llx\n",
            static_cast<unsigned long long>(addr));
        return E_FAIL;
    }

    SmartFieldAnalyzer analyzer;
    analyzer.DataSpaces = ctx.ds;
    analyzer.Symbols    = ctx.sym;

    ULONG count = 0;
    for (ULONG off = 0; off + 8 <= rd; ) {
        if (ctx.ctrl->GetInterrupt() == S_OK) {
            ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"\n[*] Aborted by user (Ctrl+C)\n");
            break;
        }
        auto fa = analyzer.Analyze(buf.data(), rd, off, addr);
        if (fa.type != FieldType::Unknown && fa.type != FieldType::Padding && fa.confidence > 0.25) {
            PrintField(ctx.ctrl, fa);
            count++;
        }
        off += (fa.size > 0) ? fa.size : 8;
    }

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n[+] Complete: %lu fields identified (confidence > 25%%)\n",
        static_cast<unsigned long>(count));
    return S_OK;
}
