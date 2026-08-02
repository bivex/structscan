/**
 * @file ScanEngine.cpp
 * @brief Mode 1: Single-Instance Bayesian Smart Scan Engine
 */

#include "../include/structscan.h"

HRESULT DoSingleScan(
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
        L"[+] Algorithm: Bayesian Field Classifier v4.0 (Shannon Entropy + Multi-feature)\n\n");

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
    for (ULONG off = 0; off + 8 <= rd; ) {
        if (ctrl->GetInterrupt() == S_OK) {
            ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"\n[*] Aborted by user (Ctrl+C)\n");
            break;
        }
        auto fa = analyzer.Analyze(buf.data(), rd, off, addr);
        if (fa.type != FieldType::Unknown && fa.type != FieldType::Padding && fa.confidence > 0.25) {
            PrintField(ctrl, fa);
            count++;
        }
        off += fa.size > 0 ? fa.size : 8;
    }

    ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"\n[+] Complete: %lu fields identified (confidence > 25%%)\n",
        static_cast<unsigned long>(count));
    return S_OK;
}
