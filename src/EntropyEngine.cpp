/**
 * @file EntropyEngine.cpp
 * @brief Mode 4: Shannon Entropy Heatmap Engine
 */

#include "../include/structscan.h"

HRESULT DoEntropyMap(
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
