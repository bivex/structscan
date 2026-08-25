/**
 * @file EntropyEngine.cpp
 * @brief Mode 4: Shannon Entropy Heatmap Engine
 */

#include "../include/structscan.h"

static std::wstring FormatEntropyBar(double H) {
    int barW = static_cast<int>(H / 4.0 * 24 + 0.5); // Max entropy for 16 bytes is log2(16) = 4.0 bits
    if (barW > 24) barW = 24;

    wchar_t fillChar = L'.';
    if (H >= 3.5)      fillChar = L'#';
    else if (H >= 2.2) fillChar = L'*';
    else if (H >= 1.0) fillChar = L'+';

    std::wstring bar(barW, fillChar);
    bar.resize(24, L' ');
    return bar;
}

static const wchar_t* GetEntropyNote(double H) {
    if (H < 0.5) return L"<- Zero/Padding";
    if (H < 1.8) return L"<- Counter/Flag";
    if (H < 3.2) return L"<- String/Tag";
    return L"<- Pointer/Crypto";
}

HRESULT DoEntropyMap(
    const DebugContext& ctx,
    const wchar_t*      target,
    ULONG               scanWindow
) {
    ULONG64 addr = ResolveTarget(ctx.sym, target, nullptr);
    if (addr == 0) {
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Cannot resolve: %s\n", target);
        return E_FAIL;
    }

    std::vector<uint8_t> buf(scanWindow);
    ULONG rd = 0;
    if (FAILED(ctx.ds->ReadVirtual(addr, buf.data(), scanWindow, &rd)) || rd == 0) return E_FAIL;

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"[+] Entropy Heatmap for 0x%016llx (%lu bytes)\n\n",
        static_cast<unsigned long long>(addr),
        static_cast<unsigned long>(rd));

    ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS,
        L"  Offset    H(bits)  Bar                        Notes\n"
        L"  --------  -------  -------------------------  ----------------\n");

    for (ULONG off = 0; off + 16 <= rd; off += 16) {
        double H = SmartFieldAnalyzer::ComputeEntropy(buf.data() + off, 16);
        std::wstring bar = FormatEntropyBar(H);
        const wchar_t* note = GetEntropyNote(H);

        wchar_t line[256] = {};
        swprintf_s(line, L"  +0x%04lx   %5.2f    %s  %s\n",
            static_cast<unsigned long>(off), H, bar.c_str(), note);
        ctx.ctrl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"%s", line);
    }
    return S_OK;
}
