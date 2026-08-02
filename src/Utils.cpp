/**
 * @file Utils.cpp
 * @brief Common StructScan Utilities (Symbol resolution, ASCII bars, field printers)
 */

#include "../include/structscan.h"
#include <cwchar>

ULONG64 ResolveTarget(
    IDebugControl4*  ctrl,
    IDebugSymbols4*  sym,
    const wchar_t*   token,
    ULONG64*         outModBase,
    wchar_t*         outModName,
    size_t           modNameCch,
    ULONG*           outModSize
) {
    wchar_t* end = nullptr;
    ULONG64 addr = wcstoull(token, &end, 16);
    if (end != token && *end == L'\0' && addr >= 0x10000) return addr;

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

std::wstring ConfBar(double conf, int width) {
    std::wstring bar = L"[";
    int filled = static_cast<int>(conf * width + 0.5);
    for (int i = 0; i < width; i++) bar += (i < filled) ? L'#' : L'-';
    bar += L"]";
    return bar;
}

void PrintField(IDebugControl4* ctrl, const FieldAnalysis& fa) {
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
