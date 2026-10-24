/**
 * @file Utils.cpp
 * @brief Common StructScan Utilities (Symbol resolution, ASCII bars, field printers)
 */

#include "../include/structscan.h"
#include <cwchar>
#include <cstdlib>

ULONG64 ResolveTarget(
    IDebugSymbols4* sym,
    const wchar_t*  token,
    ModuleInfo*     outModInfo
) {
    if (!token || !sym) return 0;

    // Clean backtick (`) which WinDbg uses in 64-bit addresses (e.g. fffff801`9de361c0)
    wchar_t cleanToken[128] = {};
    size_t ci = 0;
    for (size_t i = 0; token[i] && ci + 1 < _countof(cleanToken); ++i) {
        if (token[i] != L'`') {
            cleanToken[ci++] = token[i];
        }
    }
    cleanToken[ci] = L'\0';
    wchar_t* end = nullptr;
    ULONG64 addr = std::wcstoull(cleanToken, &end, 16);
    if (end != cleanToken && *end == L'\0' && addr >= 0x10000) {
        // If truncated 32-bit kernel pointer on 64-bit target, restore high 32 bits from kernel base
        if ((addr & 0xFFFFFFFF00000000ULL) == 0 && (addr & 0x80000000ULL) != 0) {
            ULONG64 ntBase = 0;
            if (SUCCEEDED(sym->GetModuleByModuleNameWide(L"nt", 0, nullptr, &ntBase)) && ntBase > 0xFFFFFFFF00000000ULL) {
                addr |= (ntBase & 0xFFFFFFFF00000000ULL);
            }
        }
        return addr;
    }
    wchar_t modName[128] = {};
    const wchar_t* bang = wcschr(token, L'!');
    if (bang) {
        wcsncpy_s(modName, token, bang - token);
        ULONG idx = 0;
        ULONG64 modBase = 0;
        if (SUCCEEDED(sym->GetModuleByModuleNameWide(modName, 0, &idx, &modBase))) {
            if (outModInfo) {
                outModInfo->base = modBase;
                wcsncpy_s(outModInfo->name, modName, _TRUNCATE);
                DEBUG_MODULE_PARAMETERS mp = {};
                if (SUCCEEDED(sym->GetModuleParameters(1, nullptr, idx, &mp))) {
                    outModInfo->size = mp.Size;
                }
            }
        }
    }

    // Try direct exact symbol lookup first (gives full 64-bit address without truncation)
    ULONG64 exactAddr = 0;
    if (SUCCEEDED(sym->GetOffsetByNameWide(token, &exactAddr)) && exactAddr != 0) {
        return exactAddr;
    }

    ULONG64 searchHandle = 0;
    ULONG64 result = 0;
    if (SUCCEEDED(sym->StartSymbolMatchWide(token, &searchHandle))) {
        sym->GetNextSymbolMatch(searchHandle, nullptr, 0, 0, &result);
        sym->EndSymbolMatch(searchHandle);
    }
    if (result != 0 && (result & 0xFFFFFFFF00000000ULL) == 0 && (result & 0x80000000ULL) != 0) {
        ULONG64 ntBase = 0;
        if (SUCCEEDED(sym->GetModuleByModuleNameWide(L"nt", 0, nullptr, &ntBase)) && ntBase > 0xFFFFFFFF00000000ULL) {
            result |= (ntBase & 0xFFFFFFFF00000000ULL);
        }
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
