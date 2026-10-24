/**
 * @file Utils.cpp
 * @brief Common StructScan Utilities (Symbol resolution, ASCII bars, field printers)
 */

#include "../include/structscan.h"
#include <cwchar>
#include <cstdlib>

static bool ParseHex64(const wchar_t* s, ULONG64* outVal) {
    if (!s || !outVal) return false;
    while (*s == L' ' || *s == L'\t') s++;
    if (!*s) return false;
    if (s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) s += 2;
    if (!*s) return false;
    ULONG64 val = 0;
    int digits = 0;
    while (*s) {
        if (*s == (wchar_t)0x60) { s++; continue; }
        wchar_t c = *s++;
        uint8_t d = 0;
        if (c >= L'0' && c <= L'9') d = c - L'0';
        else if (c >= L'a' && c <= L'f') d = c - L'a' + 10;
        else if (c >= L'A' && c <= L'F') d = c - L'A' + 10;
        else break;
        val = (val << 4) | d;
        digits++;
    }
    if (digits == 0) return false;
    if (digits <= 8 && (val & 0x80000000ULL) != 0 && (val & 0xFFFFFFFF00000000ULL) == 0) {
        val |= 0xFFFFF80100000000ULL;
    }
    *outVal = val;
    return true;
}

ULONG64 ResolveTarget(
    IDebugSymbols4* sym,
    const wchar_t*  token,
    ModuleInfo*     outModInfo
) {
    if (!token || !sym) return 0;

    ULONG64 hexAddr = 0;
    if (ParseHex64(token, &hexAddr) && hexAddr >= 0x10000) {
        if ((hexAddr & 0xFFFFFFFF00000000ULL) == 0 && (hexAddr & 0x80000000ULL) != 0) {
            ULONG64 kbase = 0;
            if (SUCCEEDED(sym->GetModuleByModuleNameWide(L"nt", 0, nullptr, &kbase)) && kbase > 0xFFFFFFFF00000000ULL) {
                hexAddr |= (kbase & 0xFFFFFFFF00000000ULL);
            } else {
                hexAddr |= 0xFFFFF80000000000ULL;
            }
        }
        return hexAddr;
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
