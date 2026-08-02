/**
 * @file Main.cpp
 * @brief High-Speed Ultra-Fast StructScan WinDbg Extension Implementation
 * @author Joseph Ryan Ries (2022) / Modernized & Fast-Optimized by Antigravity AI (2026)
 * 
 * Performs direct bulk virtual memory reads (ReadVirtual) and native C++ pattern matching
 * to scan non-symbol data structures in sub-milliseconds without DbgEng command overhead.
 */

#include "../include/structscan.h"
#include <cwchar>
#include <vector>
#include <cctype>
#include <iostream>

#define EXTENSION_VERSION_MAJOR 2
#define EXTENSION_VERSION_MINOR 3

__declspec(dllexport) HRESULT CALLBACK DebugExtensionInitialize(_Out_ PULONG Version, _Out_ PULONG Flags) {
    if (Version) *Version = DEBUG_EXTENSION_VERSION(EXTENSION_VERSION_MAJOR, EXTENSION_VERSION_MINOR);
    if (Flags) *Flags = 0;
    return S_OK;
}

// Helper: Check if character is printable ASCII
inline bool IsPrintableAscii(uint8_t c) {
    return c >= 0x20 && c <= 0x7E;
}

__declspec(dllexport) HRESULT CALLBACK structscan(_In_ IDebugClient* Client, _In_opt_ PCSTR Args) {
    if (!Client) return E_INVALIDARG;

    HRESULT hr = S_OK;
    IDebugControl4* DebugControl = nullptr;
    IDebugSymbols4* Symbols = nullptr;
    IDebugDataSpaces4* DataSpaces = nullptr;

    if (FAILED(Client->QueryInterface(__uuidof(IDebugControl4), (void**)&DebugControl))) return E_FAIL;
    if (FAILED(Client->QueryInterface(__uuidof(IDebugSymbols4), (void**)&Symbols))) {
        DebugControl->Release();
        return E_FAIL;
    }
    Client->QueryInterface(__uuidof(IDebugDataSpaces4), (void**)&DataSpaces);

    wchar_t wideArgs[256] = { 0 };
    if (Args && strlen(Args) > 0) {
        size_t converted = 0;
        mbstowcs_s(&converted, wideArgs, _countof(wideArgs), Args, _TRUNCATE);
    }

    // Support !structscan unload
    if (_wcsicmp(wideArgs, L"unload") == 0) {
        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[+] Unloading structscan extension...\n");
        DebugControl->ExecuteWide(DEBUG_OUTCTL_ALL_CLIENTS, L".unload structscan.dll", DEBUG_EXECUTE_DEFAULT);
        DebugControl->ExecuteWide(DEBUG_OUTCTL_ALL_CLIENTS, L".unload structscan", DEBUG_EXECUTE_DEFAULT);
        goto Exit;
    }

    if (wcslen(wideArgs) == 0) {
        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"=============================================================\n");
        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L" StructScan v%d.%d — High-Speed Direct Memory Structure Scanner \n", EXTENSION_VERSION_MAJOR, EXTENSION_VERSION_MINOR);
        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"=============================================================\n\n");
        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"USAGE: !structscan <module!symbol | hex_address> [max_offset_hex]\n");
        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"       !structscan unload\n");
        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"EXAMPLE: !structscan nt!PsInitialSystemProcess 0x400\n");
        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"EXAMPLE: !structscan fffff802ac809ab0 0x200\n\n");
        goto Exit;
    }

    ULONG64 symbolAddress = 0;
    ULONG maxScanOffset = 0x400; // Default scan window: 1024 bytes

    wchar_t targetToken[128] = { 0 };
    wchar_t offsetToken[128] = { 0 };

    swscanf_s(wideArgs, L"%s %s", targetToken, static_cast<unsigned>(_countof(targetToken)), offsetToken, static_cast<unsigned>(_countof(offsetToken)));

    if (wcslen(offsetToken) > 0) {
        maxScanOffset = static_cast<ULONG>(wcstoul(offsetToken, nullptr, 16));
        if (maxScanOffset == 0) maxScanOffset = 0x400;
    }

    // Try parsing hex address
    wchar_t* endPtr = nullptr;
    symbolAddress = wcstoull(targetToken, &endPtr, 16);

    if (endPtr == targetToken || *endPtr != L'\0' || symbolAddress < 0x10000) {
        symbolAddress = 0;
        wchar_t moduleName[128] = { 0 };
        wchar_t* bangPos = wcschr(targetToken, L'!');
        if (bangPos) {
            wcsncpy_s(moduleName, targetToken, bangPos - targetToken);
            ULONG imageIndex = 0;
            ULONG64 imageBase = 0;
            if (SUCCEEDED(Symbols->GetModuleByModuleNameWide(moduleName, 0, &imageIndex, &imageBase))) {
                DEBUG_MODULE_PARAMETERS modParams = { 0 };
                Symbols->GetModuleParameters(1, nullptr, imageIndex, &modParams);
                DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[+] Module: %s | Base: 0x%p | Size: 0x%lx\n",
                    moduleName, reinterpret_cast<void*>(imageBase), modParams.Size);
            }
        }

        ULONG64 searchHandle = 0;
        if (SUCCEEDED(Symbols->StartSymbolMatchWide(targetToken, &searchHandle))) {
            Symbols->GetNextSymbolMatch(searchHandle, nullptr, 0, 0, &symbolAddress);
            Symbols->EndSymbolMatch(searchHandle);
        }
    }

    if (symbolAddress == 0) {
        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Symbol or address '%s' not found!\n", targetToken);
        goto Exit;
    }

    DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[+] Target Address: 0x%p (Scan Window: 0x%lx bytes)\n",
        reinterpret_cast<void*>(symbolAddress), maxScanOffset);
    DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[+] Performing High-Speed Bulk Memory Analysis...\n\n");

    if (DataSpaces) {
        std::vector<uint8_t> buffer(maxScanOffset);
        ULONG bytesRead = 0;

        if (FAILED(DataSpaces->ReadVirtual(symbolAddress, buffer.data(), maxScanOffset, &bytesRead)) || bytesRead == 0) {
            DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Failed to read virtual memory at 0x%p\n", reinterpret_cast<void*>(symbolAddress));
            goto Exit;
        }

        ULONG matchCount = 0;

        for (ULONG offset = 0; offset + sizeof(uint64_t) <= bytesRead; offset += 8) {
            if (DebugControl->GetInterrupt() == S_OK) {
                DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"\n[*] Scan aborted by user Ctrl+C.\n");
                break;
            }

            ULONG64 currentAddr = symbolAddress + offset;
            const uint8_t* ptr = buffer.data() + offset;

            // 1. Check UNICODE_STRING pattern
            uint16_t uLen = *reinterpret_cast<const uint16_t*>(ptr);
            uint16_t uMaxLen = *reinterpret_cast<const uint16_t*>(ptr + 2);
            if (offset + 16 <= bytesRead) {
                uint64_t uBufPtr = *reinterpret_cast<const uint64_t*>(ptr + 8);
                if (uLen > 0 && uLen <= uMaxLen && uMaxLen <= 1024 && (uLen % 2 == 0) && uBufPtr > 0xFFFF000000000000ULL) {
                    std::vector<wchar_t> wstr(uLen / 2 + 1, 0);
                    ULONG uRead = 0;
                    if (SUCCEEDED(DataSpaces->ReadVirtual(uBufPtr, wstr.data(), uLen, &uRead)) && uRead > 0) {
                        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"  +0x%04lx [0x%p] (UNICODE_STRING %u/%u B): %s\n",
                            offset, reinterpret_cast<void*>(currentAddr), static_cast<unsigned int>(uLen), static_cast<unsigned int>(uMaxLen), wstr.data());
                        matchCount++;
                    }
                }
            }

            // 2. Check ASCII String pattern inline
            size_t asciiLen = 0;
            while (offset + asciiLen < bytesRead && IsPrintableAscii(ptr[asciiLen])) {
                asciiLen++;
            }
            if (asciiLen >= 4) {
                std::wstring wstr(asciiLen, L'\0');
                for (size_t i = 0; i < asciiLen; ++i) {
                    wstr[i] = static_cast<wchar_t>(ptr[i]);
                }
                DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"  +0x%04lx [0x%p] (ASCII String %u B): %s\n",
                    offset, reinterpret_cast<void*>(currentAddr), static_cast<unsigned int>(asciiLen), wstr.c_str());
                matchCount++;
            }

            // 3. Check Kernel Pointer & Symbol Name Resolution
            uint64_t ptrVal = *reinterpret_cast<const uint64_t*>(ptr);
            if (ptrVal > 0xFFFF000000000000ULL) {
                wchar_t symName[256] = { 0 };
                ULONG64 displacement = 0;
                if (SUCCEEDED(Symbols->GetNameByOffsetWide(ptrVal, symName, _countof(symName), nullptr, &displacement))) {
                    DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"  +0x%04lx [0x%p] (Pointer): 0x%p -> %s+0x%llx\n",
                        offset, reinterpret_cast<void*>(currentAddr), reinterpret_cast<void*>(ptrVal), symName, displacement);
                    matchCount++;
                }
            }
        }

        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"\n[+] Scan Complete: %u interesting fields identified.\n", static_cast<unsigned int>(matchCount));
    }

Exit:
    if (DataSpaces) DataSpaces->Release();
    if (Symbols) Symbols->Release();
    if (DebugControl) DebugControl->Release();
    return hr;
}
