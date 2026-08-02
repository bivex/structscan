/**
 * @file Main.cpp
 * @brief StructScan WinDbg Extension — Non-Symbol Structure Scanner
 * @author Joseph Ryan Ries (2022) / Modernized by Antigravity AI (2026)
 * 
 * Scans data structures without private symbols to locate strings, pointers,
 * UNICODE_STRINGs, and embedded pointers.
 */

#include "Main.h"
#include <cwchar>
#include <sstream>
#include <iostream>

#define EXTENSION_VERSION_MAJOR 1
#define EXTENSION_VERSION_MINOR 5

__declspec(dllexport) HRESULT CALLBACK DebugExtensionInitialize(_Out_ PULONG Version, _Out_ PULONG Flags) {
    if (Version) *Version = DEBUG_EXTENSION_VERSION(EXTENSION_VERSION_MAJOR, EXTENSION_VERSION_MINOR);
    if (Flags) *Flags = 0;
    return S_OK;
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

    // Usage check
    if (wcslen(wideArgs) == 0 || wcschr(wideArgs, L'!') == nullptr) {
        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"=============================================================\n");
        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L" StructScan v%d.%d — Non-Symbol Data Structure Scanner       \n", EXTENSION_VERSION_MAJOR, EXTENSION_VERSION_MINOR);
        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"=============================================================\n\n");
        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"USAGE: !structscan <module!symbol_or_address> [max_offset_hex]\n");
        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"EXAMPLE: !structscan ntdsai!gAnchor\n");
        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"EXAMPLE: !structscan 0x7ffc64da6000 0x200\n\n");
        goto Exit;
    }

    wchar_t moduleName[128] = { 0 };
    wchar_t symbolName[128] = { 0 };
    wchar_t* bangPos = wcschr(wideArgs, L'!');

    if (bangPos) {
        wcsncpy_s(moduleName, wideArgs, bangPos - wideArgs);
        wcscpy_s(symbolName, bangPos + 1);
    }

    ULONG imageIndex = 0;
    ULONG64 imageBase = 0;
    ULONG64 symbolAddress = 0;
    ULONG maxScanOffset = 0x1000;

    // Check optional max offset argument
    wchar_t* spacePos = wcschr(wideArgs, L' ');
    if (spacePos) {
        maxScanOffset = static_cast<ULONG>(wcstoul(spacePos + 1, nullptr, 16));
        if (maxScanOffset == 0) maxScanOffset = 0x1000;
    }

    // Resolve Symbol Address
    if (wcsncmp(wideArgs, L"0x", 2) == 0 || iswxdigit(wideArgs[0])) {
        symbolAddress = wcstoull(wideArgs, nullptr, 16);
    } else {
        if (SUCCEEDED(Symbols->GetModuleByModuleNameWide(moduleName, 0, &imageIndex, &imageBase))) {
            DEBUG_MODULE_PARAMETERS modParams = { 0 };
            Symbols->GetModuleParameters(1, nullptr, imageIndex, &modParams);
            DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[+] Module: %s | Base: 0x%p | Size: 0x%lx\n",
                moduleName, reinterpret_cast<void*>(imageBase), modParams.Size);
        }

        ULONG64 searchHandle = 0;
        if (SUCCEEDED(Symbols->StartSymbolMatchWide(wideArgs, &searchHandle))) {
            Symbols->GetNextSymbolMatch(searchHandle, nullptr, 0, 0, &symbolAddress);
            Symbols->EndSymbolMatch(searchHandle);
        }
    }

    if (symbolAddress == 0) {
        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Symbol or address '%s' not found!\n", wideArgs);
        goto Exit;
    }

    DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[+] Target Address: 0x%p (Max Scan: 0x%lx bytes)\n",
        reinterpret_cast<void*>(symbolAddress), maxScanOffset);
    DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[+] Scanning for Strings, UNICODE_STRINGs, and Pointers...\n\n");

    {
        // One-time RAII Output Callback Capture (NO FLIPPING IN LOOP!)
        OutputCaptureCallback outputCapture;
        if (FAILED(outputCapture.Initialize(Client))) {
            DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"[-] Failed to initialize OutputCaptureCallback!\n");
            goto Exit;
        }

        const wchar_t* displayCmds[] = { L"dS", L"ds" };

        for (ULONG offset = 0; offset < maxScanOffset; offset += 8) {
            // Check for user interrupt (Ctrl+C) via DbgEng native method
            if (DebugControl->GetInterrupt() == S_OK) {
                DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"\n[*] Scan aborted by user interrupt (Ctrl+C).\n");
                break;
            }

            ULONG64 currentAddr = symbolAddress + offset;

            // 1. Try displaying string via dS / ds
            for (int c = 0; c < _countof(displayCmds); ++c) {
                outputCapture.Clear();
                wchar_t cmdBuffer[128];
                swprintf_s(cmdBuffer, L"%s 0x%llx", displayCmds[c], currentAddr);

                DebugControl->ExecuteWide(DEBUG_OUTCTL_THIS_CLIENT, cmdBuffer, DEBUG_EXECUTE_DEFAULT);

                const std::wstring& outStr = outputCapture.GetOutput();
                if (!outStr.empty() && outStr.find(L"???") == std::wstring::npos) {
                    DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"  +0x%04lx [0x%p] (%s): %s",
                        offset, reinterpret_cast<void*>(currentAddr), displayCmds[c], outStr.c_str());
                }
            }

            // 2. Read pointer at current offset if DataSpaces is available
            if (DataSpaces) {
                ULONG64 ptrValue = 0;
                ULONG bytesRead = 0;
                if (SUCCEEDED(DataSpaces->ReadPointersVirtual(1, currentAddr, &ptrValue)) && ptrValue != 0) {
                    wchar_t symName[256] = { 0 };
                    ULONG64 displacement = 0;
                    if (SUCCEEDED(Symbols->GetNameByOffsetWide(ptrValue, symName, _countof(symName), nullptr, &displacement))) {
                        DebugControl->OutputWide(DEBUG_OUTCTL_ALL_CLIENTS, L"  +0x%04lx [0x%p] (Pointer): 0x%p -> %s+0x%llx\n",
                            offset, reinterpret_cast<void*>(currentAddr), reinterpret_cast<void*>(ptrValue), symName, displacement);
                    }
                }
            }
        }
    }

Exit:
    if (DataSpaces) DataSpaces->Release();
    if (Symbols) Symbols->Release();
    if (DebugControl) DebugControl->Release();
    return hr;
}
