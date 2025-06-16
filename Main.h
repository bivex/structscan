#pragma once

#include <DbgEng.h> // Required for HRESULT, IDebugClient4, etc.

// structscan - a WinDbg extension that scans data structures for which you do not have 
// private symbols and attempts to find interesting data in them.
// Joseph Ryan Ries - 2022. Watch the development on this extension on video
// here: https://www.youtube.com/watch/v=d1uT8tmnhZI
//
// TODO: Currently the only way I have gotten this to work is if I install my callback to
// get debugger output, execute the debugger command, then reinstall the original callback
// to write text to the debugger window. I feel like this constant flipping back and forth
// between the two callbacks is probably wrong. There must be a better way. I feel like I'm
// supposed to be supplying an array of callbacks that will be called in series, but I don't know...

// Define a structure to hold common scanning context
typedef struct _SCAN_CONTEXT {
    IDebugClient4* Client;
    IDebugControl4* DebugControl;
    IDebugSymbols4* Symbols;
    wchar_t WideArgs[128];
    wchar_t ModuleName[64];
    ULONG ImageIndex;
    ULONG64 ImageBase;
    ULONG64 SymbolAddress;
    DEBUG_MODULE_PARAMETERS ModuleParameters;
} SCAN_CONTEXT, *PSCAN_CONTEXT;

// Global variables defined in Main.c
extern wchar_t gOutputBuffer[4096];
extern wchar_t gCommandBuffer[128];
extern IDebugOutputCallbacks2* gPrevOutputCallback;
extern IDebugOutputCallbacks2 gOutputCallback;
extern IDebugOutputCallbacks2Vtbl gOcbVtbl;

// Function prototypes
__declspec(dllexport) HRESULT CALLBACK DebugExtensionInitialize(PULONG Version, PULONG Flags);
__declspec(dllexport) HRESULT CALLBACK structscan(IDebugClient4* Client, PCSTR Args);

HRESULT InitAndValidateArgs(
    PSCAN_CONTEXT Context,
    PCSTR Args
);

HRESULT GetSymbolInformation(
    PSCAN_CONTEXT Context
);

HRESULT SetupAndRestoreOutputCallbacks(
    IDebugClient4* Client,
    IDebugControl4* DebugControl,
    IDebugOutputCallbacks2** PrevOutputCallback
);

HRESULT ScanMemoryForInterestingData(
    PSCAN_CONTEXT Context,
    wchar_t** DisplayMemCommands,
    ULONG DisplayMemCommandsCount
);

void ReleaseInterfaces(
    PSCAN_CONTEXT Context,
    IDebugOutputCallbacks2* PrevOutputCallback
);

// Callbacks for the debugger engine.
ULONG __cdecl CbAddRef(IDebugOutputCallbacks2* This);
ULONG __cdecl CbQueryInterface(IDebugOutputCallbacks2* This, REFIID InterfaceId, PVOID* Interface);
ULONG __cdecl CbRelease(IDebugOutputCallbacks2* This);
HRESULT __cdecl CbGetInterestMask(IDebugOutputCallbacks2* This, PULONG Mask);
HRESULT __stdcall CbOutput(IDebugOutputCallbacks2* This, ULONG Mask, PCSTR Text);
HRESULT __stdcall CbOutput2(IDebugOutputCallbacks2* This, ULONG Which, ULONG Flags, ULONG64 Arg, PCWSTR Text); 