// structscan - a WinDbg extension that scans data structures for which you do not have 
// private symbols and attempts to find interesting data in them.
// Joseph Ryan Ries - 2022. Watch the development on this extension on video
// here: https://www.youtube.com/watch?v=d1uT8tmnhZI
// This is a test comment to force recompilation. New comment for commit.
//
// TODO: Currently the only way I have gotten this to work is if I install my callback to
// get debugger output, execute the debugger command, then reinstall the original callback
// to write text to the debugger window. I feel like this constant flipping back and forth
// between the two callbacks is probably wrong. There must be a better way. I feel like I'm
// supposed to be supplying an array of callbacks that will be called in series, but I don't know...

// Need to define INITGUID before dbgeng.h because we need to use the GUIDs
// from C, since we don't have __uuidof
#define INITGUID
#define CINTERFACE // Added to ensure C-style COM interface usage

// Removed #define UNICODE and #define _UNICODE as they are defined in project settings

#include <DbgEng.h>
#include <windows.h> // Required for InterlockedIncrement/Decrement
#include <wchar.h>

#include <stdio.h>

#include "Main.h"

#define EXTENSION_VERSION_MAJOR	1

#define EXTENSION_VERSION_MINOR 0

// Need to define a larger buffer for the module!symbol names
wchar_t gOutputBuffer[4096];

// Command buffer for debugger commands
wchar_t gCommandBuffer[512]; // Increased size to accommodate longer symbol paths

volatile ULONG g_cRef = 1; // Global reference count for our callback object

IDebugOutputCallbacks2* gPrevOutputCallback;

IDebugOutputCallbacks2 gOutputCallback;

IDebugOutputCallbacks2Vtbl gOcbVtbl = {
	.AddRef = &CbAddRef,
	.Release = &CbRelease,
	.Output = &CbOutput,
	.Output2 = &CbOutput2,
	.QueryInterface = &CbQueryInterface,
	.GetInterestMask = &CbGetInterestMask };

// Forward declarations for new functions
HRESULT AcquireDebugInterfaces(SCAN_CONTEXT* Context, IDebugClient4* Client);
HRESULT EnumerateAndScanAllSymbols(SCAN_CONTEXT* Context);

// This is the entry point of our DLL. EngHost calls this as soon as you load the DLL.
__declspec(dllexport) HRESULT CALLBACK DebugExtensionInitialize(PULONG Version, PULONG Flags)
{
	*Version = DEBUG_EXTENSION_VERSION(EXTENSION_VERSION_MAJOR, EXTENSION_VERSION_MINOR);

	*Flags = 0;

	gOutputCallback.lpVtbl = &gOcbVtbl;

	return(S_OK);
}

__declspec(dllexport) HRESULT CALLBACK structscan(IDebugClient4* Client, PCSTR Args) // Keep Args for now, make it optional later or overload
{
	HRESULT Hr = S_OK;

	SCAN_CONTEXT Context = { 0 };
    Context.Client = Client;

    // Ensure we get DebugControl for initial output
    if ((Hr = AcquireDebugInterfaces(&Context, Client)) == S_OK)
    {
        Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: Function entered. Hr from AcquireDebugInterfaces: 0x%lx\n", (unsigned long)Hr);
    }
    else
    {
        // If AcquireDebugInterfaces fails, we can't output messages. Log to file directly.
        FILE* logFile = NULL;
        _wfopen_s(&logFile, L"C:\\lg.txt", L"a+");
        if (logFile) {
            fwprintf(logFile, L"structscan: Function entered. Hr from AcquireDebugInterfaces: 0x%lx (AcquireDebugInterfaces failed, direct file log).\n", (unsigned long)Hr);
            fclose(logFile);
        }
        goto Exit;
    }

    // --- Inlined SetupAndRestoreOutputCallbacks logic ---
    Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: Attempting to get existing output callback (inlined)...\n");

    Hr = Context.Client->lpVtbl->GetOutputCallbacks(Context.Client, (PDEBUG_OUTPUT_CALLBACKS*)&gPrevOutputCallback);
    if (Hr != S_OK)
    {
        Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: Failed to get existing output callback (inlined)! Hr = 0x%lx!\n\n\n", (unsigned long)Hr);
        FILE* logFileError = NULL; // Critical error, direct file log
        _wfopen_s(&logFileError, L"C:\\lg.txt", L"a+");
        if (logFileError) {
            fwprintf(logFileError, L"structscan: Failed to get existing output callback (inlined)! Hr = 0x%lx!\n", (unsigned long)Hr);
            fclose(logFileError);
        }
        goto Exit;
    }
    Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: Successfully got existing output callback (inlined). PrevOutputCallback = 0x%p\n", (void*)gPrevOutputCallback);

    Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: Attempting to set our output callback (inlined)...\n");

    Hr = Context.Client->lpVtbl->SetOutputCallbacks(Context.Client, (PDEBUG_OUTPUT_CALLBACKS)&gOutputCallback);
    // Always print the HRESULT from SetOutputCallbacks
    Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: SetOutputCallbacks returned Hr = 0x%lx.\n", (unsigned long)Hr);

    if (Hr != S_OK)
    {
        Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: Failed to set our output callback (inlined)! Critical error, exiting. Hr = 0x%lx!\n\n\n", (unsigned long)Hr);
        FILE* logFileSetCritError = NULL; // Critical error, direct file log
        _wfopen_s(&logFileSetCritError, L"C:\\lg.txt", L"a+");
        if (logFileSetCritError) {
            fwprintf(logFileSetCritError, L"structscan: Failed to set our output callback (inlined)! Critical error, exiting. Hr = 0x%lx!\n", (unsigned long)Hr);
            fclose(logFileSetCritError);
        }
        goto Exit; // Exit here, this is the critical failure point
    }
    Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: Successfully set our output callback (inlined).\n");

    // --- End inlined SetupAndRestoreOutputCallbacks logic ---

    // Check if arguments are provided. If not, perform full scan.
    if (Args != NULL && Args[0] != '\0')
    {
        size_t CharsConverted = 0;
        mbstowcs_s(&CharsConverted, Context.WideArgs, _countof(Context.WideArgs), Args, _TRUNCATE);

        // Original validation logic for single symbol scan
        if (wcslen(Context.WideArgs) >= 64 ||
            wcschr(Context.WideArgs, L'!') == NULL ||
            Context.WideArgs[0] == L'!' ||
            wcschr(Context.WideArgs, L' ') ||
            wcschr(Context.WideArgs, L'*'))
        {
            // Output help message for invalid single argument (will be caught by CbOutput2)
            if ((Hr = AcquireDebugInterfaces(&Context, Client)) == S_OK) // Re-acquire interfaces if not already successful
            {
                Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan v%d.%d, Joseph Ryan Ries 2022\n\n", (int)EXTENSION_VERSION_MAJOR, (int)EXTENSION_VERSION_MINOR);
                Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Scans data structures for which you do not have private symbols, looking for interesting data.\n\n");
                Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"USAGE: !structscan [module!struct] OR !structscan (for full scan)\n\n");
            }
            Hr = E_INVALIDARG;
            goto Exit;
        }

        // Extract module name from WideArgs for single symbol scan
        for (size_t c = 0; c < _countof(Context.ModuleName); c++)
        {
            if (Context.WideArgs[c] == L'!')
            {
                break;
            }
            Context.ModuleName[c] = Context.WideArgs[c];
        }

        if ((Hr = GetSymbolInformation(&Context)) != S_OK) {
            FILE* errLogFile = NULL;
            _wfopen_s(&errLogFile, L"C:\\lg.txt", L"a+"); // Direct file log for critical failure in symbol info
            if (errLogFile) {
                fwprintf(errLogFile, L"structscan: GetSymbolInformation failed! Hr = 0x%lx!\n", (unsigned long)Hr);
                fclose(errLogFile);
            }
            goto Exit;
        }
        
        // Test direct OutputWide after setting our callback
        Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: Test message from direct OutputWide after setting our callback.\n");
        
        // Test command execution after setting our callback
        Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: Executing test command !sym...\n");

        memset(gOutputBuffer, 0, sizeof(gOutputBuffer)); // Clear buffer before test
        Context.DebugControl->lpVtbl->ExecuteWide(Context.DebugControl, DEBUG_OUTCTL_THIS_CLIENT, L"!sym", DEBUG_EXECUTE_DEFAULT);

        // Output buffer should contain !sym output if our callback worked
        if (gOutputBuffer[0] != '\0') {
            Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: Output from !sym captured: %s\n", gOutputBuffer);
        } else {
            Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: No output from !sym captured by our callback.\n");
        }

        wchar_t* DisplayMemCommands[] = { L"dS", L"ds" };
        if ((Hr = ScanMemoryForInterestingData(&Context, DisplayMemCommands, _countof(DisplayMemCommands))) != S_OK)
        {
            goto Exit;
        }
    }
    else // No arguments provided, perform full scan
    {
        Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Press Ctrl+C to abort...\n");
        
        Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: Test message from direct OutputWide after setting our callback (full scan path).\n");

        Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: Executing test command !sym (full scan path)...\n");

        memset(gOutputBuffer, 0, sizeof(gOutputBuffer));
        Context.DebugControl->lpVtbl->ExecuteWide(Context.DebugControl, DEBUG_OUTCTL_THIS_CLIENT, L"!sym", DEBUG_EXECUTE_DEFAULT);

        if (gOutputBuffer[0] != '\0') {
            Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: Output from !sym captured (full scan path): %s\n", gOutputBuffer);
        } else {
            Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: No output from !sym captured by our callback (full scan path).\n");
        }

        if ((Hr = EnumerateAndScanAllSymbols(&Context)) != S_OK)
        {
            goto Exit;
        }
    }

Exit:
    	// Log final messages to file (direct file log).
        FILE* finalLogFile = NULL;
        _wfopen_s(&finalLogFile, L"C:\\lg.txt", L"a+");
        if (finalLogFile) {
            fwprintf(finalLogFile, L"structscan: Exiting with Hr = 0x%lx.\n", (unsigned long)Hr);
            fclose(finalLogFile);
        }

    	ReleaseInterfaces(&Context, gPrevOutputCallback);

    	return(Hr);
}

// All of these CbXXX functions are my implementations of the methods that you would
// find on a IDebugCallbacks2 interface. I will put pointers to all of these functions
// into a "lpVtbl" and set that onto my callback during the extension initialization routine.
// All of these functions need to exist even if they don't do anything because the debug engine
// will try to call them and enghost will crash if any function pointers are null.

ULONG __cdecl CbAddRef(IDebugOutputCallbacks2* This)
{
	UNREFERENCED_PARAMETER(This);

	return InterlockedIncrement((volatile LONG*)&g_cRef);
}

HRESULT __cdecl CbQueryInterface(IDebugOutputCallbacks2* This, REFIID InterfaceId, PVOID* Interface)
{
	// Ensure Interface is not NULL
	if (!Interface)
	{
		return E_POINTER;
	}

	*Interface = NULL; // Initialize to NULL

	// Check for IDebugOutputCallbacks2 or IUnknown
	if (IsEqualIID(InterfaceId, &IID_IDebugOutputCallbacks2) ||
		IsEqualIID(InterfaceId, &IID_IUnknown))
	{
		*Interface = This;
		CbAddRef(This);
		return S_OK;
	}
	// Check for IDebugOutputCallbacks (base interface)
	else if (IsEqualIID(InterfaceId, &IID_IDebugOutputCallbacks))
	{
		*Interface = This;
		CbAddRef(This);
		return S_OK;
	}

	return E_NOINTERFACE; // Interface not supported
}

ULONG __cdecl CbRelease(IDebugOutputCallbacks2* This)
{
	UNREFERENCED_PARAMETER(This);

	return InterlockedDecrement((volatile LONG*)&g_cRef);
}

HRESULT __cdecl CbGetInterestMask(IDebugOutputCallbacks2* This, PULONG Mask)
{
	UNREFERENCED_PARAMETER(This);

	*Mask = DEBUG_OUTCBI_ANY_FORMAT;

	return(S_OK);
}

HRESULT __stdcall CbOutput(IDebugOutputCallbacks2* This, ULONG Mask, PCSTR Text)
{
	UNREFERENCED_PARAMETER(This);

	UNREFERENCED_PARAMETER(Mask);

	UNREFERENCED_PARAMETER(Text);

	return(S_OK);
}

HRESULT __stdcall CbOutput2(IDebugOutputCallbacks2* This, ULONG Which, ULONG Flags, ULONG64 Arg, PCWSTR Text)
{
	UNREFERENCED_PARAMETER(This);

	UNREFERENCED_PARAMETER(Which);

	UNREFERENCED_PARAMETER(Flags);

	UNREFERENCED_PARAMETER(Arg);

	// Copy to global buffer for !sym output capture
	wcscpy_s(gOutputBuffer, _countof(gOutputBuffer), Text);

	return(S_OK);
}

// New helper function to acquire debug interfaces
HRESULT AcquireDebugInterfaces(
    SCAN_CONTEXT* Context,
    IDebugClient4* Client)
{
    HRESULT Hr = S_OK;

    if ((Hr = Client->lpVtbl->QueryInterface(Client, &IID_IDebugControl4, (void**)&Context->DebugControl)) != S_OK)
    {
        return Hr;
    }

    if ((Hr = Client->lpVtbl->QueryInterface(Client, &IID_IDebugSymbols4, (void**)&Context->Symbols)) != S_OK)
    {
        // Output to debugger if DebugControl is available
        if (Context->DebugControl && Context->DebugControl->lpVtbl) {
            Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"QueryInterface for IDebugSymbols4 failed! Hr = 0x%lx!\n\n", (unsigned long)Hr);
        }
        return Hr;
    }
    return Hr;
}

HRESULT GetSymbolInformation(
    SCAN_CONTEXT* Context)
{
    HRESULT Hr = S_OK;

    // The module name might be already set if it's a single symbol scan
    // For full scan, this function won't be called directly.
    // If Context->ModuleName[0] is empty, GetModuleByModuleNameWide might fail or
    // not find the correct module. For the general case of this function,
    // we need to ensure Context->ModuleName is valid.
    // No direct file logging here, as OutputWide messages are caught by CbOutput2.

    if ((Hr = Context->Symbols->lpVtbl->GetModuleByModuleNameWide(Context->Symbols, Context->ModuleName, 0, &Context->ImageIndex, &Context->ImageBase)) != S_OK)
    {
        Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"GetModuleByModuleNameWide failed for module %s! Hr = 0x%lx!\n\n", Context->ModuleName, (unsigned long)Hr);
        return Hr;
    }

    if ((Hr = Context->Symbols->lpVtbl->GetModuleParameters(Context->Symbols, 1, NULL, Context->ImageIndex, &Context->ModuleParameters)) != S_OK)
    {
        Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"GetModuleParameters failed! Hr = 0x%lx!\n\n", (unsigned long)Hr);
        return Hr;
    }

    Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Module name: %s\nImage base: 0x%llx\nMemory Size: %llu\n", Context->ModuleName, (unsigned long long)Context->ImageBase, (unsigned long long)Context->ModuleParameters.Size);

    ULONG64 SearchHandle = 0;

    if ((Hr = Context->Symbols->lpVtbl->StartSymbolMatchWide(Context->Symbols, Context->WideArgs, &SearchHandle)) != S_OK)
    {
        Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"StartSymbolMatchWide failed! Hr = 0x%lx!\n\n", (unsigned long)Hr);
        return Hr;
    }

    Context->Symbols->lpVtbl->GetNextSymbolMatch(Context->Symbols, SearchHandle, NULL, 0, 0, &Context->SymbolAddress);

    Context->Symbols->lpVtbl->EndSymbolMatch(Context->Symbols, SearchHandle);

    if (Context->SymbolAddress == 0)
    {
        Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Symbol %s was not found!\n\n", Context->WideArgs);
        return E_FAIL;
    }

    Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Symbol Address: 0x%llx\n", (unsigned long long)Context->SymbolAddress);

    return Hr;
}

HRESULT ScanMemoryForInterestingData(
    SCAN_CONTEXT* Context,
    wchar_t** DisplayMemCommands,
    ULONG DisplayMemCommandsCount
)
{
    BOOL EndScan = FALSE;
    ULONG MaxScanOffset = 0x200; // Scan up to 512 bytes for demonstration

    // If SymbolAddress is 0, it means the symbol was not found or is invalid.
    // This can happen in the full scan if a symbol is encountered that doesn't have a valid address.
    if (Context->SymbolAddress == 0)
    {
        FILE* logFile = NULL;
        _wfopen_s(&logFile, L"C:\\lg.txt", L"a+"); // Direct file log for skipped scan
        if (logFile) {
            fwprintf(logFile, L"structscan: Skipping scan for symbol address is 0.\n");
            fclose(logFile);
        }
        return S_OK; // Just skip, don't return error
    }

    for (size_t c = 0; c < DisplayMemCommandsCount; c++)
    {
        ULONG Offset = 0;

        // Skip to next command if scan ended previously
        if (EndScan != FALSE)
        {
            break;
        }

        while (EndScan == FALSE && Offset < MaxScanOffset) // Loop until EndScan or MaxScanOffset
        {
            _snwprintf_s(gCommandBuffer, _countof(gCommandBuffer), _TRUNCATE, L"%s %s+0x%lx", DisplayMemCommands[c], Context->WideArgs, Offset);

            // Log the command about to be executed to WinDbg console (will be caught by CbOutput2).
            Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: Executing command: %s\n", gCommandBuffer);

            // For commands like dS/ds, their output is not routed through IDebugOutputCallbacks.
            // So, we execute the command, but cannot reliably capture its output into gOutputBuffer.
            // The output will only appear in the WinDbg console. Only log the command itself directly.
            memset(gOutputBuffer, 0, sizeof(gOutputBuffer)); // Clear buffer (though not used for dS/ds output)
            Context->DebugControl->lpVtbl->ExecuteWide(Context->DebugControl, DEBUG_OUTCTL_THIS_CLIENT, gCommandBuffer, DEBUG_EXECUTE_DEFAULT);

            Offset += 16; // Increment by 16 bytes for next scan, adjust as needed

            // Check for Ctrl+C to abort scan (only for current symbol)
            if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) && (GetAsyncKeyState(0x43) & 0x8000))
            {
                EndScan = TRUE;
                FILE* ctrlCLogFile = NULL;
                _wfopen_s(&ctrlCLogFile, L"C:\\lg.txt", L"a+"); // Direct file log for Ctrl+C
                if (ctrlCLogFile) {
                    fwprintf(ctrlCLogFile, L"\nCtrl+C detected. Aborting scan for current symbol.\n");
                    fclose(ctrlCLogFile);
                }
            }
        }
    }
    return S_OK;
}

// New function to enumerate and scan all symbols
HRESULT EnumerateAndScanAllSymbols(
    SCAN_CONTEXT* Context)
{
    HRESULT Hr = S_OK;
    ULONG NumberOfModules = 0;
    ULONG i = 0;
    wchar_t ModuleNameBuffer[MAX_PATH] = { 0 };
    ULONG NameSize = 0;

    wchar_t* DisplayMemCommands[] = { L"dS", L"ds" }; // Commands to use for scanning

    // Removed typedef GETNUMBERMODULES_FN and direct cast to simplify and remove C4191 warning.
    if ((Hr = Context->Symbols->lpVtbl->GetNumberModules(Context->Symbols, &NumberOfModules, NULL)) != S_OK)
    {
        Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"GetNumberModules failed! Hr = 0x%lx!\n\n", (unsigned long)Hr);
        return Hr;
    }

    Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Scanning %lu modules for interesting data (press Ctrl+C to abort full scan)...\n", NumberOfModules);

    for (i = 0; i < NumberOfModules; i++)
    {
        ULONG64 ImageBase = 0;
        ULONG ImageIndex = 0; // This variable will store the index (which is `i`)

        // Corrected GetModuleByIndex call: takes ULONG Index, PULONG64 Base
        // The DbgEng.h GetModuleByIndex prototype is: HRESULT GetModuleByIndex(THIS_ ULONG Index, PULONG64 Base) PURE;
        if ((Hr = Context->Symbols->lpVtbl->GetModuleByIndex(Context->Symbols, i, &ImageBase)) != S_OK)
        {
            Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"GetModuleByIndex failed for index %lu! Hr = 0x%lx!\n", i, (unsigned long)Hr);
            continue; // Try next module
        }

        // Set ImageIndex to current loop index 'i' for GetModuleNameStringWide
        ImageIndex = i; // Ensure ImageIndex is properly set for GetModuleNameStringWide
        
        if ((Hr = Context->Symbols->lpVtbl->GetModuleNameStringWide(Context->Symbols, DEBUG_MODNAME_MODULE, ImageIndex, ImageBase, ModuleNameBuffer, _countof(ModuleNameBuffer), &NameSize)) != S_OK)
        {
            Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"GetModuleNameStringWide failed for module index %lu! Hr = 0x%lx!\n", i, (unsigned long)Hr);
            continue; // Try next module
        }
        
        // Populate module name in context for this module's symbols
        wcsncpy_s(Context->ModuleName, _countof(Context->ModuleName), ModuleNameBuffer, _TRUNCATE);
        Context->ImageIndex = ImageIndex; // Update ImageIndex in context
        Context->ImageBase = ImageBase; // Update ImageBase in context

        // Noisy output, enable for debugging specific module loading issues
        Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"\nScanning module: %s (Base: 0x%llx)\n", Context->ModuleName, (unsigned long long)ImageBase);

        ULONG64 SearchHandle = 0;
        wchar_t SymbolMatchPattern[128] = { 0 }; // e.g., "module!*" to search all symbols in a module

        // Construct symbol search pattern for the current module
        _snwprintf_s(SymbolMatchPattern, _countof(SymbolMatchPattern), _TRUNCATE, L"%s!*", Context->ModuleName);

        if ((Hr = Context->Symbols->lpVtbl->StartSymbolMatchWide(Context->Symbols, SymbolMatchPattern, &SearchHandle)) != S_OK)
        {
            // This can fail if symbols are not loaded for the module. Continue to next module.
            Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"StartSymbolMatchWide failed for %s! Hr = 0x%lx!\n", SymbolMatchPattern, (unsigned long)Hr);
            continue;
        }

        wchar_t SymbolNameBuffer[256] = { 0 }; // Buffer for symbol name
        ULONG SymbolNameSize = 0;
        ULONG64 CurrentSymbolAddress = 0;

        while (TRUE)
        {
            // Get the next symbol match
            Hr = Context->Symbols->lpVtbl->GetNextSymbolMatchWide(Context->Symbols, SearchHandle, SymbolNameBuffer, _countof(SymbolNameBuffer), &SymbolNameSize, &CurrentSymbolAddress);

            if (Hr != S_OK)
            {
                if (Hr == S_FALSE) // No more matches
                {
                    break;
                }
                // Log other errors but continue to next symbol if possible
                Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"GetNextSymbolMatch failed! Hr = 0x%lx!\n", (unsigned long)Hr);
                break;
            }

            // Update context for the current symbol's full name (e.g., "module!symbol")
            _snwprintf_s(Context->WideArgs, _countof(Context->WideArgs), _TRUNCATE, L"%s!%s", Context->ModuleName, SymbolNameBuffer);
            Context->SymbolAddress = CurrentSymbolAddress;

            // Only output if Ctrl+C is not pressed.
            if (!((GetAsyncKeyState(VK_CONTROL) & 0x8000) && (GetAsyncKeyState(0x43) & 0x8000)))
            {
                // This output can be noisy if many symbols are found. Enable for debugging.
                Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Attempting scan for symbol: %s (Address: 0x%llx)\n", Context->WideArgs, (unsigned long long)Context->SymbolAddress);
                ScanMemoryForInterestingData(Context, DisplayMemCommands, _countof(DisplayMemCommands)); // Call the scanning function
            }
            else
            {
                Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"\nCtrl+C detected. Aborting full scan.\n");
                FILE* ctrlCLogFile = NULL;
                _wfopen_s(&ctrlCLogFile, L"C:\\lg.txt", L"a+"); // Direct file log for Ctrl+C
                if (ctrlCLogFile) {
                    fwprintf(ctrlCLogFile, L"\nCtrl+C detected. Aborting full scan.\n");
                    fclose(ctrlCLogFile);
                }
                Hr = S_FALSE; // Indicate abortion
                goto EndModuleAndSymbolScan; // Exit both loops
            }
        }
        Context->Symbols->lpVtbl->EndSymbolMatch(Context->Symbols, SearchHandle);
        
        // If Ctrl+C was pressed in the inner loop, break outer loop as well
        if (Hr == S_FALSE) break;
    }
    EndModuleAndSymbolScan:; // Label for goto

    return Hr;
}


void ReleaseInterfaces(
    SCAN_CONTEXT* Context,
    IDebugOutputCallbacks2* PrevOutputCallback
)
{
    // Ensure Context and its Client pointer are valid before proceeding
    if (!Context || !Context->Client) {
        return;
    }

    // Attempt to restore original output callbacks if they exist
    // This should always be done if SetupAndRestoreOutputCallbacks was called.
    if (PrevOutputCallback)
    {
        if (Context->DebugControl && Context->DebugControl->lpVtbl) {
            Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: Attempting to restore original callback...\n");
        }

        HRESULT hrRestore = Context->Client->lpVtbl->SetOutputCallbacks(Context->Client, (PDEBUG_OUTPUT_CALLBACKS)PrevOutputCallback);
        if (hrRestore != S_OK)
        {
            // Only output if DebugControl is valid
            if (Context->DebugControl && Context->DebugControl->lpVtbl) {
                Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Failed to restore original callback! Hr = 0x%lx\n\n", (unsigned long)hrRestore);
            }
            FILE* logFileRestoreErr = NULL; // Direct file log for restore failure
            _wfopen_s(&logFileRestoreErr, L"C:\\lg.txt", L"a+");
            if (logFileRestoreErr) {
                fwprintf(logFileRestoreErr, L"structscan: Failed to restore original callback! Hr = 0x%lx\n", (unsigned long)hrRestore);
                fclose(logFileRestoreErr);
            }
        }
        else
        {
            if (Context->DebugControl && Context->DebugControl->lpVtbl) {
                Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan: Successfully restored original callback.\n");
            }
        }
    }

    // Release Symbols interface if it was successfully acquired
    if (Context->Symbols && Context->Symbols->lpVtbl)
    {
        Context->Symbols->lpVtbl->Release(Context->Symbols);
        Context->Symbols = NULL; // Clear pointer after release
    }

    // Release DebugControl interface if it was successfully acquired
    if (Context->DebugControl && Context->DebugControl->lpVtbl)
    {
        Context->DebugControl->lpVtbl->Release(Context->DebugControl);
        Context->DebugControl = NULL; // Clear pointer after release
    }
    // Context->Client should NOT be released by the extension, as it's passed from the debugger engine.
}