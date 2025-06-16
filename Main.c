// structscan - a WinDbg extension that scans data structures for which you do not have 
// private symbols and attempts to find interesting data in them.
// Joseph Ryan Ries - 2022. Watch the development on this extension on video
// here: https://www.youtube.com/watch?v=d1uT8tmnhZI
//
// TODO: Currently the only way I have gotten this to work is if I install my callback to
// get debugger output, execute the debugger command, then reinstall the original callback
// to write text to the debugger window. I feel like this constant flipping back and forth
// between the two callbacks is probably wrong. There must be a better way. I feel like I'm
// supposed to be supplying an array of callbacks that will be called in series, but I don't know...

// Need to define INITGUID before dbgeng.h because we need to use the GUIDs
// from C, since we don't have __uuidof
#define INITGUID

#include <DbgEng.h>

#include <stdio.h>

#include "Main.h"

#define EXTENSION_VERSION_MAJOR	1

#define EXTENSION_VERSION_MINOR 0

wchar_t gOutputBuffer[4096];

wchar_t gCommandBuffer[128];

IDebugOutputCallbacks2* gPrevOutputCallback;

IDebugOutputCallbacks2 gOutputCallback;

IDebugOutputCallbacks2Vtbl gOcbVtbl = { 
	.AddRef = &CbAddRef,
	.Release = &CbRelease,
	.Output = &CbOutput,
	.Output2 = &CbOutput2,
	.QueryInterface = &CbQueryInterface,
	.GetInterestMask = &CbGetInterestMask };

// This is the entry point of our DLL. EngHost calls this as soon as you load the DLL.
__declspec(dllexport) HRESULT CALLBACK DebugExtensionInitialize(PULONG Version, PULONG Flags)
{
	*Version = DEBUG_EXTENSION_VERSION(EXTENSION_VERSION_MAJOR, EXTENSION_VERSION_MINOR);

	*Flags = 0;

	gOutputCallback.lpVtbl = &gOcbVtbl;

	return(S_OK);
}

__declspec(dllexport) HRESULT CALLBACK structscan(IDebugClient4* Client, PCSTR Args)
{
	HRESULT Hr = S_OK;

	SCAN_CONTEXT Context = { 0 };
    Context.Client = Client;

	wchar_t* DisplayMemCommands[] = { L"dS", L"ds" };

	BOOL EndScan = FALSE;

	if ((Hr = InitAndValidateArgs(&Context, Args)) != S_OK)
	{
		goto Exit;
	}

	if ((Hr = GetSymbolInformation(&Context)) != S_OK)
	{
		goto Exit;
	}

	Context.DebugControl->lpVtbl->OutputWide(Context.DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Press Ctrl+C to abort...\n");

	if ((Hr = SetupAndRestoreOutputCallbacks(Context.Client, Context.DebugControl, &gPrevOutputCallback)) != S_OK)
	{
		goto Exit;
	}

	if ((Hr = ScanMemoryForInterestingData(&Context, DisplayMemCommands, _countof(DisplayMemCommands))) != S_OK)
	{
		goto Exit;
	}

Exit:

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

	return(1);
}

ULONG __cdecl CbQueryInterface(IDebugOutputCallbacks2* This, REFIID InterfaceId, PVOID* Interface)
{
	UNREFERENCED_PARAMETER(InterfaceId);

	*Interface = This;

	CbAddRef(This);

	return(S_OK);
}

ULONG __cdecl CbRelease(IDebugOutputCallbacks2* This)
{
	UNREFERENCED_PARAMETER(This);

	return(0);
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

	wcscpy_s(gOutputBuffer, _countof(gOutputBuffer), Text);

	return(S_OK);
}

HRESULT InitAndValidateArgs(
    SCAN_CONTEXT* Context,
    PCSTR Args)
{
    HRESULT Hr = S_OK;

    size_t CharsConverted = 0;

    mbstowcs_s(&CharsConverted, Context->WideArgs, _countof(Context->WideArgs), Args, _TRUNCATE);

    if ((Hr = Context->Client->lpVtbl->QueryInterface(Context->Client, &IID_IDebugControl4, (void**)&Context->DebugControl)) != S_OK)
    {
        return Hr;
    }

    if ((Hr = Context->Client->lpVtbl->QueryInterface(Context->Client, &IID_IDebugSymbols4, (void**)&Context->Symbols)) != S_OK)
    {
        Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"QueryInterface failed! Hr = 0x%x!\n\n", Hr);
        return Hr;
    }

    if (wcslen(Context->WideArgs) >= 64 ||
        wcschr(Context->WideArgs, L'!') == NULL ||
        Context->WideArgs[0] == L'!' ||
        wcschr(Context->WideArgs, L' ') ||
        wcschr(Context->WideArgs, L'*'))
    {
        Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"structscan v%d.%d, Joseph Ryan Ries 2022\n\n", EXTENSION_VERSION_MAJOR, EXTENSION_VERSION_MINOR);
        Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Scans data structures for which you do not have private symbols, looking for interesting data.\n\n");
        Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"USAGE: !structscan module!struct\n\n");
        return E_INVALIDARG;
    }

    // Extract module name from WideArgs
    for (size_t c = 0; c < _countof(Context->ModuleName); c++)
    {
        if (Context->WideArgs[c] == L'!')
        {
            break;
        }
        Context->ModuleName[c] = Context->WideArgs[c];
    }

    return Hr;
}

HRESULT GetSymbolInformation(
    SCAN_CONTEXT* Context)
{
    HRESULT Hr = S_OK;

    if ((Hr = Context->Symbols->lpVtbl->GetModuleByModuleNameWide(Context->Symbols, Context->ModuleName, 0, &Context->ImageIndex, &Context->ImageBase)) != S_OK)
    {
        Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"GetModuleByModuleNameWide failed! Hr = 0x%x!\n\n", Hr);
        return Hr;
    }

    if ((Hr = Context->Symbols->lpVtbl->GetModuleParameters(Context->Symbols, 1, NULL, Context->ImageIndex, &Context->ModuleParameters)) != S_OK)
    {
        Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"GetModuleParameters failed! Hr = 0x%x!\n\n", Hr);
        return Hr;
    }

    Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Module name: %s\nImage base: 0x%p\nMemory Size: %llu\n", Context->ModuleName, Context->ImageBase, Context->ModuleParameters.Size);

    ULONG64 SearchHandle = 0;

    if ((Hr = Context->Symbols->lpVtbl->StartSymbolMatchWide(Context->Symbols, Context->WideArgs, &SearchHandle)) != S_OK)
    {
        Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"StartSymbolMatchWide failed! Hr = 0x%x!\n\n", Hr);
        return Hr;
    }

    Context->Symbols->lpVtbl->GetNextSymbolMatch(Context->Symbols, SearchHandle, NULL, 0, 0, &Context->SymbolAddress);

    Context->Symbols->lpVtbl->EndSymbolMatch(Context->Symbols, SearchHandle);

    if (Context->SymbolAddress == 0)
    {
        Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Symbol %s was not found!\n\n", Context->WideArgs);
        return E_FAIL;
    }

    Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Symbol Address: %p\n", Context->SymbolAddress);

    return Hr;
}

HRESULT SetupAndRestoreOutputCallbacks(
    IDebugClient4* Client,
    IDebugControl4* DebugControl,
    IDebugOutputCallbacks2** PrevOutputCallback)
{
    HRESULT Hr = S_OK;

    if ((Hr = Client->lpVtbl->GetOutputCallbacks(Client, (PDEBUG_OUTPUT_CALLBACKS)PrevOutputCallback)) != S_OK)
    {
        DebugControl->lpVtbl->OutputWide(DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Failed to get existing output callback! Hr = 0x%x\n\n\n", Hr);
        return Hr;
    }

    if ((Hr = Client->lpVtbl->SetOutputCallbacks(Client, (PDEBUG_OUTPUT_CALLBACKS)&gOutputCallback)) != S_OK)
    {
        DebugControl->lpVtbl->OutputWide(DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Failed to set output callback! Hr = 0x%x\n\n\n", Hr);
        return Hr;
    }
    return Hr;
}

HRESULT ScanMemoryForInterestingData(
    SCAN_CONTEXT* Context,
    wchar_t** DisplayMemCommands,
    ULONG DisplayMemCommandsCount
)
{
    BOOL EndScan = FALSE;

    for (size_t c = 0; c < DisplayMemCommandsCount; c++)
    {
        ULONG Offset = 0;

        if (EndScan != FALSE)
        {
            break;
        }

        while (EndScan == FALSE)
        {
            wchar_t SymbolName[64] = { 0 };

            _snwprintf_s(gCommandBuffer, _countof(gCommandBuffer), _TRUNCATE, L"%s %s+0x%lx", DisplayMemCommands[c], Context->WideArgs, Offset);

            Context->DebugControl->lpVtbl->ExecuteWide(Context->DebugControl, DEBUG_OUTCTL_THIS_CLIENT, gCommandBuffer, DEBUG_EXECUTE_DEFAULT);

            if (gPrevOutputCallback)
            {
                HRESULT tempHr = Context->Client->lpVtbl->SetOutputCallbacks(Context->Client, (PDEBUG_OUTPUT_CALLBACKS)gPrevOutputCallback);
                if (tempHr != S_OK)
                {
                    Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Failed to restore original callback!\n\n");
                    return tempHr;
                }
            }

            if (wcsstr(gOutputBuffer, L"???") == 0 && (gOutputBuffer[0] != '\0'))
            {
                Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"%s = %s", gCommandBuffer, gOutputBuffer);
            }

            memset(gOutputBuffer, 0, sizeof(gOutputBuffer));

            HRESULT tempHr = Context->Client->lpVtbl->SetOutputCallbacks(Context->Client, (PDEBUG_OUTPUT_CALLBACKS)&gOutputCallback);
            if (tempHr != S_OK)
            {
                Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Failed to set output callback!\n\n");
                return tempHr;
            }

            Offset += 2;

            Context->Symbols->lpVtbl->GetNameByOffsetWide(Context->Symbols, (Context->SymbolAddress + Offset), SymbolName, _countof(SymbolName), NULL, NULL);

            if (wcscmp(SymbolName, Context->WideArgs) != 0)
            {
                break;
            }

            if ((Offset >= 0x1000) || ((GetAsyncKeyState(VK_CONTROL) & 0x8000) && (GetAsyncKeyState(0x43) & 0x8000)))
            {
                EndScan = TRUE;
            }
        }
    }
    return S_OK;
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
    if (PrevOutputCallback)
    {
        HRESULT hrRestore = Context->Client->lpVtbl->SetOutputCallbacks(Context->Client, (PDEBUG_OUTPUT_CALLBACKS)PrevOutputCallback);
        if (hrRestore != S_OK)
        {
            // Only output if DebugControl is valid
            if (Context->DebugControl && Context->DebugControl->lpVtbl) {
                Context->DebugControl->lpVtbl->OutputWide(Context->DebugControl, DEBUG_OUTCTL_ALL_CLIENTS, L"Failed to restore original callback!\n\n");
            }
        }
    }

    // Release Symbols interface if it was successfully acquired
    if (Context->Symbols && Context->Symbols->lpVtbl)
    {
        Context->Symbols->lpVtbl->Release(Context->Symbols);
    }

    // Release DebugControl interface if it was successfully acquired
    if (Context->DebugControl && Context->DebugControl->lpVtbl)
    {
        Context->DebugControl->lpVtbl->Release(Context->DebugControl);
    }
    // Context->Client should NOT be released by the extension, as it's passed from the debugger engine.
}