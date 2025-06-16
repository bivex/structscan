# structscan

This is a simple WinDbg extension that scans data structures for which you do not have private symbols and tries to find interesting data.

Watch the development in real time on video here: https://www.youtube.com/watch?v=d1uT8tmnhZI

## Installation

To install the `structscan.dll` extension, copy the `structscan.dll` file into the `winext` subdirectory of your WinDbg installation path. For example, if WinDbg is installed in `C:\Program Files\Debugging Tools for Windows (x64)`, you would copy the DLL to `C:\Program Files\Debugging Tools for Windows (x64)\winext`.

Alternatively, you can copy the `structscan.dll` file to `%LOCALAPPDATA%\Dbg\UserExtensions` (e.g., `C:\Users\<YourUsername>\AppData\Local\Dbg\UserExtensions`). This location is typically searched by WinDbg for user-specific extensions.

After copying the DLL, you can load the extension in WinDbg using the command: `!load structscan.dll`

## Usage Notes

The `structscan` extension is designed to scan data structures for which you **do not have private symbols**. This is particularly useful when analyzing custom or undocumented structures within a module.

For well-known Windows operating system structures, such as `ntdll!_PEB` (Process Environment Block) or kernel structures like `nt!_ETHREAD` (Executive Thread Block), WinDbg provides its own built-in commands that are often more effective and provide richer detail, as these structures typically have public symbols available from Microsoft.

**Examples of Built-in WinDbg Commands for Well-Known Structures:**

*   To display the Process Environment Block (`_PEB`) of the current process:
    ```
    !peb
    ```
*   To display the definition of a specific structure (e.g., `_PEB` from `ntdll.dll`):
    ```
    dt ntdll!_PEB
    ```
*   To list modules and their symbol status (`pdb symbols` means symbols are loaded, `deferred` means they are not yet fully loaded):
    ```
    lmD
    ```
*   To force reload symbols for a specific module (e.g., `ntdll.dll`):
    ```
    .reload /f ntdll.dll
    ```
*   To check and set your symbol path:
    ```
    sympath
    .sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
    ```

Remember to use `!structscan module!struct` when you are specifically targeting structures without readily available symbol information.
