# structscan

This is a simple WinDbg extension that scans data structures for which you do not have private symbols and tries to find interesting data.

Watch the development in real time on video here: https://www.youtube.com/watch?v=d1uT8tmnhZI

## Installation

To install the `structscan.dll` extension, copy the `structscan.dll` file into the `winext` subdirectory of your WinDbg installation path. For example, if WinDbg is installed in `C:\Program Files\Debugging Tools for Windows (x64)`, you would copy the DLL to `C:\Program Files\Debugging Tools for Windows (x64)\winext`.

Alternatively, you can copy the `structscan.dll` file to `%LOCALAPPDATA%\Dbg\UserExtensions` (e.g., `C:\Users\<YourUsername>\AppData\Local\Dbg\UserExtensions`). This location is typically searched by WinDbg for user-specific extensions.

After copying the DLL, you can load the extension in WinDbg using the command: `!load structscan.dll`

## Usage Notes

The `structscan` extension is designed to scan data structures for which you **do not have private symbols**. This is particularly useful when analyzing custom or undocumented structures within a module.

### Example: Scanning a Custom Application's Structure

This example demonstrates how to use `!structscan` with a hypothetical custom application named `MyCustomApp.exe` that contains an undocumented global data structure `g_AppData` (of type `_APP_DATA_BLOCK`).

1.  **Build the `MyCustomApp` example application:**
    Navigate to the root of the `structscan` project and run `build.bat`. This will compile `MyCustomApp.exe` (and `MyCustomApp.pdb`) into `MyCustomApp_Example\build\Debug`.
    ```bash
    build.bat
    ```

2.  **Run `MyCustomApp.exe`:**
    Execute the compiled application from its `Debug` directory. Keep its console window open and running.
    ```bash
    C:\Users\Admin\Desktop\Dev\structscan\MyCustomApp_Example\build\Debug\MyCustomApp.exe
    ```

3.  **Attach WinDbg to `MyCustomApp.exe`:**
    In WinDbg, go to `File` -> `Attach to a Process...` (or press `F6`), select `MyCustomApp.exe` from the list, and click `OK`. Once attached, type `g` and press Enter to let it run.

4.  **Load the `structscan.dll` extension:**
    ```
    .load structscan.dll
    ```

5.  **Add `MyCustomApp`'s build directory to the symbol path:**
    This allows WinDbg to find the `MyCustomApp.pdb` file, which contains the address of `g_AppData`.
    ```
    .sympath+ C:\Users\Admin\Desktop\Dev\structscan\MyCustomApp_Example\build\Debug
    ```

6.  **Force reload symbols for `MyCustomApp.exe`:**
    ```
    .reload /f MyCustomApp.exe
    ```

7.  **Verify the symbol address (optional, but recommended):**
    ```
    x MyCustomApp!g_AppData
    ```
    This should return the memory address of `g_AppData`.

8.  **Execute `!structscan`:**
    Now, run `!structscan` pointing to the module and the global variable:
    ```
    !structscan MyCustomApp!g_AppData
    ```
    `!structscan` will display memory around `g_AppData` using different display commands (`dS`, `ds`, etc.), attempting to reveal recognizable data (strings, pointers, integers) even without a formal structure definition for `_APP_DATA_BLOCK`.

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
