# Kernel Mode Debugging with WinDbg

To enter kernel mode debugging with WinDbg, you typically need to set up two machines:

1.  **Target Machine:** The machine you will be debugging (where the kernel is running).
2.  **Host Machine:** The machine where WinDbg is running and from which you will control the debugging session.

Here are the most common methods for setting up kernel debugging:

### 1. Serial Debugging

This is an older but reliable method.

**On the Target Machine:**

1.  Open Command Prompt as an administrator.
2.  Execute the following commands:
    ```
    bcdedit /debug on
    bcdedit /dbgsettings serial debugport:COM1 baudrate:115200
    ```
    *   `COM1`: Replace with your serial port number.
    *   `115200`: Baud rate (can be higher, e.g., 921600).
3.  Reboot the target machine.

**On the Host Machine (in WinDbg):**

1.  Launch WinDbg.
2.  Select `File` -> `Kernel Debug` -> `COM`.
3.  Specify the same parameters (`Port` and `Baud Rate`) as configured on the target machine.
4.  Click `OK`. WinDbg will wait for a connection.

### 2. Network Debugging

This is a more modern and faster method. Requires Windows 8 or newer on the target machine.

**On the Target Machine:**

1.  Open Command Prompt as an administrator.
2.  Generate an encryption key (GUID):
    ```
    bcdedit /dbgsettings net hostip:W.X.Y.Z port:N key:your_key_here
    ```
    *   `W.X.Y.Z`: IP address of your host machine.
    *   `N`: Port number (e.g., 50000).
    *   `your_key_here`: Encryption key. **This must be a GUID**, for example, `{F4F4F4F4-F4F4-F4F4-F4F4-F4F4F4F4F4F4}`. You can generate one using PowerShell: `[guid]::NewGuid()`.
3.  Enable debugging:
    ```
    bcdedit /debug on
    ```
4.  Reboot the target machine.

**On the Host Machine (in WinDbg):**

1.  Launch WinDbg.
2.  Select `File` -> `Kernel Debug` -> `NET`.
3.  Specify the same `Port` and `Key` (encryption key) as configured on the target machine.
4.  Click `OK`.

### 3. USB Debugging

This method is convenient for debugging virtual machines or physical devices with USB 3.0 support.

**On the Target Machine:**

1.  Open Command Prompt as an administrator.
2.  Execute the following command:
    ```
    bcdedit /debug on
    bcdedit /dbgsettings usb targetname:MyDebugTarget
    ```
    *   `MyDebugTarget`: An arbitrary name for the target machine.
3.  Reboot the target machine.
4.  Connect the target and host machines with a special USB debugging cable (often a type A-A or A-B cable with a "bridge" function).

**On the Host Machine (in WinDbg):**

1.  Launch WinDbg.
2.  Select `File` -> `Kernel Debug` -> `USB`.
3.  Specify the `Target Name` (the same as on the target machine).
4.  Click `OK`.

### 4. Local Kernel Debugging

This mode allows you to debug the kernel of the current machine. It is less intrusive but has limitations, such as not being able to debug very early boot stages or perform operations that might crash the system (e.g., stopping the kernel).

**On the Host Machine (in WinDbg):**

1.  Launch WinDbg as an administrator.
2.  Select `File` -> `Kernel Debug` -> `Local`.
3.  Click `OK`.

**Important Notes:**

*   **Symbols:** For successful kernel debugging, it is crucial to set up the correct symbol path. Microsoft provides public symbols for its operating systems. You can set the symbol path in WinDbg: `sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols`.
*   **Drivers:** Ensure that all necessary drivers for your chosen debugging method are installed on both machines.
*   **Security:** Kernel debugging provides full control over the system. Use it with caution and only on trusted machines. 