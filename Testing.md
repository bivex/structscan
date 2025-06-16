.load windbgmcpExt.dll
!load structscan.dll

.sympath+ C:\Users\Admin\Desktop\Dev\structscan\MyCustomApp_Example\build\Debug
.reload /f MyCustomApp.exe
x MyCustomApp!g_AppData
!structscan MyCustomApp!g_AppData