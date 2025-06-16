#include <iostream>
#include <string>
#include <vector>

// For Windows-specific types like ULONG_PTR, ULONG, BOOL, PVOID, SIZE_T, TRUE, malloc, free, memset, strcpy_s
#include <Windows.h>
#include <cstdlib>
#include <cstring>

// Define a hypothetical custom application data block structure
// This structure would typically be undocumented for structscan to be useful
// Making it more C-style/POD-compatible for easier structscan interpretation
typedef struct _APP_DATA_BLOCK {
    ULONG_PTR UniqueId;
    CHAR AppName[64];
    ULONG Version;
    BOOL IsActive;
    PVOID DataBuffer;
    SIZE_T DataBufferSize;
    // Replace std::vector with fixed-size arrays of characters for simplicity
    CHAR RecentFiles[3][64]; // Max 3 file names, each up to 63 chars + null terminator
    ULONG NumRecentFiles; // To track how many are valid
} APP_DATA_BLOCK, *PAPP_DATA_BLOCK;

// A global instance of our custom data block
APP_DATA_BLOCK g_AppData; // No {0} initialization here for POD struct

void InitializeAppData() {
    g_AppData.UniqueId = 0x123456789ABCDEF0;
    strcpy_s(g_AppData.AppName, sizeof(g_AppData.AppName), "MyCustomApp"); // strcpy_s takes 3 args
    g_AppData.Version = 100;
    g_AppData.IsActive = TRUE; // TRUE is defined in Windows.h
    
    // Allocate a small buffer for demonstration
    g_AppData.DataBufferSize = 256;
    g_AppData.DataBuffer = malloc(g_AppData.DataBufferSize);
    if (g_AppData.DataBuffer) {
        memset(g_AppData.DataBuffer, 0xAA, g_AppData.DataBufferSize); // memset takes 3 args
    }

    // Populate recent files
    strcpy_s(g_AppData.RecentFiles[0], sizeof(g_AppData.RecentFiles[0]), "file1.txt");
    strcpy_s(g_AppData.RecentFiles[1], sizeof(g_AppData.RecentFiles[1]), "image.png");
    strcpy_s(g_AppData.RecentFiles[2], sizeof(g_AppData.RecentFiles[2]), "report.pdf");
    g_AppData.NumRecentFiles = 3;

    std::cout << "MyCustomApp: Application data initialized." << std::endl;
}

void CleanupAppData() {
    if (g_AppData.DataBuffer) {
        free(g_AppData.DataBuffer);
        g_AppData.DataBuffer = nullptr;
    }
    // No need to clear std::vector if removed
    g_AppData.NumRecentFiles = 0; // Reset count
    std::cout << "MyCustomApp: Application data cleaned up." << std::endl;
}

int main() {
    InitializeAppData();

    std::cout << "MyCustomApp: Running. Press Enter to exit." << std::endl;
    std::cin.get(); // Keep the app running

    CleanupAppData();
    return 0;
} 