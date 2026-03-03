#include <windows.h>
#include <string>
#include "resource.h"

// Extract embedded DLL to disk
bool ExtractDLL(int resourceId, const std::string& outputPath) {
    HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(resourceId), RT_RCDATA);
    if (!hResource) return false;

    HGLOBAL hLoadedResource = LoadResource(NULL, hResource);
    if (!hLoadedResource) return false;

    LPVOID pResourceData = LockResource(hLoadedResource);
    if (!pResourceData) return false;

    DWORD dwResourceSize = SizeofResource(NULL, hResource);
    if (dwResourceSize == 0) return false;

    HANDLE hFile = CreateFileA(outputPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD dwBytesWritten;
    bool success = WriteFile(hFile, pResourceData, dwResourceSize, &dwBytesWritten, NULL);
    CloseHandle(hFile);

    return success && (dwBytesWritten == dwResourceSize);
}

// Extract all embedded DLLs on startup
void ExtractEmbeddedDLLs() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string exeDir = std::string(exePath);
    exeDir = exeDir.substr(0, exeDir.find_last_of("\\\\/"));

    // Extract DLLs to the same directory as the EXE
    ExtractDLL(IDR_D3DX9_43_DLL, exeDir + "\\d3dx9_43.dll");
    ExtractDLL(IDR_D3DX10_43_DLL, exeDir + "\\d3dx10_43.dll");
    ExtractDLL(IDR_D3DX11_43_DLL, exeDir + "\\d3dx11_43.dll");
    ExtractDLL(IDR_D3DCOMPILER_43_DLL, exeDir + "\\D3DCompiler_43.dll");
}
