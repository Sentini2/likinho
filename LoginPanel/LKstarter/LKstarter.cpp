#include <windows.h>
#include <string>
#include <vector>
#include <shellapi.h>
#include <fstream>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

#define IDR_LOADER_EXE      101

#define IDR_IMG_FIVEM       201
#define IDR_IMG_FUNDO       202
#define IDR_IMG_FUNDO2      203
#define IDR_IMG_LOGO        204

bool ExtractResource(int resId, const std::wstring& path) {
    HRSRC hRes = FindResourceW(NULL, MAKEINTRESOURCEW(resId), (LPCWSTR)RT_RCDATA);
    if (!hRes) return false;

    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return false;

    DWORD dataSize = SizeofResource(NULL, hRes);
    void* data = LockResource(hData);

    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    file.write((char*)data, dataSize);
    file.close();
    return true;
}

void SelfDelete() {
    TCHAR szExePath[MAX_PATH];
    GetModuleFileName(NULL, szExePath, MAX_PATH);

    TCHAR szCmd[MAX_PATH * 2];
    // ping is a simple way to wait a second before deleting
    wsprintf(szCmd, TEXT("/c ping 127.0.0.1 -n 2 > nul & del \"%s\""), szExePath);

    ShellExecute(NULL, TEXT("open"), TEXT("cmd.exe"), szCmd, NULL, SW_HIDE);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    // 1. Create directory for srcimg if needed
    CreateDirectoryW(L"srcimg", NULL);

    // 2. Extract Embedded Files
    bool s1 = ExtractResource(IDR_LOADER_EXE, L"LoaderLK.exe");
    
    // Extract Assets to srcimg folder
    ExtractResource(IDR_IMG_FIVEM, L"srcimg\\fivem.lk");
    ExtractResource(IDR_IMG_FUNDO, L"srcimg\\fundo.lk");
    ExtractResource(IDR_IMG_FUNDO2, L"srcimg\\fundo2.lk");
    ExtractResource(IDR_IMG_LOGO, L"srcimg\\logo.lk");

    if (s1) {
        // 3. Launch LoaderLK.exe
        ShellExecuteW(NULL, L"open", L"LoaderLK.exe", NULL, NULL, SW_SHOW);
    } else {
        MessageBoxA(NULL, "Failed to initialize loader components.", "LKstarter Error", MB_OK | MB_ICONERROR);
    }

    // 4. Self delete and exit
    SelfDelete();
    return 0;
}
