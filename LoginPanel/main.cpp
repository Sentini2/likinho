#pragma execution_character_set("utf-8")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "strmiids.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "imm32.lib")

#include <algorithm>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <mutex>
#include <atomic>
#include <fstream>
#include <iostream>
#include <sstream>
#include <random>
#include <map>
#include <locale.h>

#include <windows.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <winhttp.h>
#include <gdiplus.h>
#include <d3d11.h>
#include <dxgi.h>
#include <mmsystem.h>
#include <mciapi.h>
#include <dshow.h>
#include <commdlg.h>
#include <shlobj.h>
#include <winternl.h>
#include <urlmon.h>
#include <tlhelp32.h>
#include <intrin.h>

using namespace Gdiplus;

// ============================================================
// PEB PROCESS NAME SPOOFING — oculta do Gerenciador de Tarefas
// ============================================================
void SpoofProcessName() {
    typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE, UINT, PVOID, ULONG, PULONG);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;
    auto NtQIP = (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQIP) return;

    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen = 0;
    if (NtQIP(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &retLen) != 0) return;

    PEB* pPeb = pbi.PebBaseAddress;
    if (!pPeb) return;
    RTL_USER_PROCESS_PARAMETERS* pParams = pPeb->ProcessParameters;
    if (!pParams) return;

    // Nome falso que aparece no Gerenciador de Tarefas
    static wchar_t fakeName[] = L"C:\\Windows\\System32\\RuntimeBroker.exe";
    UNICODE_STRING fakeStr;
    fakeStr.Length        = (USHORT)(wcslen(fakeName) * sizeof(wchar_t));
    fakeStr.MaximumLength = fakeStr.Length + sizeof(wchar_t);
    fakeStr.Buffer        = fakeName;

    DWORD oldProt;
    // Patch ImagePathName
    VirtualProtect(&pParams->ImagePathName, sizeof(UNICODE_STRING), PAGE_READWRITE, &oldProt);
    pParams->ImagePathName = fakeStr;
    VirtualProtect(&pParams->ImagePathName, sizeof(UNICODE_STRING), oldProt, &oldProt);
    // Patch CommandLine
    VirtualProtect(&pParams->CommandLine, sizeof(UNICODE_STRING), PAGE_READWRITE, &oldProt);
    pParams->CommandLine = fakeStr;
    VirtualProtect(&pParams->CommandLine, sizeof(UNICODE_STRING), oldProt, &oldProt);
}

std::string sessionToken = "";

// Auto-Update Globals
#include "Version.h"
const std::string CURRENT_VERSION = LOADER_VERSION;
bool g_isAdmin = false;
bool g_UpdateAvailable = false;
char g_UpdateStatus[256] = "";

// ImGui Headers
#include "Executor/imgui/imgui.h"
#include "Executor/imgui/imgui_impl_dx11.h"
#include "Executor/imgui/imgui_impl_win32.h"

// Unified Global State
static char g_statusMsg[512] = "Ready to inject";
static ImVec4 g_statusColor = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
static bool g_injectComplete = false;
static bool g_blockInject = false;
static bool g_isInjecting = false;
static bool g_showInjectView = false;
static bool g_isLoggedIn = false;
static bool g_isLoading = false;
static char g_sessionToken[128] = "";
static std::mutex g_statusMutex;
static std::wstring g_InjectionDir = L"";

#ifndef API_HOST
#define API_HOST L"sentini555.onrender.com" // Render URL
#define API_PORT 443
#define API_SECURE WINHTTP_FLAG_SECURE // HTTPS
#endif

namespace Protection {
    // Forward declare the global session token from main
    extern std::string sessionToken;

    // Random Name Generator for Update Polymorphism
    std::string GenerateRandomName() {
        const std::vector<std::string> names = {
            "SystemHelper.exe", "NvidiaUpdate.exe", "SteamService.exe", "RuntimeBroker.exe",
            "Escada.exe", "Rato.exe", "Mosca.exe", "Abacaxi.exe", "Teclado.exe", "Monitor.exe",
            "ChromeUpdater.exe", "DiscordRichPresence.exe", "SpotifyHelper.exe"
        };
        std::srand(std::time(0));
        return names[std::rand() % names.size()];
    }

    // Seamless Update Function
    void PerformSeamlessUpdate(const std::string& url) {
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        std::wstring updatePath = std::wstring(tempPath) + L"update.tmp";

        // Download silently
        HRESULT hr = URLDownloadToFileW(NULL, std::wstring(url.begin(), url.end()).c_str(), updatePath.c_str(), 0, NULL);
        if (FAILED(hr)) {
             MessageBoxA(NULL, "Failed to download update automatically. Opening browser...", "Update Error", MB_OK | MB_ICONERROR);
             ShellExecuteA(NULL, "open", url.c_str(), NULL, NULL, SW_SHOWNORMAL);
             ExitProcess(0);
             return;
        }

        // Generate Random Name
        std::string newName = GenerateRandomName();
        
        // Create batch script
        std::wstring batPath = std::wstring(tempPath) + L"update.bat";
        std::ofstream bat(batPath);
        
        wchar_t selfPath[MAX_PATH];
        GetModuleFileNameW(NULL, selfPath, MAX_PATH);

        auto w2s = [](const std::wstring& w) -> std::string {
            if (w.empty()) return "";
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, &w[0], (int)w.size(), NULL, 0, NULL, NULL);
            std::string strTo(size_needed, 0);
            WideCharToMultiByte(CP_UTF8, 0, &w[0], (int)w.size(), &strTo[0], size_needed, NULL, NULL);
            return strTo;
        };
        
        // Batch Logic: 
        // 1. Wait
        // 2. Delete current EXE
        // 3. Rename downloaded TMP file to RandomName in Current Folder
        // 4. Start RandomName
        // 5. Delete self

        std::string sSelf = w2s(selfPath);
        std::string sDir = sSelf.substr(0, sSelf.find_last_of("\\/"));
        std::string sUpdateTmp = w2s(updatePath);
        
        bat << "@echo off\n";
        bat << "timeout /t 2 /nobreak > nul\n";
        bat << "del /f /q \"" << sSelf << "\"\n";
        bat << "copy /Y \"" << sUpdateTmp << "\" \"" << sDir << "\\" << newName << "\" > nul\n";
        bat << "del \"" << sUpdateTmp << "\"\n"; // Clean temp
        bat << "start \"\" \"" << sDir << "\\" << newName << "\"\n";
        bat << "del \"%~f0\" & exit\n";
        bat.close();

        // Run bat hidden
        ShellExecuteW(NULL, L"open", batPath.c_str(), NULL, NULL, SW_HIDE);
        ExitProcess(0);
    }

    inline int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
        UINT  num = 0; UINT  size = 0;
        Gdiplus::ImageCodecInfo* pImageCodecInfo = NULL;
        Gdiplus::GetImageEncodersSize(&num, &size);
        if (size == 0) return -1;
        pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(malloc(size));
        if (pImageCodecInfo == NULL) return -1;
        Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);
        for (UINT j = 0; j < num; ++j) {
            if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
                *pClsid = pImageCodecInfo[j].Clsid;
                free(pImageCodecInfo); return j;
            }
        }
        free(pImageCodecInfo); return -1;
    }

    inline std::string CaptureScreenshotToBase64() {
        int x = GetSystemMetrics(SM_XVIRTUALSCREEN);
        int y = GetSystemMetrics(SM_YVIRTUALSCREEN);
        int w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        int h = GetSystemMetrics(SM_CYVIRTUALSCREEN);

        HDC hdcScreen = GetDC(NULL);
        HDC hdcMem = CreateCompatibleDC(hdcScreen);
        HBITMAP hbm = CreateCompatibleBitmap(hdcScreen, w, h);
        SelectObject(hdcMem, hbm);
        BitBlt(hdcMem, 0, 0, w, h, hdcScreen, x, y, SRCCOPY);

        Gdiplus::Bitmap* bmp = new Gdiplus::Bitmap(hbm, NULL);
        CLSID clsid;
        GetEncoderClsid(L"image/jpeg", &clsid);

        IStream* istream = NULL;
        CreateStreamOnHGlobal(NULL, TRUE, &istream);
        bmp->Save(istream, &clsid, NULL);

        HGLOBAL hg = NULL;
        GetHGlobalFromStream(istream, &hg);
        size_t size = GlobalSize(hg);
        void* ptr = GlobalLock(hg);
        std::string buffer((char*)ptr, size);
        GlobalUnlock(hg);
        istream->Release();

        delete bmp; DeleteObject(hbm); DeleteDC(hdcMem); ReleaseDC(NULL, hdcScreen);

        static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out; int val = 0, valb = -6;
        for (unsigned char c : buffer) {
            val = (val << 8) + c; valb += 8;
            while (valb >= 0) {
                out.push_back(b64_table[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) out.push_back(b64_table[((val << 8) >> (valb + 8)) & 0x3F]);
        while (out.size() % 4) out.push_back('=');
        return out;
    }

    // Forward declare HttpPostWithHeader which is defined later in main.cpp
    // Or we move the Protection namespace after HttpPostWithHeader.
}
#include <map>
#include <tlhelp32.h>
#pragma comment(lib, "strmiids.lib")
#pragma comment(lib, "comdlg32.lib")

// ImGui includes removed here (redundant)

// WIC Image loader
#include "stb_image_impl.h"

// FontAwesome 6
#include "Menu/src/Includes/ImGui/FontAwesome/FontAwesome.hpp"
#include "Menu/src/Includes/ImGui/FontAwesome/RawAwesome6.hpp"

// ============================================================
// FORWARD DECLARATIONS
// ============================================================
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

#include <intrin.h>

static std::string GetMachineHWID() {
    std::string hwidData = "";

    // 1. Windows MachineGuid
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        char buf[256] = {};
        DWORD sz = sizeof(buf);
        if (RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, (LPBYTE)buf, &sz) == ERROR_SUCCESS) {
            hwidData += buf;
        }
        RegCloseKey(hKey);
    }

    // 2. CPU ID
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);
    char cpuId[64];
    sprintf_s(cpuId, "%08X%08X", cpuInfo[3], cpuInfo[0]);
    hwidData += cpuId;

    // 3. Computer Name & Volume Serial
    char compName[256] = {};
    DWORD cnSz = sizeof(compName);
    GetComputerNameA(compName, &cnSz);
    DWORD volSerial = 0;
    GetVolumeInformationA("C:\\", nullptr, 0, &volSerial, nullptr, nullptr, nullptr, 0);
    char volStr[32];
    sprintf_s(volStr, "%s-%08X", compName, volSerial);
    hwidData += volStr;

    // 4. Simple hash-like combination (or use a real hashing function if available)
    // For now we'll just return the concatenated string. The server already hashes it with SHA256.
    return hwidData;
}

// ============================================================
// BASE64 DECODE
// ============================================================
static std::vector<unsigned char> Base64Decode(const std::string& encoded) {
    static const unsigned char table[256] = {
        64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
        64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63,52,53,54,55,56,57,58,59,60,61,64,64,64,0,64,64,
        64,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
        64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64
    };
    std::vector<unsigned char> out;
    out.reserve(encoded.size() * 3 / 4);
    int val = 0, bits = -8;
    for (unsigned char c : encoded) {
        if (table[c] >= 64) continue;
        val = (val << 6) + table[c];
        bits += 6;
        if (bits >= 0) { out.push_back((unsigned char)((val >> bits) & 0xFF)); bits -= 8; }
    }
    return out;
}

// ============================================================
// BASE64 ENCODE
// ============================================================
static std::string Base64Encode(const unsigned char* data, size_t len) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        unsigned val = (unsigned)data[i] << 16;
        if (i + 1 < len) val |= (unsigned)data[i + 1] << 8;
        if (i + 2 < len) val |= (unsigned)data[i + 2];
        out.push_back(table[(val >> 18) & 0x3F]);
        out.push_back(table[(val >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? table[(val >> 6) & 0x3F] : '=');
        out.push_back((i + 2 < len) ? table[val & 0x3F] : '=');
    }
    return out;
}

// ============================================================
// GET PUBLIC IP - fetches real public IP from external service
// ============================================================
static std::string FetchPublicIP() {
    HINTERNET hSession = WinHttpOpen(L"LoginPanel/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";
    HINTERNET hConnect = WinHttpConnect(hSession, L"api.ipify.org", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return ""; }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/", nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return ""; }
    BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (bResults) bResults = WinHttpReceiveResponse(hRequest, nullptr);
    std::string ip;
    if (bResults) {
        DWORD dwSize = 0;
        do {
            dwSize = 0;
            WinHttpQueryDataAvailable(hRequest, &dwSize);
            if (dwSize > 0) {
                char* buf = new char[dwSize + 1];
                DWORD dwRead = 0;
                WinHttpReadData(hRequest, buf, dwSize, &dwRead);
                buf[dwRead] = '\0';
                ip += buf;
                delete[] buf;
            }
        } while (dwSize > 0);
    }
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return ip;
}


// ============================================================
// LOAD TEXTURE FROM MEMORY (WIC) - for base64 avatar images
// ============================================================
static bool LoadTextureFromMemoryWIC(const unsigned char* data, size_t dataSize, ID3D11Device* device,
    ID3D11ShaderResourceView** outSRV, int* outWidth, int* outHeight)
{
    *outSRV = nullptr; *outWidth = 0; *outHeight = 0;
    if (!data || dataSize == 0) return false;

    IWICImagingFactory* wicFactory = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&wicFactory));
    if (FAILED(hr)) return false;

    IWICStream* stream = nullptr;
    hr = wicFactory->CreateStream(&stream);
    if (FAILED(hr)) { wicFactory->Release(); return false; }

    hr = stream->InitializeFromMemory((BYTE*)data, (DWORD)dataSize);
    if (FAILED(hr)) { stream->Release(); wicFactory->Release(); return false; }

    IWICBitmapDecoder* decoder = nullptr;
    hr = wicFactory->CreateDecoderFromStream(stream, nullptr, WICDecodeMetadataCacheOnLoad, &decoder);
    if (FAILED(hr)) { stream->Release(); wicFactory->Release(); return false; }

    IWICBitmapFrameDecode* frame = nullptr;
    hr = decoder->GetFrame(0, &frame);
    if (FAILED(hr)) { decoder->Release(); stream->Release(); wicFactory->Release(); return false; }

    IWICFormatConverter* converter = nullptr;
    hr = wicFactory->CreateFormatConverter(&converter);
    if (FAILED(hr)) { frame->Release(); decoder->Release(); stream->Release(); wicFactory->Release(); return false; }

    hr = converter->Initialize(frame, GUID_WICPixelFormat32bppRGBA, WICBitmapDitherTypeNone, nullptr, 0.0, WICBitmapPaletteTypeCustom);
    if (FAILED(hr)) { converter->Release(); frame->Release(); decoder->Release(); stream->Release(); wicFactory->Release(); return false; }

    UINT width, height;
    converter->GetSize(&width, &height);
    UINT stride = width * 4;
    UINT bufferSize = stride * height;
    BYTE* buffer = new BYTE[bufferSize];
    hr = converter->CopyPixels(nullptr, stride, bufferSize, buffer);

    if (SUCCEEDED(hr)) {
        D3D11_TEXTURE2D_DESC desc = {};
        desc.Width = width; desc.Height = height; desc.MipLevels = 1; desc.ArraySize = 1;
        desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM; desc.SampleDesc.Count = 1;
        desc.Usage = D3D11_USAGE_DEFAULT; desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        D3D11_SUBRESOURCE_DATA sub = {}; sub.pSysMem = buffer; sub.SysMemPitch = stride;
        ID3D11Texture2D* texture = nullptr;
        hr = device->CreateTexture2D(&desc, &sub, &texture);
        if (SUCCEEDED(hr)) {
            D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
            srvDesc.Format = desc.Format; srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D; srvDesc.Texture2D.MipLevels = 1;
            device->CreateShaderResourceView(texture, &srvDesc, outSRV);
            texture->Release();
            *outWidth = (int)width; *outHeight = (int)height;
        }
    }
    delete[] buffer;
    converter->Release(); frame->Release(); decoder->Release(); stream->Release(); wicFactory->Release();
    return *outSRV != nullptr;
}

// ============================================================
// GLOBALS
// ============================================================
static ID3D11Device*            g_pd3dDevice = nullptr;
static ID3D11DeviceContext*     g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*          g_pSwapChain = nullptr;
static ID3D11RenderTargetView*  g_mainRenderTargetView = nullptr;

// API configuration - defined at top of file
// (Removed duplicate commented-out block)

// Defines for resources
#define IDR_MENU_LOADER    101
#define IDR_D3D10_DLL      102
#define IDR_D3DCOMPILER    103
#define IDR_D3DX9          104
#define IDR_D3DX10         105
#define IDR_D3DX11         106
#define IDR_IMG_FIVEM   201
#define IDR_IMG_FUNDO   202
#define IDR_IMG_FUNDO2  203
#define IDR_IMG_LOGO    204
#define IDR_AUD_INJECT  301
#define IDR_VCRUNTIME   107
#define IDR_MSVCP       108
#define IDR_VCR_1       109
#define IDR_MSV_1       110
#define IDR_AUD_MUSIC1  302
#define IDR_AUD_MUSIC2  303
#define IDR_AUD_MUSIC3  304
#define IDR_AUD_MUSIC4  305

// Helper function to extract resource to file
bool ExtractResource(int resId, const std::wstring& path) {
    // Check if file already exists to avoid unnecessary writes
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return true;

    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(resId), RT_RCDATA);
    if (!hRes) return false;
    
    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return false;
    
    DWORD dataSize = SizeofResource(NULL, hRes);
    void* data = LockResource(hData);
    if (!data) return false;

    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD written = 0;
    BOOL result = WriteFile(hFile, data, dataSize, &written, NULL);
    CloseHandle(hFile);

    return (result && written == dataSize);
}

// Global asset directory
static std::wstring g_AssetDir = L"";

// Helper to extract all assets to temp folder
// Helper to extract all assets to temp folder
void ExtractAssets() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    g_AssetDir = std::wstring(tempPath) + L"LoaderLK_Assets\\";
    CreateDirectoryW(g_AssetDir.c_str(), NULL);
    CreateDirectoryW((g_AssetDir + L"srcimg\\").c_str(), NULL);
    CreateDirectoryW((g_AssetDir + L"srcimg\\music\\").c_str(), NULL);

    // Extract Images
    ExtractResource(IDR_IMG_FIVEM, g_AssetDir + L"srcimg\\fivem.lk");
    ExtractResource(IDR_IMG_FUNDO, g_AssetDir + L"srcimg\\fundo.lk");
    ExtractResource(IDR_IMG_FUNDO2, g_AssetDir + L"srcimg\\fundo2.lk");
    ExtractResource(IDR_IMG_LOGO, g_AssetDir + L"srcimg\\logo.lk");

    // Extract Audio
    ExtractResource(IDR_AUD_INJECT, g_AssetDir + L"srcimg\\inject.lk");
    ExtractResource(IDR_AUD_MUSIC1, g_AssetDir + L"srcimg\\music\\track1.lk");
    ExtractResource(IDR_AUD_MUSIC2, g_AssetDir + L"srcimg\\music\\track2.lk");
    ExtractResource(IDR_AUD_MUSIC3, g_AssetDir + L"srcimg\\music\\track3.lk");
    ExtractResource(IDR_AUD_MUSIC4, g_AssetDir + L"srcimg\\music\\track4.lk");
}

// Helper to get full path for asset
// Helper for wide strings - Checks local srcimg first
std::wstring GetAssetPathW(const std::wstring& relPath) {
    // 1. Try local srcimg folder first (User requirement: "apenas o srcimg")
    if (GetFileAttributesW(relPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        return relPath;
    }
    // 2. Fallback to extracted assets in %TEMP%
    if (g_AssetDir.empty()) return relPath;
    return g_AssetDir + relPath;
}

#include "MemoryMap.hpp"

// Helper to find process ID by name
DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(pe32);
        if (Process32FirstW(snapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &pe32));
        }
        CloseHandle(snapshot);
    }
    return pid;
}

// Helper to get resource buffer
std::vector<unsigned char> GetResourceBuffer(int resId) {
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(resId), RT_RCDATA);
    if (!hRes) return {};
    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return {};
    DWORD dataSize = SizeofResource(NULL, hRes);
    void* data = LockResource(hData);
    if (!data) return {};
    return std::vector<unsigned char>((unsigned char*)data, (unsigned char*)data + dataSize);
}

// Helper to inject LoadLibraryW call into target process
bool InjectLoadLibW(HANDLE hProc, const std::wstring& path) {
    if (path.empty()) return false;
    size_t len = (path.size() + 1) * sizeof(wchar_t);
    void* pMem = VirtualAllocEx(hProc, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMem) return false;
    
    WriteProcessMemory(hProc, pMem, path.c_str(), len, nullptr);
    
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoadLib = GetProcAddress(hK32, "LoadLibraryW");
    
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)pLoadLib, pMem, 0, nullptr);
    if (hThread) {
        // Wait for the remote thread to finish, with a 15s timeout for slow systems
        DWORD waitRes = WaitForSingleObject(hThread, 15000); 
        DWORD exitCode = 0;
        if (waitRes == WAIT_OBJECT_0) {
            GetExitCodeThread(hThread, &exitCode);
        }
        CloseHandle(hThread);
        VirtualFreeEx(hProc, pMem, 0, MEM_RELEASE);
        return (exitCode != 0); // LoadLibrary returns HMODULE on success
    }
    VirtualFreeEx(hProc, pMem, 0, MEM_RELEASE);
    return false;
}

void CreateInjectionDir() {
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned int> dist(1000, 9999);
    
    g_InjectionDir = std::wstring(tempPath) + L"LK_" + std::to_wstring(dist(gen)) + L"\\";
    CreateDirectoryW(g_InjectionDir.c_str(), NULL);
    SetFileAttributesW(g_InjectionDir.c_str(), FILE_ATTRIBUTE_HIDDEN);
}

void CleanupInjectionDir() {
    if (g_InjectionDir.empty()) return;
    
    // Simple recursive delete via shell or manual find first
    std::wstring searchPath = g_InjectionDir + L"*";
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                std::wstring file = g_InjectionDir + fd.cFileName;
                DeleteFileW(file.c_str());
            }
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);
    }
    RemoveDirectoryW(g_InjectionDir.c_str());
}

// Inject MenuLoader and dependencies from temp folder
void ExtractAndRunLoader(bool hasMenuKey) {
    if (g_InjectionDir.empty()) CreateInjectionDir();

    // 1. Auth token
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned int> dist(1000, 9999);
    
    sessionToken = std::to_string(dist(gen));
    char tempPathA[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPathA);
    std::string authPath = std::string(tempPathA) + "lk_auth.dat";
    std::ofstream authFile(authPath, std::ios::binary);
    if (authFile.is_open()) {
        std::string status = (hasMenuKey ? "active" : "inactive");
        authFile.write(status.c_str(), status.length());
        authFile.close();
    }

    // 2. Extract All necessary files
    strcpy_s(g_statusMsg, "Extracting components...");
    ExtractResource(IDR_D3D10_DLL, g_InjectionDir + L"LK_Executor.dll");
    ExtractResource(IDR_D3DCOMPILER, g_InjectionDir + L"D3DCompiler_43.dll");
    ExtractResource(IDR_D3DX9, g_InjectionDir + L"d3dx9_43.dll");
    ExtractResource(IDR_D3DX10, g_InjectionDir + L"d3dx10_43.dll");
    ExtractResource(IDR_D3DX11, g_InjectionDir + L"d3dx11_43.dll");
    ExtractResource(IDR_VCRUNTIME, g_InjectionDir + L"vcruntime140.dll");
    ExtractResource(IDR_MSVCP, g_InjectionDir + L"msvcp140.dll");
    ExtractResource(IDR_VCR_1, g_InjectionDir + L"vcruntime140_1.dll");
    ExtractResource(IDR_MSV_1, g_InjectionDir + L"msvcp140_1.dll");
    ExtractResource(IDR_MENU_LOADER, g_InjectionDir + L"MenuLoader.dll");

    // 3. Open Explorer as dummy host
    strcpy_s(g_statusMsg, "Searching for host process...");
    DWORD targetPid = GetProcessIdByName(L"explorer.exe");
    if (targetPid == 0) {
        strcpy_s(g_statusMsg, "Error: Explorer not found.");
        return;
    }
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProcess) {
        strcpy_s(g_statusMsg, "Error: Failed to open host.");
        return;
    }

    // 4. Inject ONLY MenuLoader into host (explorer.exe)
    // Dependencies and Executor will be injected by MenuLoader into FiveM.
    strcpy_s(g_statusMsg, "Injecting menu...");
    g_isInjecting = true;
    
    if (!InjectLoadLibW(hProcess, g_InjectionDir + L"MenuLoader.dll")) {
        strcpy_s(g_statusMsg, "Error: Menu injection failed.");
        g_statusColor = ImVec4(1.0f, 0.3f, 0.3f, 1.0f);
        g_isInjecting = false;
        CloseHandle(hProcess);
        return;
    }

    strcpy_s(g_statusMsg, "Inject successful!");
    g_statusColor = ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
    g_injectComplete = true;
    g_isInjecting = false;
    
    CloseHandle(hProcess);
}

static UINT                     g_ResizeWidth = 0, g_ResizeHeight = 0;
static HWND                     g_hWnd = nullptr;

// Background texture
static ID3D11ShaderResourceView* g_pBackgroundSRV = nullptr;
static int g_bgWidth = 0, g_bgHeight = 0;

// Logo texture
static ID3D11ShaderResourceView* g_pLogoSRV = nullptr;
static int g_logoWidth = 0, g_logoHeight = 0;

// Login state
static bool g_showLogin = true;    // true = login, false = register
static char g_username[128] = "";
static char g_password[128] = "";
static char g_regUsername[128] = "";
static char g_regPassword[128] = "";
static char g_regToken[256] = "";
static std::string g_publicIP;
static char g_vpnWarning[256] = "";
static char g_statusLabel[128] = "Loading...";
static ImU32 g_statusCardColor = IM_COL32(255, 255, 255, 255);
static bool g_rememberUsername = false;
// Security popup variables removed
static float g_injectErrorTime = 0.0f;
static bool g_crackedBan = false; // Cracked ban state

// Animation
static float g_animTime = 0.0f;

// Title bar dragging
static bool g_isDragging = false;
static POINT g_dragStart = {};

// Menu state (FIFA style)
static int g_menuTab = 0; // 0=Play, 1=Redeem, 2=Chat, 3=Settings, 4=Update, 5=Create Key

// Inject state
static float g_injectProgress = 0.0f; // 0.0 to 1.0
static bool g_audioPlaying = false;
static bool g_audioLoaded = false;
static wchar_t g_audioPath[MAX_PATH] = {};

// Inject image
static ID3D11ShaderResourceView* g_pInjectSRV = nullptr;
static int g_injectImgW = 0, g_injectImgH = 0;

// FiveM image
static ID3D11ShaderResourceView* g_pFivemSRV = nullptr;
static int g_fivemW = 0, g_fivemH = 0;

// Fonts
static ImFont* g_fontMain = nullptr;
static ImFont* g_fontIcons = nullptr;
static ImFont* g_fontBig = nullptr;
static ImFont* g_fontIconsBig = nullptr;

// Smooth tab transition
static float g_tabAnim = 1.0f;

// Theme system
static int g_themeIndex = 0; // 0=LiKinho(orange), 1=Nippy(purple)
static bool g_showVersionDropdown = false; // Controle do dropdown de versão
static int g_versionIndex = 0; // 0=GTA, 1=DragonQuest
static float g_accentColor[3] = {1.0f, 0.55f, 0.0f};
static ID3D11ShaderResourceView* g_pBg2SRV = nullptr;
static int g_bg2Width = 0, g_bg2Height = 0;
static ID3D11ShaderResourceView* g_pDQBgSRV = nullptr; // Background DragonQuest
static int g_dqBgWidth = 0, g_dqBgHeight = 0;

// Profile
static bool g_showProfilePopup = false;
static ID3D11ShaderResourceView* g_pProfileSRV = nullptr;
static int g_profileW = 0, g_profileH = 0;
static wchar_t g_profilePicPath[MAX_PATH] = {};

// Settings
static bool g_bubblesEnabled = true;
static bool g_musicAutoPlay = true;
static bool g_loadDQMusic = false; // Flag para carregar músicas DragonQuest

// Chat system
struct ChatMsg {
    std::string username;
    std::string text;
    std::string role; // "user" or "admin"
    std::string avatar; // base64 data URI
};
static char g_chatInput[512] = {};
static std::vector<ChatMsg> g_chatMessages;
static std::mutex g_chatMutex;
static std::map<std::string, ID3D11ShaderResourceView*> g_avatarCache; // username -> texture
static std::map<std::string, std::string> g_avatarHashCache; // username -> avatar hash (to detect changes)
static float g_chatScrollY = 0.0f;
static bool g_chatScrollToBottom = true;
static float g_lastChatPoll = 0.0f;
static bool g_chatPolling = false;
static bool g_chatLocked = false;
static float g_lastChatStatusPoll = 0.0f;

// Ticket system
static bool g_showTicketCreate = false;
static char g_ticketSubject[128] = {};
static char g_ticketMessage[512] = {};
static bool g_ticketSending = false;
static std::string g_ticketStatus; // feedback msg
static float g_ticketStatusTime = 0.0f;
static std::string g_currentTicketId = ""; // ID do ticket atual

// Ticket messages structure
struct TicketMsg {
    std::string username;
    std::string text;
    std::string role; // "user" or "admin"
    std::string timestamp;
};
static std::vector<TicketMsg> g_ticketChatMessages; // Mensagens do chat do ticket

static float g_ticketScrollY = 0.0f;
static bool g_ticketScrollToBottom = true;
static float g_lastTicketPoll = 0.0f;

// Ticket list system
struct TicketListItem {
    int id;
    std::string subject;
    std::string status;
    std::string created_at;
    std::string last_message_text;
    std::string last_message_role;
    int message_count;
};
static std::vector<TicketListItem> g_ticketList;
static bool g_ticketListPolling = false;
static bool g_ticketListLoaded = false;
static float g_lastTicketListPoll = 0.0f;
static int g_ticketViewMode = 0; // 0 = list, 1 = chat
static char g_newTicketInput[512] = {};

// Menu Keys & Redeem
static std::string g_menuKeyStatus = "none";
static int g_menuKeyDays = 0;
static bool g_menuKeyLifetime = false; // Lifetime menu key status
static bool g_isLifetime = false;       // Lifetime main key status
static char g_redeemInput[128] = "";
static std::string g_redeemStatus = "";
static float g_redeemStatusTime = 0.0f;
static bool g_redeemLoading = false;
static float g_redeemAnim = 0.0f;
static bool g_redeemSuccess = false;

// Lifetime Key Creation
static char g_createLifetimeInput[128] = "";
static std::string g_createLifetimeStatus = "";
static float g_createLifetimeStatusTime = 0.0f;
static bool g_createLifetimeLoading = false;
static bool g_createLifetimeSuccess = false;

// ── Confetti particles (redeem success) ───────────────────────────────────
struct ConfettiParticle {
    float x, y, vx, vy;
    float r; // radius
    float rot, rotSpd;
    ImU32 col;
    float life; // 0..1
};
static std::vector<ConfettiParticle> g_confetti;
static float g_confettiTime = 0.0f;

// ── Card shake (redeem error) ─────────────────────────────────────────────
static float g_shakeAnim   = 0.0f; // >0 while shaking
static float g_shakeOffset = 0.0f; // current X offset

// ── Login card slide-in ───────────────────────────────────────────────────
static float g_cardSlideY  = 60.0f; // starts offset, lerps to 0
static float g_cardAlpha   = 0.0f;  // fades from 0..1

// ── Shimmer sweep offset (title text) ────────────────────────────────────
// driven by g_animTime, no extra state needed

// ── Input focus flash ─────────────────────────────────────────────────────
static float g_inputFocusAnim = 0.0f; // 0..1 per frame, driven by active state

// ============================================================
// ANTI-DEBUG & SECURITY MONITOR
// ============================================================
// Helper to escape JSON characters
static std::string EscapeJson(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else if (c == '\b') out += "\\b";
        else if (c == '\f') out += "\\f";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else out += c;
    }
    return out;
}

static void ReportSecurityThreat(const std::string& processName, const std::string& threatType) {
    // TERMINATE IMMEDIATELY — do not let crackers react
    // Capture screenshot and build payload BEFORE terminating
    std::string screenshot = Protection::CaptureScreenshotToBase64();
    std::string user = g_username[0] != '\0' ? g_username : "unauthenticated_user";
    std::string token = g_sessionToken[0] != '\0' ? std::string(g_sessionToken) : "";

    std::string jsonBody = "{\"username\":\"" + EscapeJson(user) +
                           "\",\"process_name\":\"" + EscapeJson(processName) +
                           "\",\"threat_type\":\"" + EscapeJson(threatType) +
                           "\",\"screenshot_base64\":\"" + screenshot + "\"}";

    // Fire-and-forget: send report asynchronously, process terminates right after
    struct ReportPayload { std::string body; std::string tok; };
    ReportPayload* payload = new ReportPayload{ jsonBody, token };

    HANDLE hThread = CreateThread(nullptr, 0, [](LPVOID param) -> DWORD {
        ReportPayload* p = (ReportPayload*)param;
        HINTERNET hSession = WinHttpOpen(L"SecurityMonitor/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (hSession) {
            HINTERNET hConnect = WinHttpConnect(hSession, API_HOST, API_PORT, 0);
            if (hConnect) {
                HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/security/report",
                    nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, API_SECURE);
                if (hRequest) {
                    std::wstring headers = L"Content-Type: application/json\r\n";
                    if (!p->tok.empty())
                        headers += L"x-auth-token: " + std::wstring(p->tok.begin(), p->tok.end()) + L"\r\n";
                    WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1L,
                        (LPVOID)p->body.c_str(), (DWORD)p->body.size(), (DWORD)p->body.size(), 0);
                    WinHttpReceiveResponse(hRequest, nullptr);
                    WinHttpCloseHandle(hRequest);
                }
                WinHttpCloseHandle(hConnect);
            }
            WinHttpCloseHandle(hSession);
        }
        delete p;
        return 0;
    }, payload, 0, nullptr);
    if (hThread) CloseHandle(hThread);

    // Give the report thread ~300ms to send before we kill the process
    Sleep(300);
    TerminateProcess(GetCurrentProcess(), 0);
}

// ============================================================
// SHARED SECURITY BLACKLISTS
// ============================================================
static const std::vector<std::string> g_badWindowTitles = {
    "process hacker", "system informer", "x64dbg", "x32dbg", "ollydbg",
    "cheat engine", "cheatengine", "wireshark", "dnspy", "fiddler",
    "httpdebugger", "http debugger", "charles proxy", "burp suite",
    "ida pro", "ida64", "ida freeware", "reclass", "api monitor",
    "megadumper", "scylla", "pestudio", "procmon", "process monitor",
    "windbg", "immunity debugger", "httptoolkit", "mitmproxy",
    "010 editor", "winhex", "ilspy", "dotpeek", "justdecompile"
};

static BOOL CALLBACK SecurityEnumWindows(HWND hWnd, LPARAM lParam) {
    char title[256];
    if (GetWindowTextA(hWnd, title, sizeof(title))) {
        std::string sTitle = title;
        std::transform(sTitle.begin(), sTitle.end(), sTitle.begin(), ::tolower);

        for (const auto& bad : g_badWindowTitles) {
            if (sTitle.find(bad) != std::string::npos) {
                if (IsWindowVisible(hWnd)) {
                    ReportSecurityThreat(title, "bad_window_title");
                    return FALSE;
                }
            }
        }
    }
    return TRUE;
}

// ============================================================
// WINEVENT HOOK — instant window open/title detection
// ============================================================
static void CALLBACK WinEventProc(HWINEVENTHOOK, DWORD event, HWND hwnd,
    LONG idObject, LONG, DWORD, DWORD) {
    // Only care about real windows (not menus/scrollbars etc.)
    if (idObject != OBJID_WINDOW) return;
    if (!hwnd) return;

    char title[256] = {};
    if (GetWindowTextA(hwnd, title, sizeof(title)) == 0) return;

    std::string sTitle = title;
    for (auto& c : sTitle) c = (char)tolower((unsigned char)c);

    for (const auto& bad : g_badWindowTitles) {
        if (sTitle.find(bad) != std::string::npos) {
            // Instant — triggered by the OS the moment window appears
            ReportSecurityThreat(title, "bad_window_winevent");
            return;
        }
    }
}

// ============================================================
// ANTI-DEBUG CHECKS
// ============================================================
static bool CheckDebuggerPresent() {
    // 1. IsDebuggerPresent (basic, but still useful)
    if (IsDebuggerPresent())
        return true;

    // 2. CheckRemoteDebuggerPresent
    BOOL remoteDbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDbg);
    if (remoteDbg)
        return true;

    // 3. NtQueryInformationProcess — DebugPort
    typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE, UINT, PVOID, ULONG, PULONG);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        auto NtQIP = (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (NtQIP) {
            DWORD_PTR debugPort = 0;
            ULONG retLen = 0;
            // ProcessDebugPort = 7
            if (NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), &retLen) == 0) {
                if (debugPort != 0)
                    return true;
            }
            // ProcessDebugFlags = 31 (returns 0 if being debugged)
            DWORD debugFlags = 0;
            if (NtQIP(GetCurrentProcess(), 31, &debugFlags, sizeof(debugFlags), &retLen) == 0) {
                if (debugFlags == 0)
                    return true;
            }
        }
    }

    // 4. Heap flags check — debugger sets HEAP_TAIL_CHECKING_ENABLED etc.
    PVOID pPeb = (PVOID)__readgsqword(0x60);
    if (pPeb) {
        PVOID heap = *(PVOID*)((BYTE*)pPeb + 0x30);
        if (heap) {
            DWORD heapFlags = *(DWORD*)((BYTE*)heap + 0x70);
            if (heapFlags & 0x70) // HEAP_TAIL_CHECKING_ENABLED | HEAP_FREE_CHECKING_ENABLED | HEAP_CHECK_HEAP_PARAMETERS
                return true;
        }
    }

    return false;
}

static void SecurityMonitor() {
    // No initial delay — start monitoring right away
    // (GDI+ init happens before this thread is spawned)

    static const std::vector<std::string> blacklistedProcesses = {
        "x64dbg.exe", "x32dbg.exe", "processhacker.exe", "hacker.exe", "proc_hacker.exe",
        "cheatengine-x86_64.exe", "cheatengine-i386.exe", "cheat engine.exe", "cheat_engine.exe",
        "wireshark.exe", "fiddler.exe", "fiddlereverywhere.exe", "httpdebugger.exe", "charles.exe",
        "ida64.exe", "idaw.exe", "ida.exe", "dnspy.exe", "dnspy-x86.exe",
        "simpleassemblyexplorer.exe", "megadumper.exe", "megadumper-x64.exe",
        "ollydbg.exe", "immunitydebugger.exe", "windbg.exe", "scylla.exe",
        "petools.exe", "lordpe.exe", "importrec.exe", "hxd.exe", "resourcerer.exe",
        "detectiteasy.exe", "die.exe", "pestudio.exe", "strings.exe",
        "processhacker", "systeminformer", "systeminformer.exe",
        "cheatengine.exe", "cheatengine-x86_64-gui.exe",
        "reclass.exe", "reclass64.exe", "reclass.net.exe",
        "ilspy.exe", "dotpeek.exe", "justdecompile.exe",
        "httptoolkit.exe", "burpsuite.exe", "burpsuite_community.exe",
        "mitmproxy.exe", "proxifier.exe",
        "api monitor.exe", "apimonitor-x64.exe", "apimonitor-x86.exe",
        "rohitab.exe", "process monitor.exe", "procmon.exe", "procmon64.exe",
        "tcpview.exe", "autoruns.exe", "autoruns64.exe",
        "winhex.exe", "010editor.exe"
    };

    while (true) {
        // === 1. Debugger detection ===
        if (CheckDebuggerPresent()) {
            ReportSecurityThreat("debugger_attached", "debugger_detected");
        }

        // === 2. Process scan ===
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    std::string pName = pe32.szExeFile;
                    std::string lowerPName = pName;
                    for (auto& c : lowerPName) c = (char)tolower((unsigned char)c);

                    for (const auto& black : blacklistedProcesses) {
                        std::string lowerBlack = black;
                        for (auto& c : lowerBlack) c = (char)tolower((unsigned char)c);
                        if (lowerPName == lowerBlack) {
                            CloseHandle(hSnapshot);
                            ReportSecurityThreat(pName, "debugging_tool_detected");
                        }
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }

        // === 3. Window title scan (all visible windows) ===
        EnumWindows(SecurityEnumWindows, 0);

        // Poll every 100ms — fast enough to feel instant
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// Accent color helpers
inline ImU32 Accent(int a) { return IM_COL32((int)(g_accentColor[0]*255), (int)(g_accentColor[1]*255), (int)(g_accentColor[2]*255), a); }
inline ImU32 AccentBright(int a) {
    int r = (int)(g_accentColor[0]*255)+40; if (r>255) r=255;
    int g = (int)(g_accentColor[1]*255)+40; if (g>255) g=255;
    int b = (int)(g_accentColor[2]*255)+40; if (b>255) b=255;
    return IM_COL32(r, g, b, a);
}

// ============================================================
// PATH HELPERS
// ============================================================
void GetExeDir(wchar_t* out, int outLen) {
    GetModuleFileNameW(nullptr, out, outLen);
    wchar_t* last = wcsrchr(out, L'\\');
    if (last) *(last + 1) = 0;
}

void BuildPathFromExe(const wchar_t* rel, wchar_t* out, int outLen) {
    wchar_t exeDir[MAX_PATH];
    GetExeDir(exeDir, MAX_PATH);
    wchar_t combined[MAX_PATH];
    wcscpy_s(combined, exeDir);
    wcscat_s(combined, rel);
    GetFullPathNameW(combined, outLen, out, nullptr);
}

// Theme / background helpers
void SaveUserSettings();  // forward decl
void ApplyTheme(int idx) {
    g_themeIndex = idx;
    if (idx == 0) { 
        // LiKinho theme
        g_accentColor[0]=1.0f; g_accentColor[1]=0.55f; g_accentColor[2]=0.0f; 
        g_versionIndex = 0; // Reset para GTA
    }
    else { 
        // Nippy theme - mostrar dropdown
        g_showVersionDropdown = true;
        if (g_versionIndex == 0) {
            // GTA version
            g_accentColor[0]=0.63f; g_accentColor[1]=0.31f; g_accentColor[2]=1.0f;
        } else {
            // DragonQuest version
            g_accentColor[0]=0.2f; g_accentColor[1]=0.8f; g_accentColor[2]=0.4f;
        }
    }
    SaveUserSettings();
}

// Forward declarations - functions defined later in this file
void MusicScanFolder();
void LoadDragonQuestMusic();

void ApplyVersion(int version) {
    g_versionIndex = version;
    if (version == 0) {
        // GTA version
        g_accentColor[0]=0.63f; g_accentColor[1]=0.31f; g_accentColor[2]=1.0f;
        g_loadDQMusic = false;
        MusicScanFolder(); // Reload regular music
    } else {
        // DragonQuest version
        g_accentColor[0]=0.2f; g_accentColor[1]=0.8f; g_accentColor[2]=0.4f;
        g_loadDQMusic = true;
        MusicScanFolder(); // This will call LoadDragonQuestMusic() via flag
    }
    SaveUserSettings();
}


ID3D11ShaderResourceView* GetCurrentBg() {
    if (g_themeIndex == 1 && g_versionIndex == 1 && g_pDQBgSRV) {
        return g_pDQBgSRV; // DragonQuest background
    }
    return (g_themeIndex == 1 && g_pBg2SRV) ? g_pBg2SRV : g_pBackgroundSRV;
}

// ============================================================
// USER SETTINGS SAVE / LOAD (per-username file in userdata/)
// ============================================================
void XOREncryptDecrypt(char* data, size_t size) {
    const char* key = "WexizeSecretKeyV2";
    size_t keyLen = strlen(key);
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key[i % keyLen];
    }
}

void GetUserSettingsPath(wchar_t* out, int outLen) {
    wchar_t dir[MAX_PATH];
    GetExeDir(dir, MAX_PATH);
    wcscat_s(dir, L"cfg"); // Renamed from userdata
    CreateDirectoryW(dir, nullptr);
    // Convert username to wide
    wchar_t wUser[128];
    MultiByteToWideChar(CP_UTF8, 0, g_username, -1, wUser, 128);
    swprintf_s(out, outLen, L"%s\\%s.cfg", dir, wUser);
}

void SaveUserSettings() {
    // Always save to both files: generic and user-specific
    wchar_t genericPath[MAX_PATH];
    GetTempPathW(MAX_PATH, genericPath);
    wcscat_s(genericPath, L"LKSettings.cfg");
    
    wchar_t userPath[MAX_PATH];
    if (g_username[0] != 0 && g_isLoggedIn) {
        GetUserSettingsPath(userPath, MAX_PATH);
    } else {
        wcscpy_s(userPath, genericPath);
    }
    
    // Build settings string
    std::string content;
    char buf[1024];

    sprintf_s(buf, "theme=%d\n", g_themeIndex); content += buf;
    sprintf_s(buf, "accentR=%.4f\n", g_accentColor[0]); content += buf;
    sprintf_s(buf, "accentG=%.4f\n", g_accentColor[1]); content += buf;
    sprintf_s(buf, "accentB=%.4f\n", g_accentColor[2]); content += buf;
    sprintf_s(buf, "bubbles=%d\n", g_bubblesEnabled ? 1 : 0); content += buf;
    sprintf_s(buf, "musicAuto=%d\n", g_musicAutoPlay ? 1 : 0); content += buf;
    sprintf_s(buf, "rememberUser=%d\n", g_rememberUsername ? 1 : 0); content += buf;

    if (g_rememberUsername && g_username[0] != 0) {
        sprintf_s(buf, "savedUser=%s\n", g_username); content += buf;
        sprintf_s(buf, "savedToken=%s\n", g_sessionToken); content += buf;
        sprintf_s(buf, "savedPass=%s\n", g_password); content += buf;
    }

    char picUtf8[MAX_PATH * 2] = {};
    WideCharToMultiByte(CP_UTF8, 0, g_profilePicPath, -1, picUtf8, sizeof(picUtf8), nullptr, nullptr);
    sprintf_s(buf, "profilePic=%s\n", picUtf8); content += buf;

    // Encrypt content
    std::vector<char> encrypted(content.begin(), content.end());
    XOREncryptDecrypt(encrypted.data(), encrypted.size());

    // Save to generic file
    FILE* f = nullptr;
    _wfopen_s(&f, genericPath, L"wb"); // wb for binary
    if (f) {
        fwrite(encrypted.data(), 1, encrypted.size(), f);
        fclose(f);
    }
    
    // Save to user-specific file if logged in
    if (g_username[0] != 0 && g_isLoggedIn && wcscmp(userPath, genericPath) != 0) {
        _wfopen_s(&f, userPath, L"wb");
        if (f) {
            fwrite(encrypted.data(), 1, encrypted.size(), f);
            fclose(f);
        }
    }
}

void LoadUserSettings() {
    // Always load from generic file first (shared settings)
    wchar_t genericPath[MAX_PATH];
    GetTempPathW(MAX_PATH, genericPath);
    wcscat_s(genericPath, L"LKSettings.cfg");
    
    wchar_t userPath[MAX_PATH];
    if (g_username[0] != 0 && g_isLoggedIn) {
        GetUserSettingsPath(userPath, MAX_PATH);
    } else {
        wcscpy_s(userPath, genericPath);
    }
    
    // Try user path first if we have a username, otherwise generic
    wchar_t loadPath[MAX_PATH];
    wcscpy_s(loadPath, userPath);

    FILE* f = nullptr;
    _wfopen_s(&f, loadPath, L"rb");
    if (!f) {
        // Fallback to generic if user file doesn't exist
        _wfopen_s(&f, genericPath, L"rb");
        if (!f) return;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0) { fclose(f); return; }

    std::vector<char> data(size);
    fread(data.data(), 1, size, f);
    fclose(f);

    // Decrypt
    XOREncryptDecrypt(data.data(), data.size());
    std::string content(data.data(), data.size());

    std::stringstream ss(content);
    std::string line;
    while (std::getline(ss, line)) {
        float fv; int iv; char sv[512];
        if (sscanf_s(line.c_str(), "theme=%d", &iv) == 1) { g_themeIndex = iv; }
        else if (sscanf_s(line.c_str(), "accentR=%f", &fv) == 1) { g_accentColor[0] = fv; }
        else if (sscanf_s(line.c_str(), "accentG=%f", &fv) == 1) { g_accentColor[1] = fv; }
        else if (sscanf_s(line.c_str(), "accentB=%f", &fv) == 1) { g_accentColor[2] = fv; }
        else if (sscanf_s(line.c_str(), "bubbles=%d", &iv) == 1) { g_bubblesEnabled = (iv != 0); }
        else if (sscanf_s(line.c_str(), "musicAuto=%d", &iv) == 1) { g_musicAutoPlay = (iv != 0); }
        else if (sscanf_s(line.c_str(), "rememberUser=%d", &iv) == 1) { g_rememberUsername = (iv != 0); }
        else if (sscanf_s(line.c_str(), "savedUser=%511[^\n]", sv, 512) == 1 && g_rememberUsername) { strcpy_s(g_username, sv); }
        else if (sscanf_s(line.c_str(), "savedToken=%511[^\n]", sv, 512) == 1 && g_rememberUsername) { strcpy_s(g_sessionToken, sv); }
        else if (sscanf_s(line.c_str(), "savedPass=%511[^\n]", sv, 512) == 1 && g_rememberUsername) { strcpy_s(g_password, sv); }
        else if (sscanf_s(line.c_str(), "profilePic=%511[^\n]", sv, 512) == 1) {
            MultiByteToWideChar(CP_UTF8, 0, sv, -1, g_profilePicPath, MAX_PATH);
        }
    }
}

// Debug log helper
static wchar_t g_logPath[MAX_PATH] = {};
void DebugLog(const wchar_t* msg) {
    if (g_logPath[0] == 0) {
        GetTempPathW(MAX_PATH, g_logPath);
        wcscat_s(g_logPath, L"LKAudio\\debug.log");
    }
    FILE* f = nullptr;
    _wfopen_s(&f, g_logPath, L"a");
    if (f) { fwprintf(f, L"%s\n", msg); fclose(f); }
}
void DebugLogMCI(const wchar_t* action, MCIERROR err) {
    wchar_t buf[512];
    if (err == 0) {
        swprintf_s(buf, L"[OK] %s", action);
    } else {
        wchar_t errMsg[256] = {};
        mciGetErrorStringW(err, errMsg, 256);
        swprintf_s(buf, L"[ERR %lu] %s -> %s", err, action, errMsg);
    }
    DebugLog(buf);
}

// Copy file to %TEMP%\LKAudio\ and return the temp path (MCI-safe, no special chars)
bool CopyToTempDir(const wchar_t* srcPath, const wchar_t* filename, wchar_t* outPath, int outLen) {
    wchar_t tempDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tempDir);
    wcscat_s(tempDir, L"LKAudio\\");
    CreateDirectoryW(tempDir, nullptr);
    wcscpy_s(outPath, outLen, tempDir);
    wcscat_s(outPath, outLen, filename);
    bool ok = CopyFileW(srcPath, outPath, FALSE) || GetFileAttributesW(outPath) != INVALID_FILE_ATTRIBUTES;
    wchar_t logBuf[512];
    swprintf_s(logBuf, L"CopyToTemp: %s -> %s = %s", srcPath, outPath, ok ? L"OK" : L"FAIL");
    DebugLog(logBuf);
    return ok;
}

// ============================================================
// DIRECTSHOW AUDIO PLAYER HELPER
// ============================================================
struct DSPlayer {
    IGraphBuilder* graph = nullptr;
    IMediaControl* control = nullptr;
    IMediaSeeking* seeking = nullptr;
    IBasicAudio* audio = nullptr;
    bool loaded = false;
    bool playing = false;

    bool Load(const wchar_t* path) {
        Release();
        HRESULT hr = CoCreateInstance(CLSID_FilterGraph, nullptr, CLSCTX_INPROC_SERVER,
            IID_IGraphBuilder, (void**)&graph);
        if (FAILED(hr) || !graph) return false;
        hr = graph->RenderFile(path, nullptr);
        if (FAILED(hr)) { Release(); return false; }
        graph->QueryInterface(IID_IMediaControl, (void**)&control);
        graph->QueryInterface(IID_IMediaSeeking, (void**)&seeking);
        graph->QueryInterface(IID_IBasicAudio, (void**)&audio);
        loaded = true;
        DebugLog(L"[DS] Loaded OK");
        return true;
    }

    void Play() {
        if (!loaded || !control) return;
        if (seeking) {
            LONGLONG pos = 0;
            seeking->SetPositions(&pos, AM_SEEKING_AbsolutePositioning, nullptr, AM_SEEKING_NoPositioning);
        }
        control->Run();
        playing = true;
    }

    void Resume() {
        if (!loaded || !control) return;
        control->Run();
        playing = true;
    }

    void Pause() {
        if (!loaded || !control) return;
        control->Pause();
        playing = false;
    }

    void Stop() {
        if (!loaded || !control) return;
        control->Stop();
        playing = false;
    }

    void SetVolume(long vol) { // vol: 0-1000
        if (!audio) return;
        // IBasicAudio volume: -10000 (silent) to 0 (full)
        long db;
        if (vol <= 0) db = -10000;
        else db = (long)(2000.0 * log10((double)vol / 1000.0));
        if (db < -10000) db = -10000;
        audio->put_Volume(db);
    }

    bool IsFinished() {
        if (!loaded || !seeking) return false;
        LONGLONG pos = 0, dur = 0;
        seeking->GetCurrentPosition(&pos);
        seeking->GetDuration(&dur);
        return (dur > 0 && pos >= dur);
    }

    void Release() {
        if (control) { control->Stop(); control->Release(); control = nullptr; }
        if (seeking) { seeking->Release(); seeking = nullptr; }
        if (audio) { audio->Release(); audio = nullptr; }
        if (graph) { graph->Release(); graph = nullptr; }
        loaded = false;
        playing = false;
    }
};

// ============================================================
// INJECT AUDIO (DirectShow)
// ============================================================
static DSPlayer g_injectPlayer;

void AudioLoad() {
    if (g_audioLoaded) return;
    std::wstring assetPath = GetAssetPathW(L"srcimg\\inject.lk");
    // DirectShow should handle the temp path fine
    if (g_injectPlayer.Load(assetPath.c_str())) {
        g_audioLoaded = true;
    }
}

void AudioPlay() {
    if (!g_audioLoaded) AudioLoad();
    if (g_audioLoaded && !g_audioPlaying) {
        g_injectPlayer.Play();
        g_audioPlaying = true;
    }
}

void AudioStop() {
    if (g_audioPlaying) {
        g_injectPlayer.Stop();
        g_audioPlaying = false;
    }
}

void AudioClose() {
    AudioStop();
    g_injectPlayer.Release();
    g_audioLoaded = false;
}

// ============================================================
// MUSIC PLAYER (DirectShow)
// ============================================================
static DSPlayer g_musicPlayer;
static std::vector<std::wstring> g_musicTempPaths;
static std::vector<std::string>  g_musicNames;
static int g_musicIndex = -1;
static bool g_musicPlaying = false;
static bool g_musicLoaded = false;
static bool g_musicMuted = false;
static int g_musicVolume = 800; // 0-1000

// ============================================================
// DRAGON QUEST MUSIC LOADER
// ============================================================
void MusicPlayIndex(int idx); // Forward declaration
void LoadDragonQuestMusic() {
    g_musicTempPaths.clear();
    g_musicNames.clear();
    
    // Carregar músicas específicas do DragonQuest (formato .lk)
    std::wstring dqMusicDir = GetAssetPathW(L"srcimg\\music\\");
    
    // Lista de músicas DragonQuest em formato .lk (incluindo tracks existentes)
    const wchar_t* dqTracks[] = {
        L"tracka.lk", L"trackb.lk", L"trackc.lk",  // DragonQuest originals
        L"track1.lk", L"track2.lk", L"track3.lk", L"track4.lk"  // Tracks existentes
    };
    const char* dqNames[] = {
        "Dragon Quest A", "Dragon Quest B", "Dragon Quest C",
        "Dragon Quest 1", "Dragon Quest 2", "Dragon Quest 3", "Dragon Quest 4"
    };
    
    int totalTracks = sizeof(dqTracks) / sizeof(dqTracks[0]);
    
    for (int i = 0; i < totalTracks; i++) {
        wchar_t srcPath[MAX_PATH];
        wcscpy_s(srcPath, dqMusicDir.c_str());
        wcscat_s(srcPath, dqTracks[i]);
        
        // Verificar se o arquivo existe
        if (GetFileAttributesW(srcPath) != INVALID_FILE_ATTRIBUTES) {
            wchar_t tempName[64];
            swprintf_s(tempName, L"dqtrack%d.lk", i);
            wchar_t tempPath[MAX_PATH];
            if (CopyToTempDir(srcPath, tempName, tempPath, MAX_PATH)) {
                g_musicTempPaths.push_back(tempPath);
                g_musicNames.push_back(dqNames[i]);
            }
        }
    }
    
    // Começar a tocar a primeira música se auto-play estiver ativo
    if (!g_musicTempPaths.empty() && g_musicAutoPlay) {
        MusicPlayIndex(0);
    }
}

void MusicScanFolder() {
    g_musicTempPaths.clear();
    g_musicNames.clear();

    // Verificar se deve carregar músicas DragonQuest
    if (g_loadDQMusic) {
        LoadDragonQuestMusic();
        g_loadDQMusic = false; // Reset flag
        return;
    }

    std::wstring musicDirStr = GetAssetPathW(L"srcimg\\music\\");
    wchar_t musicDir[MAX_PATH];
    wcscpy_s(musicDir, musicDirStr.c_str());

    wchar_t searchPath[MAX_PATH];
    wcscpy_s(searchPath, musicDir);
    wcscat_s(searchPath, L"*");

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    int fileIdx = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring name(fd.cFileName);
        if (name.size() > 4) {
            std::wstring ext = name.substr(name.size() - 3);
            for (auto& c : ext) c = towlower(c);
            if (ext == L".lk" || ext == L".mp3" || ext == L".wav") {
                wchar_t srcPath[MAX_PATH];
                wcscpy_s(srcPath, musicDir);
                wcscat_s(srcPath, fd.cFileName);

                wchar_t tempName[64];
                swprintf_s(tempName, L"track%d.lk", fileIdx++);
                wchar_t tempPath[MAX_PATH];
                if (CopyToTempDir(srcPath, tempName, tempPath, MAX_PATH)) {
                    g_musicTempPaths.push_back(tempPath);
                    std::wstring disp = name.substr(0, name.size() - 3);
                    std::string dispA;
                    dispA.reserve(disp.size());
                    for (wchar_t wc : disp) dispA += (char)(wc < 128 ? wc : '?');
                    g_musicNames.push_back(dispA);
                }
            }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
}

void MusicStop() {
    g_musicPlayer.Stop();
    g_musicLoaded = false;
    g_musicPlaying = false;
}

void MusicPlayIndex(int idx) {
    if (g_musicTempPaths.empty()) return;
    if (idx < 0) idx = (int)g_musicTempPaths.size() - 1;
    if (idx >= (int)g_musicTempPaths.size()) idx = 0;
    g_musicIndex = idx;

    g_musicPlayer.Release();
    if (!g_musicPlayer.Load(g_musicTempPaths[idx].c_str())) return;
    g_musicLoaded = true;

    g_musicPlayer.SetVolume(g_musicMuted ? 0 : g_musicVolume);
    g_musicPlayer.Play();
    g_musicPlaying = true;
}

void MusicToggle() {
    if (!g_musicLoaded || g_musicTempPaths.empty()) {
        if (!g_musicTempPaths.empty()) MusicPlayIndex(0);
        return;
    }
    if (g_musicPlaying) {
        g_musicPlayer.Pause();
        g_musicPlaying = false;
    } else {
        g_musicPlayer.Resume();
        g_musicPlaying = true;
    }
}

void MusicNext() { MusicPlayIndex(g_musicIndex + 1); }
void MusicPrev() { MusicPlayIndex(g_musicIndex - 1); }

void MusicSetVolume(int vol) {
    g_musicVolume = vol;
    if (g_musicVolume < 0) g_musicVolume = 0;
    if (g_musicVolume > 1000) g_musicVolume = 1000;
    g_musicPlayer.SetVolume(g_musicMuted ? 0 : g_musicVolume);
}

void MusicToggleMute() {
    g_musicMuted = !g_musicMuted;
    MusicSetVolume(g_musicVolume);
}

void MusicCheckAutoNext() {
    if (!g_musicLoaded || !g_musicPlaying) return;
    if (g_musicPlayer.IsFinished()) {
        MusicNext();
    }
}

void MusicCleanup() {
    g_musicPlayer.Release();
    g_musicLoaded = false;
    g_musicPlaying = false;
}

// ============================================================
// ICON BUTTON HELPER (reusable)
// ============================================================
struct IconBtn {
    static bool Draw(ImDrawList* d, const char* icon, float x, float y, float sz, ImVec2 mouse, ImU32 col, ImU32 hoverCol) {
        bool hov = (mouse.x >= x && mouse.x <= x + sz && mouse.y >= y && mouse.y <= y + sz);
        ImVec2 iSz = ImGui::CalcTextSize(icon);
        d->AddText(ImVec2(x + (sz - iSz.x) * 0.5f, y + (sz - iSz.y) * 0.5f), hov ? hoverCol : col, icon);
        return hov && ImGui::IsMouseClicked(0);
    }
};

// ============================================================
// DRAW MUSIC CONTROLS INLINE (for bottom bar integration)
// ============================================================
void DrawMusicControlsInline(ImDrawList* draw, float rx, float ry, float rw, float rh) {
    if (g_musicTempPaths.empty()) return;
    ImVec2 mp = ImGui::GetIO().MousePos;
    float btnSz = 22.0f;
    ImU32 dimCol = IM_COL32(130, 130, 140, 180);
    ImU32 hovCol = AccentBright(255);
    ImU32 accentCol = Accent(230);

    float cx = rx + 8;
    float cy = ry + (rh - btnSz) * 0.5f;

    if (g_fontIcons) ImGui::PushFont(g_fontIcons);

    // Prev
    if (IconBtn::Draw(draw, ICON_FA_BACKWARD_STEP, cx, cy, btnSz, mp, dimCol, hovCol)) MusicPrev();
    cx += btnSz + 2;

    // Play/Pause
    const char* ppIcon = g_musicPlaying ? ICON_FA_PAUSE : ICON_FA_PLAY;
    if (IconBtn::Draw(draw, ppIcon, cx, cy, btnSz, mp, accentCol, hovCol)) MusicToggle();
    cx += btnSz + 2;

    // Next
    if (IconBtn::Draw(draw, ICON_FA_FORWARD_STEP, cx, cy, btnSz, mp, dimCol, hovCol)) MusicNext();
    cx += btnSz + 8;

    // Volume icon
    const char* muteIcon = g_musicMuted ? ICON_FA_VOLUME_XMARK : (g_musicVolume < 400 ? ICON_FA_VOLUME_LOW : ICON_FA_VOLUME_HIGH);
    if (IconBtn::Draw(draw, muteIcon, cx, cy, btnSz, mp, dimCol, hovCol)) MusicToggleMute();
    cx += btnSz + 4;

    if (g_fontIcons) ImGui::PopFont();

    // Volume slider
    float sliderW = 60.0f;
    float sliderY = ry + rh * 0.5f - 2;
    draw->AddRectFilled(ImVec2(cx, sliderY), ImVec2(cx + sliderW, sliderY + 3), IM_COL32(40, 40, 48, 200), 2.0f);
    float fillW = sliderW * (g_musicVolume / 1000.0f);
    draw->AddRectFilled(ImVec2(cx, sliderY), ImVec2(cx + fillW, sliderY + 3), Accent(200), 2.0f);
    draw->AddCircleFilled(ImVec2(cx + fillW, sliderY + 1.5f), 4.0f, AccentBright(255), 10);
    bool onSlider = (mp.x >= cx - 4 && mp.x <= cx + sliderW + 4 && mp.y >= sliderY - 8 && mp.y <= sliderY + 12);
    if (onSlider && ImGui::IsMouseDown(0)) {
        float pct = (mp.x - cx) / sliderW;
        if (pct < 0) pct = 0; if (pct > 1) pct = 1;
        MusicSetVolume((int)(pct * 1000));
    }
    cx += sliderW + 10;

    // Song name (clipped)
    if (g_fontMain) ImGui::PushFont(g_fontMain);
    const char* songName = (g_musicIndex >= 0 && g_musicIndex < (int)g_musicNames.size())
        ? g_musicNames[g_musicIndex].c_str() : "";
    float maxNameW = rx + rw - cx - 8;
    if (maxNameW > 20) {
        draw->PushClipRect(ImVec2(cx, ry), ImVec2(cx + maxNameW, ry + rh), true);
        ImVec2 nSz = ImGui::CalcTextSize(songName);
        draw->AddText(ImVec2(cx, ry + (rh - nSz.y) * 0.5f), IM_COL32(180, 180, 190, 200), songName);
        draw->PopClipRect();
    }
    if (g_fontMain) ImGui::PopFont();
}

// ============================================================
// ORANGE BUBBLES
// ============================================================
struct Bubble {
    float x, y;
    float radius;
    float speedX, speedY;
    float alpha;
    float phase; // for pulsing
};

static std::vector<Bubble> g_bubbles;

void InitBubbles(int count, float screenW, float screenH) {
    g_bubbles.clear();
    srand((unsigned)time(nullptr));
    for (int i = 0; i < count; i++) {
        Bubble b;
        b.x = (float)(rand() % (int)screenW);
        b.y = (float)(rand() % (int)screenH);
        b.radius = 2.0f + (rand() % 12);
        b.speedX = -8.0f + (float)(rand() % 16);
        b.speedY = -10.0f - (float)(rand() % 15);
        b.alpha = 0.03f + (float)(rand() % 8) / 100.0f;
        b.phase = (float)(rand() % 628) / 100.0f;
        g_bubbles.push_back(b);
    }
}

void UpdateAndDrawBubbles(ImDrawList* drawList, float dt, float screenW, float screenH) {
    if (!g_bubblesEnabled) return;
    for (auto& b : g_bubbles) {
        b.x += b.speedX * dt;
        b.y += b.speedY * dt;

        float pulse = 0.5f + 0.5f * sinf(g_animTime * 1.5f + b.phase);
        float currentAlpha = b.alpha * (0.6f + 0.4f * pulse);

        if (b.y + b.radius < 0) { b.y = screenH + b.radius; b.x = (float)(rand() % (int)screenW); }
        if (b.x < -b.radius) b.x = screenW + b.radius;
        if (b.x > screenW + b.radius) b.x = -b.radius;

        drawList->AddCircleFilled(ImVec2(b.x, b.y), b.radius * 1.8f, Accent((int)(currentAlpha * 80)), 32);
        drawList->AddCircleFilled(ImVec2(b.x, b.y), b.radius, Accent((int)(currentAlpha * 255)), 32);
        drawList->AddCircleFilled(ImVec2(b.x - b.radius * 0.25f, b.y - b.radius * 0.25f), b.radius * 0.4f, AccentBright((int)(currentAlpha * 120)), 16);
    }
}

// ============================================================
// HTTP CLIENT (WinHTTP) - for KeyAuth API
// ============================================================
struct HttpResponse {
    int statusCode;
    std::string body;
    bool success;
};

HttpResponse HttpPost(const std::wstring& host, int port, const std::wstring& path, const std::string& jsonBody) {
    HttpResponse resp = { 0, "", false };

    HINTERNET hSession = WinHttpOpen(L"LoginPanel/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return resp;

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), (INTERNET_PORT)port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return resp; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, (port == INTERNET_DEFAULT_HTTPS_PORT ? WINHTTP_FLAG_SECURE : 0));
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return resp; }

    const wchar_t* headers = L"Content-Type: application/json\r\n";
    BOOL bResults = WinHttpSendRequest(hRequest, headers, -1L,
        (LPVOID)jsonBody.c_str(), (DWORD)jsonBody.size(), (DWORD)jsonBody.size(), 0);

    if (bResults) bResults = WinHttpReceiveResponse(hRequest, nullptr);

    if (bResults) {
        DWORD dwSize = 0;
        DWORD dwStatusCode = 0;
        DWORD dwSCSize = sizeof(dwStatusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSCSize, WINHTTP_NO_HEADER_INDEX);
        resp.statusCode = (int)dwStatusCode;

        std::string responseBody;
        do {
            dwSize = 0;
            WinHttpQueryDataAvailable(hRequest, &dwSize);
            if (dwSize > 0) {
                char* buffer = new char[dwSize + 1];
                DWORD dwDownloaded = 0;
                WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded);
                buffer[dwDownloaded] = '\0';
                responseBody += buffer;
                delete[] buffer;
            }
        } while (dwSize > 0);

        resp.body = responseBody;
        resp.success = true;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return resp;
}

HttpResponse HttpPostWithHeader(const std::wstring& host, int port, const std::wstring& path, const std::string& jsonBody, const std::wstring& extraHeader) {
    HttpResponse resp = { 0, "", false };
    HINTERNET hSession = WinHttpOpen(L"LoginPanel/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return resp;
    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), (INTERNET_PORT)port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return resp; }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, (port == INTERNET_DEFAULT_HTTPS_PORT ? WINHTTP_FLAG_SECURE : 0));
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return resp; }

    std::wstring headers = L"Content-Type: application/json\r\n" + extraHeader;
    BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), -1L,
        (LPVOID)jsonBody.c_str(), (DWORD)jsonBody.size(), (DWORD)jsonBody.size(), 0);
    if (bResults) bResults = WinHttpReceiveResponse(hRequest, nullptr);
    if (bResults) {
        DWORD dwStatusCode = 0, dwSCSize = sizeof(dwStatusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSCSize, WINHTTP_NO_HEADER_INDEX);
        resp.statusCode = (int)dwStatusCode;
        std::string responseBody;
        DWORD dwSize = 0;
        do {
            dwSize = 0;
            WinHttpQueryDataAvailable(hRequest, &dwSize);
            if (dwSize > 0) {
                char* buffer = new char[dwSize + 1];
                DWORD dwDownloaded = 0;
                WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded);
                buffer[dwDownloaded] = '\0';
                responseBody += buffer;
                delete[] buffer;
            }
        } while (dwSize > 0);
        resp.body = responseBody;
        resp.success = true;
    }
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return resp;
}

HttpResponse HttpGet(const std::wstring& host, int port, const std::wstring& path) {
    HttpResponse resp = { 0, "", false };

    HINTERNET hSession = WinHttpOpen(L"LoginPanel/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return resp;

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), (INTERNET_PORT)port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return resp; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, (port == INTERNET_DEFAULT_HTTPS_PORT ? WINHTTP_FLAG_SECURE : 0));
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return resp; }

    BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (bResults) bResults = WinHttpReceiveResponse(hRequest, nullptr);

    if (bResults) {
        DWORD dwSize = 0;
        DWORD dwStatusCode = 0;
        DWORD dwSCSize = sizeof(dwStatusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSCSize, WINHTTP_NO_HEADER_INDEX);
        resp.statusCode = (int)dwStatusCode;

        std::string responseBody;
        do {
            dwSize = 0;
            WinHttpQueryDataAvailable(hRequest, &dwSize);
            if (dwSize > 0) {
                char* buffer = new char[dwSize + 1];
                DWORD dwDownloaded = 0;
                WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded);
                buffer[dwDownloaded] = '\0';
                responseBody += buffer;
                delete[] buffer;
            }
        } while (dwSize > 0);

        resp.body = responseBody;
        resp.success = true;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return resp;
}

// Download binary data (e.g. images) - LITE VERSION helper
std::vector<unsigned char> DownloadData(const std::wstring& host, int port, const std::wstring& path) {
    std::vector<unsigned char> data;
    HINTERNET hSession = WinHttpOpen(L"LiKinhoLite/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return data;

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), (INTERNET_PORT)port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return data; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, (port == 443 ? WINHTTP_FLAG_SECURE : 0));
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return data; }

    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        if (WinHttpReceiveResponse(hRequest, nullptr)) {
            DWORD dwSize = 0;
            do {
                dwSize = 0;
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
                if (dwSize > 0) {
                    std::vector<unsigned char> chunk(dwSize);
                    DWORD dwDownloaded = 0;
                    if (WinHttpReadData(hRequest, chunk.data(), dwSize, &dwDownloaded)) {
                        data.insert(data.end(), chunk.begin(), chunk.begin() + dwDownloaded);
                    }
                }
            } while (dwSize > 0);
        }
    }
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return data;
}



HttpResponse HttpGetWithAuth(const std::wstring& host, int port, const std::wstring& path, const char* token) {
    HttpResponse resp = { 0, "", false };

    HINTERNET hSession = WinHttpOpen(L"LoginPanel/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return resp;

    HINTERNET hConnect = WinHttpConnect(hSession, host.c_str(), (INTERNET_PORT)port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return resp; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, (port == INTERNET_DEFAULT_HTTPS_PORT ? WINHTTP_FLAG_SECURE : 0));
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return resp; }

    // Add auth header
    std::wstring authHeader = L"x-auth-token: ";
    authHeader += std::wstring(token, token + strlen(token));
    std::wstring headers = authHeader + L"\r\n";

    BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), -1L,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (bResults) bResults = WinHttpReceiveResponse(hRequest, nullptr);

    if (bResults) {
        DWORD dwSize = 0;
        DWORD dwStatusCode = 0;
        DWORD dwSCSize = sizeof(dwStatusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSCSize, WINHTTP_NO_HEADER_INDEX);
        resp.statusCode = (int)dwStatusCode;

        std::string responseBody;
        do {
            dwSize = 0;
            WinHttpQueryDataAvailable(hRequest, &dwSize);
            if (dwSize > 0) {
                char* buffer = new char[dwSize + 1];
                DWORD dwDownloaded = 0;
                WinHttpReadData(hRequest, buffer, dwSize, &dwDownloaded);
                buffer[dwDownloaded] = '\0';
                responseBody += buffer;
                delete[] buffer;
            }
        } while (dwSize > 0);

        resp.body = responseBody;
        resp.success = true;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return resp;
}

// Simple JSON value extractor (no external lib needed)
std::string JsonGetString(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return "";
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    if (pos >= json.size()) return "";

    if (json[pos] == '"') {
        pos++;
        size_t end = json.find('"', pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    }
    // Number or bool
    size_t end = json.find_first_of(",}", pos);
    if (end == std::string::npos) return json.substr(pos);
    return json.substr(pos, end - pos);
}

bool JsonGetBool(const std::string& json, const std::string& key) {
    std::string val = JsonGetString(json, key);
    return val == "true";
}

// Forward declarations
void CheckInjectStatus();
bool StyledButton(const char* label, ImVec2 size);
void RenderTicketChatOverlay(ImDrawList* draw, float cX, float cY, float cW, float cH);
void TicketSendMessage(const char* message);
// Auto-login removed - only remember username/password

// ============================================================
// KeyAuth API calls
// ============================================================
// Check for updates (Client Side)
void CheckForUpdates() {
    // 1. Check version API
    HttpResponse resp = HttpGet(API_HOST, API_PORT, L"/api/version");
    if (resp.success && resp.statusCode == 200) {
        std::string remoteVer = JsonGetString(resp.body, "version");
        if (!remoteVer.empty() && remoteVer != CURRENT_VERSION) {
             g_UpdateAvailable = true;
             std::string url = JsonGetString(resp.body, "url");
             if (url.empty()) return;

             // Use the seamless update function (PolyMorphic)
             Protection::PerformSeamlessUpdate(url);
        }
    }
}

void DoLogin(const char* user, const char* pass) {
    g_isLoading = true;
    std::string hwid = GetMachineHWID();
    std::string pip = g_publicIP;
    // Send CURRENT_VERSION in login body
    std::string jsonBody = "{\"username\":\"" + std::string(user) + "\",\"password\":\"" + std::string(pass) + "\",\"hwid\":\"" + hwid + "\",\"client_ip\":\"" + pip + "\",\"version\":\"" + CURRENT_VERSION + "\"}";

    std::thread([jsonBody]() {
        HttpResponse resp = HttpPost(API_HOST, API_PORT, L"/api/login", jsonBody);

        std::lock_guard<std::mutex> lock(g_statusMutex);
        g_isLoading = false;

        if (!resp.success) {
            strcpy_s(g_statusMsg, "Connection error. Is the server running?");
            g_statusColor = ImVec4(1.0f, 0.3f, 0.3f, 1.0f);
            return;
        }

        // Check for Update REJECTION from Server
        std::string errCode = JsonGetString(resp.body, "code");
        if (errCode == "UPDATE_REQUIRED") {
            std::string url = JsonGetString(resp.body, "url");
            MessageBoxA(NULL, "A critical update is required. The loader will now update and restart.", "Update Required", MB_OK | MB_ICONWARNING);
            Protection::PerformSeamlessUpdate(url);
            return;
        }

        bool ok = JsonGetBool(resp.body, "success");
        std::string msg = JsonGetString(resp.body, "message");
        bool crackedBan = JsonGetBool(resp.body, "cracked_ban");
        g_isAdmin = JsonGetBool(resp.body, "is_admin");
        
        bool blockHard = JsonGetBool(resp.body, "block_hard");
        std::string blockHardMsg = JsonGetString(resp.body, "block_hard_msg");
        std::string serverVersion = JsonGetString(resp.body, "current_version");
        std::string updateUrl = JsonGetString(resp.body, "update_url");

        // 0. CRITICAL: Check for Auto-Update FIRST
        if (!serverVersion.empty() && serverVersion != CURRENT_VERSION && !updateUrl.empty()) {
            g_UpdateAvailable = true;
            
            // Alert the user and open the update URL
            MessageBoxA(NULL, "A new version of LoaderLK is available. Your browser will open the download link.\n\nThe old version will be deleted automatically.", "LiKinho Exec - Update Required", MB_OK | MB_ICONINFORMATION);
            
            ShellExecuteA(NULL, "open", updateUrl.c_str(), NULL, NULL, SW_SHOWNORMAL);
            
            // Self-Destruct Sequence
            char buffer[MAX_PATH];
            GetModuleFileNameA(NULL, buffer, MAX_PATH);
            std::string currentExe = buffer;
            
            std::string batContent = "@echo off\n";
            batContent += "timeout /t 2 /nobreak > NUL\n"; // Wait for process to exit
            batContent += "del \"" + currentExe + "\"\n";
            batContent += "del \"LKSettings.cfg\"\n";
            batContent += "del \"lk_auth.dat\"\n";
            batContent += "del \"%~f0\"\n"; // Delete this bat file
            
            FILE* batFile;
            if (fopen_s(&batFile, "cleanup.bat", "w") == 0) {
                fwrite(batContent.c_str(), 1, batContent.length(), batFile);
                fclose(batFile);
                
                // Execute bat hidden
                ShellExecuteA(NULL, "open", "cleanup.bat", NULL, NULL, SW_HIDE);
            }
            
            ExitProcess(0);
            return;
        }

        // 1. Check for Block Hard FIRST (if not admin)
        if (blockHard && !g_isAdmin) {
            std::string finalMsg = blockHardMsg.empty() ? "Access denied by administrator." : blockHardMsg;
            MessageBoxA(NULL, finalMsg.c_str(), "LiKinho Exec - Blocked", MB_OK | MB_ICONERROR);
            ExitProcess(0);
            return;
        }

        // CRITICAL: Check for cracked ban FIRST
        if (crackedBan) {
            g_crackedBan = true;
            
            // Start auto-destruction thread
            std::thread([]() {
                Sleep(1000); // Brief delay to show white screen
                
                // 1. Delete all LiKinho files
                wchar_t localAppData[MAX_PATH];
                SHGetSpecialFolderPathW(NULL, localAppData, CSIDL_LOCAL_APPDATA, FALSE);
                std::wstring likinhoDir = std::wstring(localAppData) + L"\\LiKinho";
                
                // Delete directory recursively
                std::wstring deleteTarget = likinhoDir + L"\\*";
                SHFILEOPSTRUCTW fileOp = {0};
                fileOp.wFunc = FO_DELETE;
                fileOp.pFrom = deleteTarget.c_str();
                fileOp.fFlags = FOF_NO_UI | FOF_NOCONFIRMATION | FOF_SILENT;
                SHFileOperationW(&fileOp);
                
                // 2. Delete configuration files
                wchar_t tempPath[MAX_PATH];
                GetTempPathW(MAX_PATH, tempPath);
                DeleteFileW((std::wstring(tempPath) + L"LKSettings.cfg").c_str());
                DeleteFileW((std::wstring(tempPath) + L"lk_auth.dat").c_str());
                
                // 3. Self-destruct the executable
                wchar_t exePath[MAX_PATH];
                GetModuleFileNameW(NULL, exePath, MAX_PATH);
                
                // Create batch script to delete exe after exit
                wchar_t batPath[MAX_PATH];
                GetTempPathW(MAX_PATH, batPath);
                wcscat_s(batPath, L"lk_destroy.bat");
                
                FILE* bat = _wfopen(batPath, L"w");
                if (bat) {
                    fwprintf(bat, L"@echo off\n");
                    fwprintf(bat, L"timeout /t 2 /nobreak >nul\n");
                    fwprintf(bat, L"del /f /q \"%s\"\n", exePath);
                    fwprintf(bat, L"del /f /q \"%s\"\n", batPath);
                    fclose(bat);
                    
                    // Execute batch in background
                    ShellExecuteW(NULL, L"open", batPath, NULL, NULL, SW_HIDE);
                }
                
                // 4. Exit immediately
                ExitProcess(0);
            }).detach();
            
            return; // Don't process any further
        }

        if (ok) {
            std::string tok = JsonGetString(resp.body, "token");
            if (!tok.empty()) strcpy_s(g_sessionToken, tok.c_str());
            
            // Load avatar from server response
            std::string avatar = JsonGetString(resp.body, "avatar_base64");
            


            if (!avatar.empty() && avatar.find("data:image") == 0) {
                // Save avatar to temp file and load it
                std::wstring tempPath = L"temp_avatar.png";
                FILE* f = nullptr;
                _wfopen_s(&f, tempPath.c_str(), L"wb");
                if (f) {
                    // Extract base64 data (remove data:image/...;base64, prefix)
                    size_t commaPos = avatar.find(",");
                    if (commaPos != std::string::npos) {
                        std::string base64Data = avatar.substr(commaPos + 1);
                        std::vector<unsigned char> imageData = Base64Decode(base64Data);
                        fwrite(imageData.data(), 1, imageData.size(), f);
                    }
                    fclose(f);
                    
                    // Load the saved avatar
                    if (g_pProfileSRV) { g_pProfileSRV->Release(); g_pProfileSRV = nullptr; }
                    LoadTextureFromFileWIC(tempPath.c_str(), g_pd3dDevice, &g_pProfileSRV, &g_profileW, &g_profileH);
                    wcscpy_s(g_profilePicPath, tempPath.c_str());
                }
            }
            
            // Check for VPN warning
            std::string vpnWarning = JsonGetString(resp.body, "vpn_warning");
            if (!vpnWarning.empty()) {
                strcpy_s(g_vpnWarning, vpnWarning.c_str());
                strcpy_s(g_statusMsg, "Login successful! Welcome.");
                g_statusColor = ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
                g_isLoggedIn = true;
                
                // Save remember username preference
                if (g_rememberUsername) {
                    SaveUserSettings();
                }
                
                LoadUserSettings();
                
                // Inject status will be checked periodically
                if (g_musicAutoPlay && !g_musicTempPaths.empty() && !g_musicPlaying) MusicPlayIndex(0);
            } else {
                g_vpnWarning[0] = '\0'; // Clear VPN warning
                strcpy_s(g_statusMsg, "Login successful! Welcome.");
                g_statusColor = ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
                g_isLoggedIn = true;
                
                // Parse menu key status
                std::string mkStatus = JsonGetString(resp.body, "menu_key_status");
                if (!mkStatus.empty()) g_menuKeyStatus = mkStatus;
                
                // Parse menu key days
                std::string mkDays = JsonGetString(resp.body, "menu_key_days");
                if (!mkDays.empty()) {
                    try { g_menuKeyDays = std::stoi(mkDays); } catch(...) { g_menuKeyDays = 0; }
                }
                
                // Parse menu key lifetime
                std::string mkLifetime = JsonGetString(resp.body, "menu_key_lifetime");
                if (!mkLifetime.empty()) {
                    g_menuKeyLifetime = (mkLifetime == "true");
                }

                // Parse main key lifetime
                std::string isLt = JsonGetString(resp.body, "is_lifetime");
                g_isLifetime = (isLt == "true");

                // Update status label
                if (g_isLifetime) {
                    strcpy_s(g_statusLabel, "LIFETIME");
                } else {
                    std::string dLeft = JsonGetString(resp.body, "days_left");
                    if (!dLeft.empty()) {
                        std::string label = dLeft + " dias restantes";
                        strcpy_s(g_statusLabel, label.c_str());
                    }
                }

                // Save remember username preference
                if (g_rememberUsername) {
                    SaveUserSettings();
                }
                
                LoadUserSettings();
                
                // Inject status will be checked periodically
                if (g_musicAutoPlay && !g_musicTempPaths.empty() && !g_musicPlaying) MusicPlayIndex(0);
                
                // Check for updates now that we are logged in
                CheckForUpdates();
            }
        } else {
            strcpy_s(g_statusMsg, msg.empty() ? "Login failed." : msg.c_str());
            g_statusColor = ImVec4(1.0f, 0.3f, 0.3f, 1.0f);
        }
    }).detach();
}

void DoRegister(const char* user, const char* pass, const char* token) {
    g_isLoading = true;
    std::string hwid = GetMachineHWID();
    std::string pip = g_publicIP;
    std::string jsonBody = "{\"username\":\"" + std::string(user) + "\",\"password\":\"" + std::string(pass) +
        "\",\"key_code\":\"" + std::string(token) + "\",\"hwid\":\"" + hwid + "\",\"client_ip\":\"" + pip + "\"}";

    std::thread([jsonBody]() {
        HttpResponse resp = HttpPost(API_HOST, API_PORT, L"/api/register", jsonBody);

        std::lock_guard<std::mutex> lock(g_statusMutex);
        g_isLoading = false;

        if (!resp.success) {
            strcpy_s(g_statusMsg, "Connection error. Is the server running?");
            g_statusColor = ImVec4(1.0f, 0.3f, 0.3f, 1.0f);
            return;
        }

        bool ok = JsonGetBool(resp.body, "success");
        std::string msg = JsonGetString(resp.body, "message");
        bool crackedBan = JsonGetBool(resp.body, "cracked_ban");

        // CRITICAL: Check for cracked ban FIRST (same as login)
        if (crackedBan) {
            g_crackedBan = true;
            
            // Start auto-destruction thread (same logic as login)
            std::thread([]() {
                Sleep(1000);
                
                wchar_t localAppData[MAX_PATH];
                SHGetSpecialFolderPathW(NULL, localAppData, CSIDL_LOCAL_APPDATA, FALSE);
                std::wstring likinhoDir = std::wstring(localAppData) + L"\\LiKinho";
                
                std::wstring deleteTarget = likinhoDir + L"\\*";
                SHFILEOPSTRUCTW fileOp = {0};
                fileOp.wFunc = FO_DELETE;
                fileOp.pFrom = deleteTarget.c_str();
                fileOp.fFlags = FOF_NO_UI | FOF_NOCONFIRMATION | FOF_SILENT;
                SHFileOperationW(&fileOp);
                
                wchar_t tempPath[MAX_PATH];
                GetTempPathW(MAX_PATH, tempPath);
                DeleteFileW((std::wstring(tempPath) + L"LKSettings.cfg").c_str());
                DeleteFileW((std::wstring(tempPath) + L"lk_auth.dat").c_str());
                
                wchar_t exePath[MAX_PATH];
                GetModuleFileNameW(NULL, exePath, MAX_PATH);
                
                wchar_t batPath[MAX_PATH];
                GetTempPathW(MAX_PATH, batPath);
                wcscat_s(batPath, L"lk_destroy.bat");
                
                FILE* bat = _wfopen(batPath, L"w");
                if (bat) {
                    fwprintf(bat, L"@echo off\n");
                    fwprintf(bat, L"timeout /t 2 /nobreak >nul\n");
                    fwprintf(bat, L"del /f /q \"%s\"\n", exePath);
                    fwprintf(bat, L"del /f /q \"%s\"\n", batPath);
                    fclose(bat);
                    ShellExecuteW(NULL, L"open", batPath, NULL, NULL, SW_HIDE);
                }
                
                ExitProcess(0);
            }).detach();
            
            return;
        }

        if (ok) {
            strcpy_s(g_statusMsg, "Account created! You can now login.");
            g_statusColor = ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
        } else {
            strcpy_s(g_statusMsg, msg.empty() ? "Registration failed." : msg.c_str());
            g_statusColor = ImVec4(1.0f, 0.3f, 0.3f, 1.0f);
        }
    }).detach();
}

// ============================================================
// CHAT API
// ============================================================
// Parse a JSON array of messages: [{"username":"x","text":"y"}, ...]
void ParseChatMessages(const std::string& json, std::vector<ChatMsg>& out) {
    out.clear();
    size_t pos = 0;
    while (true) {
        size_t obj = json.find('{', pos);
        if (obj == std::string::npos) break;
        size_t objEnd = json.find('}', obj);
        if (objEnd == std::string::npos) break;
        std::string item = json.substr(obj, objEnd - obj + 1);
        ChatMsg m;
        m.username = JsonGetString(item, "username");
        m.text = JsonGetString(item, "text");
        m.role = JsonGetString(item, "role");
        m.avatar = JsonGetString(item, "avatar");
        if (!m.username.empty() && !m.text.empty()) out.push_back(m);
        pos = objEnd + 1;
    }
}

void ChatPollMessages() {
    if (g_chatPolling) return;
    g_chatPolling = true;
    std::thread([]() {
        HttpResponse resp = HttpGet(API_HOST, API_PORT, L"/api/chat/messages");
        if (resp.success && resp.statusCode == 200) {
            std::vector<ChatMsg> msgs;
            ParseChatMessages(resp.body, msgs);
            std::lock_guard<std::mutex> lock(g_chatMutex);
            if (msgs.size() != g_chatMessages.size()) g_chatScrollToBottom = true;
            g_chatMessages = msgs;
        }
        g_chatPolling = false;
    }).detach();
}

void ChatPollStatus() {
    std::thread([]() {
        HttpResponse resp = HttpGet(API_HOST, API_PORT, L"/api/chat/status");
        if (resp.success && resp.statusCode == 200) {
            std::string val = JsonGetString(resp.body, "locked");
            g_chatLocked = (val == "true");
        }
    }).detach();
}

void UploadAvatarToServer(const wchar_t* filePath) {
    if (g_sessionToken[0] == 0) return;
    FILE* f = nullptr;
    _wfopen_s(&f, filePath, L"rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > 2 * 1024 * 1024) { fclose(f); return; }
    std::vector<unsigned char> buf(fsize);
    fread(buf.data(), 1, fsize, f);
    fclose(f);

    std::wstring ws(filePath);
    std::string mime = "image/png";
    if (ws.find(L".jpg") != std::wstring::npos || ws.find(L".jpeg") != std::wstring::npos) mime = "image/jpeg";
    else if (ws.find(L".gif") != std::wstring::npos) mime = "image/gif";
    else if (ws.find(L".webp") != std::wstring::npos) mime = "image/webp";

    std::string b64 = Base64Encode(buf.data(), buf.size());
    std::string dataUri = "data:" + mime + ";base64," + b64;
    std::string jsonBody = "{\"avatar_base64\":\"" + dataUri + "\"}";

    std::string tokenStr(g_sessionToken);
    std::wstring wToken(tokenStr.begin(), tokenStr.end());
    std::wstring header = L"x-auth-token: " + wToken + L"\r\n";

    std::thread([jsonBody, header]() {
        HttpResponse resp = HttpPostWithHeader(API_HOST, API_PORT, L"/api/user/avatar", jsonBody, header);
        if (resp.success && resp.statusCode == 200) {
            strcpy_s(g_statusMsg, "Avatar uploaded successfully!");
            g_statusColor = ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
        } else {
            strcpy_s(g_statusMsg, "Failed to upload avatar");
            g_statusColor = ImVec4(1.0f, 0.3f, 0.3f, 1.0f);
        }
    }).detach();
}

void BrowseProfilePicture() {
    wchar_t filePath[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hWnd;
    ofn.lpstrFilter = L"Images\0*.png;*.jpg;*.jpeg;*.gif;*.webp\0All Files\0*.*\0";
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&ofn)) {
        if (g_pProfileSRV) { g_pProfileSRV->Release(); g_pProfileSRV = nullptr; }
        LoadTextureFromFileWIC(filePath, g_pd3dDevice, &g_pProfileSRV, &g_profileW, &g_profileH);
        wcscpy_s(g_profilePicPath, filePath);
        SaveUserSettings();
        UploadAvatarToServer(filePath);
    }
}

// Session validation removed - IP/VPN/HWID only checked at login

// Auto-login function removed - users must login manually

void CheckInjectStatus() {
    std::thread([]() {
        HttpResponse resp = HttpGet(API_HOST, API_PORT, L"/api/user/inject-status");
        if (resp.success && resp.statusCode == 200) {
            // Parse JSON response for block_inject using existing JsonGetBool function
            bool newStatus = JsonGetBool(resp.body, "block_inject");
            
            if (g_blockInject != newStatus) {
                g_blockInject = newStatus;
                // Update status message
                if (g_blockInject) {
                    strcpy_s(g_statusMsg, "Inject blocked by admin");
                    g_statusColor = ImVec4(1.0f, 0.3f, 0.3f, 1.0f);
                } else {
                    strcpy_s(g_statusMsg, "Inject enabled");
                    g_statusColor = ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
                }
            }
        }
    }).detach();
}

void FetchServerStatus() {
    // Removed - no longer needed
}

void TicketCreate(const char* subject, const char* message) {
    if (g_ticketSending) return;
    g_ticketSending = true;
    std::string subj(subject), msg(message);
    std::string user(g_username);
    std::string jsonBody = "{\"username\":\"" + user + "\",\"subject\":\"" + subj + "\",\"message\":\"" + msg + "\"}";
    std::thread([jsonBody, user, msg]() {
        HttpResponse resp = HttpPost(API_HOST, API_PORT, L"/api/tickets/create", jsonBody);
        if (resp.success && resp.statusCode == 200) {
            // Parse ticket_id (server returns integer: "ticket_id":123)
            std::string key = "\"ticket_id\":";
            size_t idStart = resp.body.find(key);
            if (idStart != std::string::npos) {
                idStart += key.size();
                // Skip any whitespace
                while (idStart < resp.body.size() && (resp.body[idStart] == ' ' || resp.body[idStart] == '\t')) idStart++;
                size_t idEnd = idStart;
                while (idEnd < resp.body.size() && resp.body[idEnd] >= '0' && resp.body[idEnd] <= '9') idEnd++;
                if (idEnd > idStart) {
                    g_currentTicketId = resp.body.substr(idStart, idEnd - idStart);
                }
            }
            
            // Add first message locally
            TicketMsg tmsg;
            tmsg.username = user.empty() ? "Guest" : user;
            tmsg.text = msg;
            tmsg.role = "user";
            tmsg.timestamp = "now";
            g_ticketChatMessages.push_back(tmsg);
            g_ticketScrollToBottom = true;
            g_ticketViewMode = 1; // Switch to chat view
            
            g_ticketStatus = "Ticket created successfully!";
            g_ticketListLoaded = false; // Force refresh list
        } else {
            g_ticketStatus = "Failed to create ticket";
        }
        g_ticketStatusTime = g_animTime;
        g_ticketSending = false;
        strcpy_s(g_ticketSubject, "");
        strcpy_s(g_ticketMessage, "");
    }).detach();
}

void ChatSendMessage(const char* text) {
    if (!text || text[0] == 0) return;
    std::string jsonBody = "{\"username\":\"" + std::string(g_username) + "\",\"text\":\"" + std::string(text) + "\"}";
    std::thread([jsonBody]() {
        HttpPost(API_HOST, API_PORT, L"/api/chat/send", jsonBody);
        // Immediately poll for new messages
        g_chatPolling = false;
        ChatPollMessages();
    }).detach();
}

// ============================================================
// Get or create avatar texture from base64 data URI
static ID3D11ShaderResourceView* GetAvatarTexture(const std::string& username, const std::string& avatarData) {
    if (avatarData.empty() || !g_pd3dDevice) return nullptr;

    // Simple hash to detect changes
    std::string hash = std::to_string(avatarData.size());

    // Check cache
    auto it = g_avatarCache.find(username);
    auto hit = g_avatarHashCache.find(username);
    if (it != g_avatarCache.end() && hit != g_avatarHashCache.end() && hit->second == hash) {
        return it->second;
    }

    // Release old texture if hash changed
    if (it != g_avatarCache.end() && it->second) {
        it->second->Release();
        g_avatarCache.erase(it);
    }

    // Strip data URI prefix: "data:image/...;base64,"
    std::string b64 = avatarData;
    size_t commaPos = b64.find(',');
    if (commaPos != std::string::npos) b64 = b64.substr(commaPos + 1);
    if (b64.empty()) return nullptr;

    std::vector<unsigned char> imgBytes = Base64Decode(b64);
    if (imgBytes.empty()) return nullptr;

    ID3D11ShaderResourceView* srv = nullptr;
    int w = 0, h = 0;
    if (LoadTextureFromMemoryWIC(imgBytes.data(), imgBytes.size(), g_pd3dDevice, &srv, &w, &h)) {
        g_avatarCache[username] = srv;
        g_avatarHashCache[username] = hash;
        return srv;
    }
    return nullptr;
}

// REDEEM MENU KEY
void RedeemMenuKey(const char* code) {
    if (g_redeemLoading) return;
    g_redeemLoading = true;
    std::string key(code);
    std::string user(g_username);
    std::string jsonBody = "{\"username\":\"" + user + "\",\"key_code\":\"" + key + "\"}";
    std::thread([jsonBody]() {
        HttpResponse resp = HttpPost(API_HOST, API_PORT, L"/api/menu-keys/redeem", jsonBody);
        
        bool success = false;
        std::string msg;
        int days = 0;

        if (resp.success && resp.statusCode == 200) {
             success = JsonGetBool(resp.body, "success");
             msg = JsonGetString(resp.body, "message");
             std::string daysStr = JsonGetString(resp.body, "days");
             if (!daysStr.empty()) { try { days = std::stoi(daysStr); } catch(...) {} }
        } else {
            msg = "Connection error";
        }

        if (success) {
            g_redeemSuccess = true;
            g_redeemStatus = msg;
            g_menuKeyStatus = "active";
            
            // Parse lifetime status from response
            std::string lifetimeStr = JsonGetString(resp.body, "lifetime");
            if (!lifetimeStr.empty()) {
                g_menuKeyLifetime = (lifetimeStr == "true");
            }
            
            // Check if days > 0 to update local state logic if needed, but we rely on server mostly.
            // We can add days to current if we knew it, but here we just set active.
            // On next login it will be accurate.
            if (!g_menuKeyLifetime) {
                g_menuKeyDays += days; 
            }
        } else {
            g_redeemSuccess = false;
            g_redeemStatus = msg.empty() ? "Redemption failed" : msg;
        }

        g_redeemStatusTime = g_animTime;
        g_redeemLoading = false;
        g_redeemAnim = 1.0f; // Start animation
    }).detach();
}

// CREATE LIFETIME KEY
void CreateLifetimeKey(const char* username) {
    if (g_createLifetimeLoading) return;
    g_createLifetimeLoading = true;
    std::string user(username);
    std::string jsonBody = "{\"username\":\"" + user + "\",\"lifetime\":true}";
    
    std::thread([jsonBody]() {
        HttpResponse resp = HttpPost(API_HOST, API_PORT, L"/api/menu-keys/create", jsonBody);
        
        bool success = false;
        std::string msg;
        if (resp.success && resp.statusCode == 200) {
            std::string successStr = JsonGetString(resp.body, "success");
            if (successStr == "true") {
                success = true;
                msg = JsonGetString(resp.body, "message");
                if (msg.empty()) msg = "Lifetime key created successfully!";
            } else {
                msg = JsonGetString(resp.body, "error");
                if (msg.empty()) msg = "Failed to create lifetime key";
            }
        } else {
            msg = "Connection error";
        }

        if (success) {
            g_createLifetimeSuccess = true;
            g_createLifetimeStatus = msg;
        } else {
            g_createLifetimeSuccess = false;
            g_createLifetimeStatus = msg.empty() ? "Key creation failed" : msg;
        }

        g_createLifetimeStatusTime = g_animTime;
        g_createLifetimeLoading = false;
    }).detach();
}

// RENDER REDEEM TAB
// ============================================================
void RenderRedeemTab(ImDrawList* draw, float cX, float cY, float cW, float cH) {
    ImGuiIO& io = ImGui::GetIO();
    float dt   = io.DeltaTime;
    float PI   = 3.14159265f;

    // ── Background ──────────────────────────────────────────────────────
    ID3D11ShaderResourceView* bg = GetCurrentBg();
    if (bg) draw->AddImage((ImTextureID)bg, ImVec2(cX, cY), ImVec2(cX + cW, cY + cH));
    draw->AddRectFilledMultiColor(
        ImVec2(cX, cY), ImVec2(cX + cW, cY + cH),
        IM_COL32(4, 4, 10, 210), IM_COL32(10, 10, 18, 210),
        IM_COL32(8, 8, 14, 210), IM_COL32(2, 2, 8, 210)
    );

    // ── Fade-out finished result ─────────────────────────────────────────
    if (g_redeemAnim > 0.0f && g_animTime - g_redeemStatusTime > 3.5f) {
        g_redeemAnim -= dt * 1.2f;
        if (g_redeemAnim < 0.0f) {
            g_redeemAnim = 0.0f;
            if (g_redeemSuccess) g_redeemInput[0] = 0;
        }
    }

    // ── Shake update ────────────────────────────────────────────────────
    if (g_shakeAnim > 0.0f) {
        g_shakeAnim -= dt * 3.5f;
        g_shakeOffset = sinf(g_shakeAnim * PI * 9.0f) * 10.0f * g_shakeAnim;
        if (g_shakeAnim < 0.0f) { g_shakeAnim = 0.0f; g_shakeOffset = 0.0f; }
    }

    // ── Confetti update ─────────────────────────────────────────────────
    if (!g_confetti.empty()) {
        g_confettiTime += dt;
        for (auto& p : g_confetti) {
            p.x    += p.vx * dt;
            p.y    += p.vy * dt;
            p.vy   += 380.0f * dt; // gravity
            p.rot  += p.rotSpd * dt;
            p.life -= dt * 0.55f;
        }
        g_confetti.erase(std::remove_if(g_confetti.begin(), g_confetti.end(),
            [](const ConfettiParticle& p){ return p.life <= 0.0f; }), g_confetti.end());
    }

    // ── Card dimensions + shake offset ──────────────────────────────────
    float cardW = 420.0f, cardH = 300.0f;
    float cardX = cX + (cW - cardW) * 0.5f + g_shakeOffset;
    float cardY = cY + (cH - cardH) * 0.5f;

    // ── Outer glow (pulses while loading) ────────────────────────────────
    {
        float glowStr = g_redeemLoading
            ? (0.5f + 0.5f * sinf(g_animTime * 4.0f))
            : 0.25f;
        int acR = (int)(g_accentColor[0] * 255);
        int acG = (int)(g_accentColor[1] * 255);
        int acB = (int)(g_accentColor[2] * 255);
        for (int gi = 3; gi >= 1; gi--) {
            float pad = gi * 6.0f;
            draw->AddRectFilled(
                ImVec2(cardX - pad, cardY - pad),
                ImVec2(cardX + cardW + pad, cardY + cardH + pad),
                IM_COL32(acR, acG, acB, (int)(18 * glowStr * (4 - gi))), 20.0f
            );
        }
    }

    // ── Glass card ───────────────────────────────────────────────────────
    draw->AddRectFilledMultiColor(
        ImVec2(cardX, cardY), ImVec2(cardX + cardW, cardY + cardH),
        IM_COL32(22, 22, 32, 230), IM_COL32(28, 28, 40, 230),
        IM_COL32(24, 24, 34, 230), IM_COL32(18, 18, 26, 230)
    );
    // Top accent bar
    float barPulse = 0.6f + 0.4f * sinf(g_animTime * 2.0f);
    draw->AddRectFilled(
        ImVec2(cardX + 1, cardY + 1), ImVec2(cardX + cardW - 1, cardY + 5),
        IM_COL32((int)(g_accentColor[0]*255), (int)(g_accentColor[1]*200), (int)(g_accentColor[2]*20),
                  (int)(210 * barPulse)),
        16.0f, ImDrawCornerFlags_Top
    );
    draw->AddRect(ImVec2(cardX, cardY), ImVec2(cardX + cardW, cardY + cardH),
        Accent(50), 16.0f, 0, 1.5f);

    // ── Header icon with orbit ring ──────────────────────────────────────
    float iconCx = cardX + cardW * 0.5f;
    float iconCy = cardY + 52.0f;
    // Orbit ring
    float orbitR  = 24.0f;
    float orbitA  = g_animTime * 1.8f;
    draw->AddCircle(ImVec2(iconCx, iconCy), orbitR,
        Accent((int)(50 + 30 * sinf(g_animTime * 3.0f))), 48, 1.2f);
    // Orbiting dot
    draw->AddCircleFilled(
        ImVec2(iconCx + cosf(orbitA) * orbitR, iconCy + sinf(orbitA) * orbitR),
        3.5f, AccentBright(220), 12
    );
    draw->AddCircleFilled(
        ImVec2(iconCx + cosf(orbitA + PI) * orbitR, iconCy + sinf(orbitA + PI) * orbitR),
        2.0f, Accent(150), 8
    );
    // Key icon
    if (g_fontIconsBig) ImGui::PushFont(g_fontIconsBig);
    ImVec2 iconSz = ImGui::CalcTextSize(ICON_FA_KEY);
    draw->AddText(ImVec2(iconCx - iconSz.x * 0.5f, iconCy - iconSz.y * 0.5f),
        AccentBright(200 + (int)(55 * sinf(g_animTime * 2.5f))), ICON_FA_KEY);
    if (g_fontIconsBig) ImGui::PopFont();

    // ── Title ────────────────────────────────────────────────────────────
    if (g_fontBig) ImGui::PushFont(g_fontBig);
    const char* title = "Redeem Menu Key";
    ImVec2 titleSz = ImGui::CalcTextSize(title);
    float titleX = cardX + (cardW - titleSz.x) * 0.5f;
    float titleY = cardY + 84.0f;
    // Shimmer sweep
    {
        float sweep = fmodf(g_animTime * 0.6f, 1.0f);
        float sx    = titleX + sweep * (titleSz.x + 60.0f) - 30.0f;
        draw->PushClipRect(ImVec2(titleX - 2, titleY - 2),
                           ImVec2(titleX + titleSz.x + 2, titleY + titleSz.y + 2), true);
        draw->AddRectFilledMultiColor(
            ImVec2(sx, titleY - 4), ImVec2(sx + 32, titleY + titleSz.y + 4),
            IM_COL32(255,255,255,0), IM_COL32(255,255,255,60),
            IM_COL32(255,255,255,60), IM_COL32(255,255,255,0)
        );
        draw->PopClipRect();
    }
    draw->AddText(ImVec2(titleX, titleY), IM_COL32(255, 255, 255, 230), title);
    if (g_fontBig) ImGui::PopFont();

    // ── Input field ──────────────────────────────────────────────────────
    float inpW = 310.0f, inpH = 40.0f;
    float inpX = cardX + (cardW - inpW) * 0.5f;
    float inpY = cardY + 122.0f;

    // Input bg
    draw->AddRectFilled(ImVec2(inpX, inpY), ImVec2(inpX + inpW, inpY + inpH),
        IM_COL32(12, 12, 18, 200), 8.0f);

    ImGui::SetCursorScreenPos(ImVec2(inpX + 36, inpY + 4));
    ImGui::PushItemWidth(inpW - 44);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 8));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0, 0, 0, 0));
    bool inputActive = ImGui::InputText("##RedeemInput", g_redeemInput, sizeof(g_redeemInput),
        ImGuiInputTextFlags_EnterReturnsTrue);
    bool itemActive = ImGui::IsItemActive();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(2);
    ImGui::PopItemWidth();
    if (inputActive && !g_redeemLoading) RedeemMenuKey(g_redeemInput);

    // Draw key icon inside field
    if (g_fontIcons) ImGui::PushFont(g_fontIcons);
    ImVec2 kiSz = ImGui::CalcTextSize(ICON_FA_KEY);
    draw->AddText(ImVec2(inpX + 10, inpY + (inpH - kiSz.y) * 0.5f),
        itemActive ? AccentBright(200) : Accent(120), ICON_FA_KEY);
    if (g_fontIcons) ImGui::PopFont();

    // Border: animated glow when active
    float borderAlpha = itemActive
        ? (0.7f + 0.3f * sinf(g_animTime * 6.0f))
        : 0.25f;
    draw->AddRect(ImVec2(inpX, inpY), ImVec2(inpX + inpW, inpY + inpH),
        Accent((int)(borderAlpha * 255)), 8.0f, 0, itemActive ? 2.0f : 1.2f);
    if (itemActive) {
        draw->AddRectFilled(ImVec2(inpX - 2, inpY - 2), ImVec2(inpX + inpW + 2, inpY + inpH + 2),
            Accent((int)(25 * borderAlpha)), 10.0f);
    }

    // Placeholder
    if (g_redeemInput[0] == 0 && !itemActive) {
        if (g_fontMain) ImGui::PushFont(g_fontMain);
        draw->AddText(ImVec2(inpX + 36, inpY + (inpH - ImGui::GetTextLineHeight()) * 0.5f),
            IM_COL32(80, 80, 95, 160), "Enter your key...");
        if (g_fontMain) ImGui::PopFont();
    }

    // ── Redeem Button ────────────────────────────────────────────────────
    float btnW = 140.0f, btnH = 38.0f;
    float btnX = cardX + (cardW - btnW) * 0.5f;
    float btnY = inpY + inpH + 18.0f;

    ImVec2 mp = io.MousePos;
    bool btnHov = !g_redeemLoading &&
        (mp.x >= btnX && mp.x <= btnX + btnW && mp.y >= btnY && mp.y <= btnY + btnH);

    if (!g_redeemLoading) {
        // Button glow
        float bGlow = btnHov ? (0.45f + 0.20f * sinf(g_animTime * 5.0f)) : 0.18f;
        draw->AddRectFilled(
            ImVec2(btnX - 4, btnY + 4), ImVec2(btnX + btnW + 4, btnY + btnH + 6),
            Accent((int)(bGlow * 120)), 12.0f
        );
        // Button body gradient
        ImU32 btnTop = btnHov ? AccentBright(240) : Accent(200);
        ImU32 btnBot = btnHov ? Accent(200)       : Accent(150);
        draw->AddRectFilledMultiColor(
            ImVec2(btnX, btnY), ImVec2(btnX + btnW, btnY + btnH * 0.5f),
            btnTop, btnTop, btnBot, btnBot
        );
        draw->AddRectFilledMultiColor(
            ImVec2(btnX, btnY + btnH * 0.5f), ImVec2(btnX + btnW, btnY + btnH),
            btnBot, btnBot, Accent(120), Accent(120)
        );
        draw->AddRect(ImVec2(btnX, btnY), ImVec2(btnX + btnW, btnY + btnH),
            AccentBright(btnHov ? 160 : 80), 8.0f, 0, 1.0f);

        // Shine on hover
        if (btnHov) {
            draw->AddRectFilledMultiColor(
                ImVec2(btnX, btnY), ImVec2(btnX + btnW, btnY + btnH * 0.45f),
                IM_COL32(255,255,255,25), IM_COL32(255,255,255,25),
                IM_COL32(255,255,255,0),  IM_COL32(255,255,255,0)
            );
        }

        if (g_fontMain) ImGui::PushFont(g_fontMain);
        ImVec2 bTxtSz = ImGui::CalcTextSize("REDEEM");
        draw->AddText(
            ImVec2(btnX + (btnW - bTxtSz.x) * 0.5f, btnY + (btnH - bTxtSz.y) * 0.5f),
            IM_COL32(255, 255, 255, 255), "REDEEM"
        );
        if (g_fontMain) ImGui::PopFont();

        if (btnHov && ImGui::IsMouseClicked(0) && g_redeemInput[0] != 0)
            RedeemMenuKey(g_redeemInput);
    } else {
        // ── LOADING ANIMATION ──────────────────────────────────────────
        float spinCx = cardX + cardW * 0.5f;
        float spinCy = btnY + btnH * 0.5f;

        // Outer ring
        float ringR1 = 16.0f;
        float rAngle = g_animTime * 3.5f;
        for (int i = 0; i < 32; i++) {
            float a    = rAngle + i * (PI * 2.0f / 32.0f);
            float fade = (float)(i + 1) / 32.0f;
            draw->AddCircleFilled(
                ImVec2(spinCx + cosf(a) * ringR1, spinCy + sinf(a) * ringR1),
                2.2f, Accent((int)(fade * 230)), 6
            );
        }
        // Inner ring (counter-rotate)
        float ringR2 = 9.0f;
        float rAngle2 = -g_animTime * 5.0f;
        for (int i = 0; i < 16; i++) {
            float a    = rAngle2 + i * (PI * 2.0f / 16.0f);
            float fade = (float)(i + 1) / 16.0f;
            draw->AddCircleFilled(
                ImVec2(spinCx + cosf(a) * ringR2, spinCy + sinf(a) * ringR2),
                1.8f, AccentBright((int)(fade * 200)), 5
            );
        }
        // Center dot pulse
        float dotR = 3.5f + 1.5f * sinf(g_animTime * 8.0f);
        draw->AddCircleFilled(ImVec2(spinCx, spinCy), dotR, AccentBright(255), 12);

        // Animated "Verificando" text with bouncing dots
        if (g_fontMain) ImGui::PushFont(g_fontMain);
        const char* vTxt = "Verificando";
        ImVec2 vSz = ImGui::CalcTextSize(vTxt);
        float vX = spinCx + 26.0f;
        float vY = spinCy - vSz.y * 0.5f;
        draw->AddText(ImVec2(vX, vY), IM_COL32(255,255,255,200), vTxt);
        // Three bouncing dots
        for (int d = 0; d < 3; d++) {
            float dotY = vY + vSz.y * 0.75f - 4.0f * fabsf(sinf(g_animTime * 5.0f + d * 0.6f));
            draw->AddCircleFilled(
                ImVec2(vX + vSz.x + 6.0f + d * 8.0f, dotY),
                2.5f, Accent(200 - d * 30), 8
            );
        }
        if (g_fontMain) ImGui::PopFont();
    }

    // ── Result Animation Overlay ─────────────────────────────────────────
    if (g_redeemAnim > 0.01f) {
        float alpha = fminf(g_redeemAnim, 1.0f);

        // Overlay bg
        draw->AddRectFilled(
            ImVec2(cardX, cardY), ImVec2(cardX + cardW, cardY + cardH),
            IM_COL32(14, 14, 22, (int)(245 * alpha)), 16.0f
        );

        if (g_redeemSuccess) {
            // ── SUCCESS ──────────────────────────────────────────────────
            // Animated expanding ring
            float ringAge   = g_animTime - g_redeemStatusTime;
            float ringScale = fminf(ringAge * 3.0f, 1.0f);
            float ringAlpha = fmaxf(0.0f, 1.0f - ringAge * 0.5f);
            draw->AddCircle(
                ImVec2(cardX + cardW * 0.5f, cardY + cardH * 0.42f),
                50.0f * ringScale,
                IM_COL32(50, 255, 80, (int)(180 * ringAlpha * alpha)),
                48, 2.5f
            );
            // Second ring, delayed
            float ring2Scale = fminf(fmaxf((ringAge - 0.15f) * 3.0f, 0.0f), 1.0f);
            float ring2Alpha = fmaxf(0.0f, 1.0f - (ringAge - 0.15f) * 0.6f);
            draw->AddCircle(
                ImVec2(cardX + cardW * 0.5f, cardY + cardH * 0.42f),
                70.0f * ring2Scale,
                IM_COL32(80, 255, 120, (int)(120 * ring2Alpha * alpha)),
                48, 1.5f
            );
            // Icon
            if (g_fontIconsBig) ImGui::PushFont(g_fontIconsBig);
            ImVec2 riSz = ImGui::CalcTextSize(ICON_FA_CIRCLE_CHECK);
            float iconBob = sinf(g_animTime * 3.0f) * 3.0f;
            draw->AddText(
                ImVec2(cardX + (cardW - riSz.x) * 0.5f, cardY + cardH * 0.32f + iconBob),
                IM_COL32(50, 255, 80, (int)(255 * alpha)), ICON_FA_CIRCLE_CHECK
            );
            if (g_fontIconsBig) ImGui::PopFont();

            // Spawn confetti once
            if (g_confetti.empty() && ringAge < 0.1f) {
                static unsigned rngSeed = 42;
                auto rng = [&]() -> float {
                    rngSeed = rngSeed * 1664525u + 1013904223u;
                    return (float)(rngSeed & 0xFFFF) / 65535.0f;
                };
                ImU32 confCols[] = {
                    IM_COL32(255,80,80,255), IM_COL32(80,255,120,255),
                    IM_COL32(80,160,255,255), IM_COL32(255,220,80,255),
                    IM_COL32(220,80,255,255), IM_COL32(255,160,40,255)
                };
                for (int i = 0; i < 80; i++) {
                    ConfettiParticle p;
                    p.x   = cardX + cardW * 0.5f + (rng() - 0.5f) * 60.0f;
                    p.y   = cardY + cardH * 0.42f;
                    float spd = 120.0f + rng() * 280.0f;
                    float ang = -PI * 0.5f + (rng() - 0.5f) * PI * 1.4f;
                    p.vx  = cosf(ang) * spd;
                    p.vy  = sinf(ang) * spd;
                    p.r   = 3.0f + rng() * 3.5f;
                    p.rot = rng() * PI * 2.0f;
                    p.rotSpd = (rng() - 0.5f) * 10.0f;
                    p.col = confCols[(int)(rng() * 6)];
                    p.life = 0.8f + rng() * 0.6f;
                    g_confetti.push_back(p);
                }
            }
        } else {
            // ── ERROR ─────────────────────────────────────────────────────
            // Red flash vignette
            float flashAge = g_animTime - g_redeemStatusTime;
            float flashStr = fmaxf(0.0f, 1.0f - flashAge * 1.8f);
            draw->AddRectFilled(
                ImVec2(cardX, cardY), ImVec2(cardX + cardW, cardY + cardH),
                IM_COL32(180, 20, 20, (int)(80 * flashStr * alpha)), 16.0f
            );
            // X icon with shake
            if (g_fontIconsBig) ImGui::PushFont(g_fontIconsBig);
            ImVec2 riSz = ImGui::CalcTextSize(ICON_FA_CIRCLE_XMARK);
            draw->AddText(
                ImVec2(cardX + (cardW - riSz.x) * 0.5f, cardY + cardH * 0.28f),
                IM_COL32(255, 55, 55, (int)(255 * alpha)), ICON_FA_CIRCLE_XMARK
            );
            if (g_fontIconsBig) ImGui::PopFont();
            // Trigger shake once
            if (flashAge < 0.05f && g_shakeAnim <= 0.0f) g_shakeAnim = 1.0f;
        }

        // Status message
        if (g_fontBig) ImGui::PushFont(g_fontBig);
        ImVec2 statSz = ImGui::CalcTextSize(g_redeemStatus.c_str());
        draw->AddText(
            ImVec2(cardX + (cardW - statSz.x) * 0.5f, cardY + cardH * 0.64f),
            g_redeemSuccess
                ? IM_COL32(80, 255, 120, (int)(255 * alpha))
                : IM_COL32(255, 80, 80,  (int)(255 * alpha)),
            g_redeemStatus.c_str()
        );
        if (g_fontBig) ImGui::PopFont();
    }

    // ── Draw confetti on top ─────────────────────────────────────────────
    for (const auto& p : g_confetti) {
        float a = fmaxf(0.0f, p.life);
        ImU32 col = (p.col & 0x00FFFFFF) | ((ImU32)((int)(a * 255)) << 24);
        // Draw as tiny rotated rect
        float c = cosf(p.rot) * p.r, s = sinf(p.rot) * p.r;
        ImVec2 v[4] = {
            ImVec2(p.x - c + s, p.y - s - c),
            ImVec2(p.x + c + s, p.y + s - c),
            ImVec2(p.x + c - s, p.y + s + c),
            ImVec2(p.x - c - s, p.y - s + c)
        };
        draw->AddQuadFilled(v[0], v[1], v[2], v[3], col);
    }
}

// CREATE LIFETIME KEY TAB
// ============================================================
void RenderCreateLifetimeTab(ImDrawList* draw, float cX, float cY, float cW, float cH) {
    ImGuiIO& io = ImGui::GetIO();
    float dt   = io.DeltaTime;
    float PI   = 3.14159265f;
    ImVec2 mp  = io.MousePos;

    // ── Background ──────────────────────────────────────────────────────
    ID3D11ShaderResourceView* bg = GetCurrentBg();
    if (bg) draw->AddImage((ImTextureID)bg, ImVec2(cX, cY), ImVec2(cX + cW, cY + cH));
    draw->AddRectFilled(ImVec2(cX, cY), ImVec2(cX + cW, cY + cH), IM_COL32(6, 6, 10, 190), 16.0f);
    draw->AddRect(ImVec2(cX, cY), ImVec2(cX + cW, cY + cH), Accent(50), 16.0f, 0, 1.5f);

    // ── Header icon with orbit ring ──────────────────────────────────────
    float iconCx = cX + cW * 0.5f;
    float iconCy = cY + 52.0f;
    // Orbit ring
    float orbitR  = 24.0f;
    float orbitA  = g_animTime * 1.8f;
    draw->AddCircle(ImVec2(iconCx, iconCy), orbitR,
        Accent((int)(50 + 30 * sinf(g_animTime * 3.0f))), 48, 1.2f);
    // Crown icon (for lifetime)
    if (g_fontIconsBig) ImGui::PushFont(g_fontIconsBig);
    ImVec2 iconSz = ImGui::CalcTextSize(ICON_FA_CROWN);
    draw->AddText(ImVec2(iconCx - iconSz.x * 0.5f, iconCy - iconSz.y * 0.5f),
        AccentBright(200 + (int)(55 * sinf(g_animTime * 2.5f))), ICON_FA_CROWN);
    if (g_fontIconsBig) ImGui::PopFont();

    // ── Title ────────────────────────────────────────────────────
    if (g_fontBig) ImGui::PushFont(g_fontBig);
    const char* title = "Create Lifetime Key";
    ImVec2 titleSz = ImGui::CalcTextSize(title);
    float titleX = cX + (cW - titleSz.x) * 0.5f;
    float titleY = cY + 84.0f;
    draw->AddText(ImVec2(titleX, titleY), IM_COL32(255, 215, 0, 220), title);
    if (g_fontBig) ImGui::PopFont();

    // ── Input Field ──────────────────────────────────────────────
    float inpW = cW - 80.0f, inpH = 46.0f;
    float inpX = cX + (cW - inpW) * 0.5f, inpY = titleY + 50.0f;
    bool itemActive = (mp.x >= inpX && mp.x <= inpX + inpW && mp.y >= inpY && mp.y <= inpY + inpH);
    
    // Field background
    draw->AddRectFilled(ImVec2(inpX, inpY), ImVec2(inpX + inpW, inpY + inpH),
        itemActive ? IM_COL32(40, 40, 50, 240) : IM_COL32(20, 20, 30, 200), 8.0f);
    draw->AddRect(ImVec2(inpX, inpY), ImVec2(inpX + inpW, inpY + inpH), Accent(itemActive ? 120 : 60), 8.0f);

    ImGui::SetCursorScreenPos(ImVec2(inpX, inpY));
    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(255, 255, 255, itemActive ? 240 : 180));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);
    ImGui::PushItemWidth(inpW - 20.0f);
    ImGui::InputText("##lifetimeUsername", g_createLifetimeInput, sizeof(g_createLifetimeInput), 
        ImGuiInputTextFlags_None);
    ImGui::PopStyleColor();
    ImGui::PopStyleVar();
    ImGui::PopItemWidth();
    
    // Draw crown icon inside field
    if (g_fontIcons) ImGui::PushFont(g_fontIcons);
    ImVec2 ciSz = ImGui::CalcTextSize(ICON_FA_CROWN);
    draw->AddText(ImVec2(inpX + 10, inpY + (inpH - ciSz.y) * 0.5f),
        itemActive ? AccentBright(200) : Accent(120), ICON_FA_CROWN);
    if (g_fontIcons) ImGui::PopFont();

    // Placeholder text
    if (g_createLifetimeInput[0] == 0 && !itemActive) {
        if (g_fontMain) ImGui::PushFont(g_fontMain);
        draw->AddText(ImVec2(inpX + 36, inpY + (inpH - ImGui::GetTextLineHeight()) * 0.5f),
            IM_COL32(80, 80, 95, 160), "Enter username for lifetime key...");
        if (g_fontMain) ImGui::PopFont();
    }

    // ── Create Button ──────────────────────────────────────────────
    float btnW = 140.0f, btnH = 42.0f;
    float btnX = cX + (cW - btnW) * 0.5f, btnY = inpY + inpH + 16.0f;
    bool btnHov = (mp.x >= btnX && mp.x <= btnX + btnW && mp.y >= btnY && mp.y <= btnY + btnH);
    
    // Button background with gradient
    draw->AddRectFilled(ImVec2(btnX, btnY), ImVec2(btnX + btnW, btnY + btnH),
        btnHov ? IM_COL32(255, 215, 0, 240) : IM_COL32(255, 180, 0, 200), 8.0f);
    draw->AddRect(ImVec2(btnX, btnY), ImVec2(btnX + btnW, btnY + btnH), 
        IM_COL32(255, 215, 0, btnHov ? 180 : 120), 8.0f);

    // Button text
    if (g_fontMain) ImGui::PushFont(g_fontMain);
    ImVec2 btnSz = ImGui::CalcTextSize("Create Lifetime Key");
    draw->AddText(ImVec2(btnX + (btnW - btnSz.x) * 0.5f, btnY + (btnH - btnSz.y) * 0.5f),
        IM_COL32(255, 255, 255, 220), "Create Lifetime Key");
    if (g_fontMain) ImGui::PopFont();

    ImGui::SetCursorScreenPos(ImVec2(btnX, btnY));
    if (ImGui::InvisibleButton("##createLifetime", ImVec2(btnW, btnH))) {
        CreateLifetimeKey(g_createLifetimeInput);
    }

    // Status message
    if (!g_createLifetimeStatus.empty()) {
        if (g_fontMain) ImGui::PushFont(g_fontMain);
        ImVec2 statSz = ImGui::CalcTextSize(g_createLifetimeStatus.c_str());
        draw->AddText(
            ImVec2(cX + (cW - statSz.x) * 0.5f, btnY + btnH + 20.0f),
            g_createLifetimeSuccess
                ? IM_COL32(255, 215, 0, 255)
                : IM_COL32(255, 100, 100, 255),
            g_createLifetimeStatus.c_str()
        );
        if (g_fontMain) ImGui::PopFont();
    }

    // Loading animation
    if (g_createLifetimeLoading) {
        float spinCx = cX + cW * 0.5f;
        float spinCy = btnY + btnH * 0.5f;
        
        // Outer ring
        float ringR1 = 16.0f;
        float rAngle = g_animTime * 3.5f;
        for (int i = 0; i < 32; i++) {
            float a    = rAngle + i * (PI * 2.0f / 32.0f);
            float fade = (float)(i + 1) / 32.0f;
            draw->AddCircleFilled(
                ImVec2(spinCx + cosf(a) * ringR1, spinCy + sinf(a) * ringR1),
                2.2f, Accent((int)(fade * 230)), 6
            );
        }
        
        // Crown icon spinning
        if (g_fontIconsBig) ImGui::PushFont(g_fontIconsBig);
        ImVec2 crownSz = ImGui::CalcTextSize(ICON_FA_CROWN);
        float crownBob = sinf(g_animTime * 3.0f) * 3.0f;
        draw->AddText(
            ImVec2(spinCx + 26.0f, spinCy - crownSz.y * 0.5f + crownBob),
            IM_COL32(255, 215, 0, 200), ICON_FA_CROWN
        );
        if (g_fontIconsBig) ImGui::PopFont();
    }
}



// RENDER CHAT TAB
// ============================================================
void RenderChatTab(ImDrawList* draw, float cX, float cY, float cW, float cH) {
    ImGuiIO& io = ImGui::GetIO();
    ImVec2 mp = io.MousePos;

    // Poll messages every 3 seconds
    if (g_animTime - g_lastChatPoll > 3.0f) {
        g_lastChatPoll = g_animTime;
        ChatPollMessages();
    }
    // Poll locked status every 5 seconds
    if (g_animTime - g_lastChatStatusPoll > 5.0f) {
        g_lastChatStatusPoll = g_animTime;
        ChatPollStatus();
    }

    float panelW = 620.0f, panelH = cH - 16;
    float panelX = (cW - panelW) * 0.5f, panelY = cY + 8;
    float inputH = 44.0f, msgAreaH = panelH - inputH - 12;

    // Panel bg
    draw->AddRectFilled(ImVec2(panelX, panelY), ImVec2(panelX + panelW, panelY + panelH),
        IM_COL32(14, 14, 20, 220), 10.0f);
    draw->AddRect(ImVec2(panelX, panelY), ImVec2(panelX + panelW, panelY + panelH),
        IM_COL32(255, 255, 255, 10), 10.0f);

    // Title
    if (g_fontBig) ImGui::PushFont(g_fontBig);
    draw->AddText(ImVec2(panelX + 16, panelY + 8), Accent(220), "Chat");
    if (g_fontBig) ImGui::PopFont();

    // Ticket button (left side of panel, next to title)
    {
        float tbW = 125, tbH = 26;
        float tbX = panelX + 72, tbY = panelY + 8;
        
        bool createHov = (mp.x >= tbX && mp.x <= tbX + tbW && mp.y >= tbY && mp.y <= tbY + tbH);
        draw->AddRectFilled(ImVec2(tbX, tbY), ImVec2(tbX + tbW, tbY + tbH),
            createHov ? Accent(80) : Accent(50), 6.0f);
        draw->AddRect(ImVec2(tbX, tbY), ImVec2(tbX + tbW, tbY + tbH),
            Accent(120), 6.0f);
        
        float padding = 8.0f;
        float iconOffX = 0.0f;
        
        if (g_fontIcons) ImGui::PushFont(g_fontIcons);
        ImVec2 iconSz = ImGui::CalcTextSize(ICON_FA_TICKET);
        if (g_fontIcons) ImGui::PopFont();

        const char* tbText = "Create Ticket";
        ImVec2 txtSz = ImGui::CalcTextSize(tbText);
        
        float totalW = iconSz.x + 4.0f + txtSz.x;
        float startX = tbX + (tbW - totalW) * 0.5f;

        if (g_fontIcons) ImGui::PushFont(g_fontIcons);
        draw->AddText(ImVec2(startX, tbY + (tbH - iconSz.y) * 0.5f),
            IM_COL32(255, 255, 255, 230), ICON_FA_TICKET);
        if (g_fontIcons) ImGui::PopFont();

        draw->AddText(ImVec2(startX + iconSz.x + 4.0f, tbY + (tbH - txtSz.y) * 0.5f),
            IM_COL32(255, 255, 255, 230), tbText);

        if (createHov && ImGui::IsMouseClicked(0)) {
            g_showTicketCreate = !g_showTicketCreate;
            if (g_showTicketCreate) {
                g_ticketViewMode = 0;
                g_ticketListLoaded = false; // Force refresh when opening
            }
        }
    }

    // Ticket status feedback
    if (!g_ticketStatus.empty() && g_animTime - g_ticketStatusTime < 4.0f) {
        if (g_fontMain) ImGui::PushFont(g_fontMain);
        const char* empty = g_ticketStatus.c_str();
        ImVec2 eSz = ImGui::CalcTextSize(empty);
        ImVec2 tsSz = ImGui::CalcTextSize(g_ticketStatus.c_str());
        bool isOk = g_ticketStatus.find("success") != std::string::npos;
        draw->AddText(ImVec2(panelX + (panelW - tsSz.x) * 0.5f, panelY + panelH + 4),
            isOk ? IM_COL32(80, 220, 80, 200) : IM_COL32(220, 80, 80, 200), g_ticketStatus.c_str());
        if (g_fontMain) ImGui::PopFont();
    }

    float msgsTop = panelY + 42;
    float msgsBot = panelY + panelH - inputH - 8;
    float msgsH = msgsBot - msgsTop;

    // Clip messages area
    draw->PushClipRect(ImVec2(panelX + 4, msgsTop), ImVec2(panelX + panelW - 4, msgsBot), true);

    // Render messages
    {
        std::lock_guard<std::mutex> lock(g_chatMutex);
        float lineH = 48.0f;
        float totalH = (float)g_chatMessages.size() * lineH;
        if (totalH < msgsH) totalH = msgsH;

        // Scroll to bottom
        if (g_chatScrollToBottom) {
            g_chatScrollY = totalH - msgsH;
            if (g_chatScrollY < 0) g_chatScrollY = 0;
            g_chatScrollToBottom = false;
        }

        // Mouse wheel scroll in messages area
        if (mp.x >= panelX && mp.x <= panelX + panelW && mp.y >= msgsTop && mp.y <= msgsBot) {
            g_chatScrollY -= io.MouseWheel * 40.0f;
            if (g_chatScrollY < 0) g_chatScrollY = 0;
            float maxScroll = totalH - msgsH;
            if (maxScroll < 0) maxScroll = 0;
            if (g_chatScrollY > maxScroll) g_chatScrollY = maxScroll;
        }

        for (int i = 0; i < (int)g_chatMessages.size(); i++) {
            float yPos = msgsTop + i * lineH - g_chatScrollY;
            if (yPos + lineH < msgsTop || yPos > msgsBot) continue;

            const ChatMsg& m = g_chatMessages[i];
            bool isAdmin = (m.role == "admin");

            // Avatar
            float avR = 14.0f;
            float avCx = panelX + 26, avCy = yPos + lineH * 0.5f;

            int hr, hg, hb;
            if (isAdmin) {
                float t = g_animTime * 2.0f;
                hr = (int)(sinf(t) * 127 + 128);
                hg = (int)(sinf(t + 2.094f) * 127 + 128);
                hb = (int)(sinf(t + 4.189f) * 127 + 128);
            } else {
                unsigned hash = 0;
                for (char c : m.username) hash = hash * 31 + (unsigned)c;
                hr = 80 + (hash % 150); hg = 80 + ((hash / 7) % 150); hb = 80 + ((hash / 13) % 150);
            }

            // Try to render avatar texture if available
            bool avatarRendered = false;
            if (!isAdmin && !m.avatar.empty()) {
                ID3D11ShaderResourceView* avSrv = GetAvatarTexture(m.username, m.avatar);
                if (avSrv) {
                    draw->AddImageRounded((ImTextureID)avSrv,
                        ImVec2(avCx - avR, avCy - avR), ImVec2(avCx + avR, avCy + avR),
                        ImVec2(0, 0), ImVec2(1, 1), IM_COL32(255, 255, 255, 230), avR);
                    avatarRendered = true;
                }
            }

            if (!avatarRendered) {
                draw->AddCircleFilled(ImVec2(avCx, avCy), avR, IM_COL32(hr, hg, hb, 180), 20);
                if (isAdmin) draw->AddCircle(ImVec2(avCx, avCy), avR + 1, IM_COL32(hr, hg, hb, 120), 20, 1.5f);
                char initial[2] = { (char)toupper(m.username[0]), 0 };
                if (g_fontMain) ImGui::PushFont(g_fontMain);
                ImVec2 iSz = ImGui::CalcTextSize(initial);
                draw->AddText(ImVec2(avCx - iSz.x * 0.5f, avCy - iSz.y * 0.5f), IM_COL32(255, 255, 255, 240), initial);
                if (g_fontMain) ImGui::PopFont();
            }

            // Username (RGB cycling for admin)
            if (g_fontMain) ImGui::PushFont(g_fontMain);
            float txX = panelX + 48;
            ImU32 nameCol = isAdmin ? IM_COL32(hr, hg, hb, 255) : IM_COL32(hr, hg, hb, 255);
            draw->AddText(ImVec2(txX, yPos + 4), nameCol, m.username.c_str());

            // Message text
            ImVec2 uSz = ImGui::CalcTextSize(m.username.c_str());
            ImU32 textCol = isAdmin ? IM_COL32(255, 255, 255, 240) : IM_COL32(180, 180, 190, 220);
            draw->AddText(ImVec2(txX + uSz.x + 10, yPos + 4), textCol, m.text.c_str());
            if (g_fontMain) ImGui::PopFont();

            // Separator line
            draw->AddLine(ImVec2(panelX + 12, yPos + lineH - 1), ImVec2(panelX + panelW - 12, yPos + lineH - 1),
                IM_COL32(255, 255, 255, 8));
        }

        if (g_chatMessages.empty()) {
            if (g_fontMain) ImGui::PushFont(g_fontMain);
            const char* empty = "No messages yet. Say something!";
            ImVec2 eSz = ImGui::CalcTextSize(empty);
            draw->AddText(ImVec2(panelX + (panelW - eSz.x) * 0.5f, msgsTop + msgsH * 0.4f), IM_COL32(80, 80, 90, 140), empty);
            if (g_fontMain) ImGui::PopFont();
        }
    }

    draw->PopClipRect();

    // Locked banner
    if (g_chatLocked) {
        if (g_fontMain) ImGui::PushFont(g_fontMain);
        const char* lockMsg = ICON_FA_LOCK "  Chat is locked by admin";
        ImVec2 lmSz = ImGui::CalcTextSize(lockMsg);
        float bannerY = msgsBot + 4;
        draw->AddRectFilled(ImVec2(panelX + 8, bannerY), ImVec2(panelX + panelW - 8, bannerY + inputH - 4),
            IM_COL32(40, 10, 10, 220), 8.0f);
        draw->AddText(ImVec2(panelX + (panelW - lmSz.x) * 0.5f, bannerY + (inputH - 4 - lmSz.y) * 0.5f),
            IM_COL32(220, 60, 60, 220), lockMsg);
        if (g_fontMain) ImGui::PopFont();
    } else {
        // Input area
        float inpX = panelX + 8, inpY = msgsBot + 6, inpW = panelW - 60, inpH2 = inputH - 8;

        ImGui::SetCursorScreenPos(ImVec2(inpX + 8, inpY + 4));
        ImGui::PushItemWidth(inpW - 16);
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.08f, 0.08f, 0.1f, 0.9f));
        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(g_accentColor[0] * 0.3f, g_accentColor[1] * 0.3f, g_accentColor[2] * 0.3f, 0.5f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10, 8));
        bool enter = ImGui::InputText("##chatinput", g_chatInput, sizeof(g_chatInput), ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(2);
        ImGui::PopItemWidth();

        // Send button
        float sendX = panelX + panelW - 44, sendY = inpY + 2, sendSz = inpH2 - 4;
        bool sendHov = (mp.x >= sendX && mp.x <= sendX + sendSz && mp.y >= sendY && mp.y <= sendY + sendSz);
        draw->AddRectFilled(ImVec2(sendX, sendY), ImVec2(sendX + sendSz, sendY + sendSz),
            sendHov ? Accent(80) : Accent(30), 8.0f);
        if (g_fontIcons) ImGui::PushFont(g_fontIcons);
        ImVec2 siSz = ImGui::CalcTextSize(ICON_FA_PAPER_PLANE);
        draw->AddText(ImVec2(sendX + (sendSz - siSz.x) * 0.5f, sendY + (sendSz - siSz.y) * 0.5f),
            sendHov ? AccentBright(255) : Accent(200), ICON_FA_PAPER_PLANE);
        if (g_fontIcons) ImGui::PopFont();

        bool sendClick = sendHov && ImGui::IsMouseClicked(0);
        if ((enter || sendClick) && g_chatInput[0] != 0) {
            ChatSendMessage(g_chatInput);
            g_chatInput[0] = 0;
            g_chatScrollToBottom = true;
        }
    }
    
    // Render ticket chat overlay
    RenderTicketChatOverlay(draw, cX, cY, cW, cH);
}


// ============================================================
// TICKET HELPER: Fetch user's ticket list
// ============================================================
void TicketFetchList() {
    if (g_ticketListPolling) return;
    g_ticketListPolling = true;
    std::string user(g_username);
    std::string jsonBody = "{\"username\":\"" + user + "\"}";
    std::thread([jsonBody]() {
        HttpResponse resp = HttpPost(API_HOST, API_PORT, L"/api/tickets/mine", jsonBody);
        if (resp.success && resp.statusCode == 200) {
            std::vector<TicketListItem> items;
            // Parse JSON array of tickets
            std::string body = resp.body;
            size_t arrStart = body.find("\"tickets\":");
            if (arrStart != std::string::npos) {
                arrStart = body.find('[', arrStart);
                if (arrStart != std::string::npos) {
                    size_t pos = arrStart + 1;
                    while (pos < body.size()) {
                        size_t objStart = body.find('{', pos);
                        if (objStart == std::string::npos) break;
                        size_t objEnd = body.find('}', objStart);
                        if (objEnd == std::string::npos) break;
                        std::string obj = body.substr(objStart, objEnd - objStart + 1);
                        
                        TicketListItem item;
                        // Parse id (integer)
                        std::string idKey = "\"id\":";
                        size_t idPos = obj.find(idKey);
                        if (idPos != std::string::npos) {
                            idPos += idKey.size();
                            item.id = atoi(obj.c_str() + idPos);
                        }
                        // Parse subject
                        item.subject = JsonGetString(obj, "subject");
                        item.status = JsonGetString(obj, "status");
                        item.created_at = JsonGetString(obj, "created_at");
                        
                        // Parse message_count (integer)
                        std::string mcKey = "\"message_count\":";
                        size_t mcPos = obj.find(mcKey);
                        if (mcPos != std::string::npos) {
                            mcPos += mcKey.size();
                            item.message_count = atoi(obj.c_str() + mcPos);
                        } else {
                            item.message_count = 0;
                        }
                        
                        // Parse last_message (nested object)
                        size_t lmPos = obj.find("\"last_message\":");
                        if (lmPos != std::string::npos) {
                            size_t lmObj = obj.find('{', lmPos);
                            if (lmObj != std::string::npos) {
                                size_t lmEnd = obj.find('}', lmObj);
                                if (lmEnd != std::string::npos) {
                                    std::string lm = obj.substr(lmObj, lmEnd - lmObj + 1);
                                    item.last_message_text = JsonGetString(lm, "text");
                                    item.last_message_role = JsonGetString(lm, "role");
                                }
                            }
                        }
                        
                        items.push_back(item);
                        pos = objEnd + 1;
                    }
                }
            }
            g_ticketList = items;
            g_ticketListLoaded = true;
        }
        g_ticketListPolling = false;
    }).detach();
}

// ============================================================
// TICKET HELPER: Poll messages for current ticket
// ============================================================
void TicketPollMessages() {
    if (g_currentTicketId.empty()) return;
    std::string user(g_username);
    std::string ticketId = g_currentTicketId;
    std::string jsonBody = "{\"username\":\"" + user + "\",\"ticket_id\":\"" + ticketId + "\"}";
    std::thread([jsonBody]() {
        HttpResponse resp = HttpPost(API_HOST, API_PORT, L"/api/tickets/messages", jsonBody);
        if (resp.success && resp.statusCode == 200) {
            // Parse messages array from ticket object
            std::string body = resp.body;
            size_t msgsStart = body.find("\"messages\":");
            if (msgsStart != std::string::npos) {
                msgsStart = body.find('[', msgsStart);
                if (msgsStart != std::string::npos) {
                    std::vector<TicketMsg> msgs;
                    size_t pos = msgsStart + 1;
                    while (pos < body.size()) {
                        size_t objStart = body.find('{', pos);
                        if (objStart == std::string::npos) break;
                        // Find matching closing brace
                        size_t objEnd = body.find('}', objStart);
                        if (objEnd == std::string::npos) break;
                        std::string obj = body.substr(objStart, objEnd - objStart + 1);
                        
                        TicketMsg m;
                        m.username = JsonGetString(obj, "from");
                        m.text = JsonGetString(obj, "text");
                        m.role = JsonGetString(obj, "role");
                        m.timestamp = JsonGetString(obj, "time");
                        msgs.push_back(m);
                        
                        pos = objEnd + 1;
                    }
                    // Only update if message count changed
                    if (msgs.size() != g_ticketChatMessages.size()) {
                        g_ticketChatMessages = msgs;
                        g_ticketScrollToBottom = true;
                    }
                }
            }
        }
    }).detach();
}

// ============================================================
// TICKET CHAT OVERLAY (List + Chat views)
// ============================================================
void RenderTicketChatOverlay(ImDrawList* draw, float cX, float cY, float cW, float cH) {
    if (!g_showTicketCreate) return;
    
    ImGuiIO& io = ImGui::GetIO();
    ImVec2 mp = io.MousePos;
    
    float ovW = 700, ovH = 500;
    float ovX = cX + (cW - ovW) * 0.5f, ovY = cY + (cH - ovH) * 0.5f;

    // Dim background
    draw->AddRectFilled(ImVec2(0, 0), ImVec2(io.DisplaySize.x, io.DisplaySize.y), IM_COL32(0, 0, 0, 150));
    
    // Panel
    draw->AddRectFilled(ImVec2(ovX, ovY), ImVec2(ovX + ovW, ovY + ovH), IM_COL32(14, 14, 20, 240), 12.0f);
    draw->AddRect(ImVec2(ovX, ovY), ImVec2(ovX + ovW, ovY + ovH), Accent(30), 12.0f);

    // Close X button
    {
        float xBtnX = ovX + ovW - 36, xBtnY = ovY + 10;
        bool xHov = (mp.x >= xBtnX && mp.x <= xBtnX + 26 && mp.y >= xBtnY && mp.y <= xBtnY + 26);
        if (xHov) draw->AddRectFilled(ImVec2(xBtnX, xBtnY), ImVec2(xBtnX + 26, xBtnY + 26), IM_COL32(255, 60, 60, 40), 6.0f);
        if (g_fontIcons) ImGui::PushFont(g_fontIcons);
        ImVec2 xSz = ImGui::CalcTextSize(ICON_FA_XMARK);
        draw->AddText(ImVec2(xBtnX + (26 - xSz.x) * 0.5f, xBtnY + (26 - xSz.y) * 0.5f),
            xHov ? IM_COL32(255, 100, 100, 255) : IM_COL32(180, 180, 180, 180), ICON_FA_XMARK);
        if (g_fontIcons) ImGui::PopFont();
        if (xHov && ImGui::IsMouseClicked(0)) {
            g_showTicketCreate = false;
            g_ticketViewMode = 0;
            return;
        }
    }

    // ======== TICKET LIST VIEW ========
    if (g_ticketViewMode == 0) {
        // Fetch list if not loaded
        if (!g_ticketListLoaded && !g_ticketListPolling) {
            TicketFetchList();
        }
        // Periodic refresh every 10s
        if (g_ticketListLoaded && g_animTime - g_lastTicketListPoll > 10.0f) {
            g_lastTicketListPoll = g_animTime;
            TicketFetchList();
        }

        // Title
        if (g_fontBig) ImGui::PushFont(g_fontBig);
        draw->AddText(ImVec2(ovX + 24, ovY + 14), IM_COL32(255, 255, 255, 230), ICON_FA_TICKET);
        ImVec2 titleIconSz = ImGui::CalcTextSize(ICON_FA_TICKET);
        draw->AddText(ImVec2(ovX + 24 + titleIconSz.x + 10, ovY + 14), IM_COL32(255, 255, 255, 230), "Support Tickets");
        if (g_fontBig) ImGui::PopFont();
        draw->AddLine(ImVec2(ovX + 20, ovY + 50), ImVec2(ovX + ovW - 20, ovY + 50), Accent(40));

        // "New Ticket" button
        {
            float nbW = 130, nbH = 30;
            float nbX = ovX + ovW - nbW - 50, nbY = ovY + 14;
            bool nbHov = (mp.x >= nbX && mp.x <= nbX + nbW && mp.y >= nbY && mp.y <= nbY + nbH);
            draw->AddRectFilled(ImVec2(nbX, nbY), ImVec2(nbX + nbW, nbY + nbH),
                nbHov ? Accent(120) : Accent(80), 8.0f);
            if (g_fontMain) ImGui::PushFont(g_fontMain);
            const char* nbLabel = ICON_FA_PLUS "  New Ticket";
            ImVec2 nbSz = ImGui::CalcTextSize(nbLabel);
            draw->AddText(ImVec2(nbX + (nbW - nbSz.x) * 0.5f, nbY + (nbH - nbSz.y) * 0.5f),
                IM_COL32(255, 255, 255, 240), nbLabel);
            if (g_fontMain) ImGui::PopFont();
            if (nbHov && ImGui::IsMouseClicked(0)) {
                g_currentTicketId = "";
                g_ticketChatMessages.clear();
                g_ticketViewMode = 1;
            }
        }

        // Ticket list area
        float listTop = ovY + 58;
        float listBot = ovY + ovH - 12;
        float listH = listBot - listTop;
        
        draw->PushClipRect(ImVec2(ovX + 8, listTop), ImVec2(ovX + ovW - 8, listBot), true);
        
        if (g_ticketList.empty()) {
            if (g_fontMain) ImGui::PushFont(g_fontMain);
            const char* emptyMsg = "No tickets yet. Click 'New Ticket' to create one.";
            ImVec2 eSz = ImGui::CalcTextSize(emptyMsg);
            draw->AddText(ImVec2(ovX + (ovW - eSz.x) * 0.5f, listTop + listH * 0.4f),
                IM_COL32(100, 100, 110, 160), emptyMsg);
            if (g_fontMain) ImGui::PopFont();
        } else {
            float itemH = 70.0f;
            for (int i = 0; i < (int)g_ticketList.size(); i++) {
                const TicketListItem& t = g_ticketList[i];
                float iy = listTop + i * (itemH + 6);
                if (iy + itemH < listTop || iy > listBot) continue;
                
                float ix = ovX + 20, iw = ovW - 40;
                bool iHov = (mp.x >= ix && mp.x <= ix + iw && mp.y >= iy && mp.y <= iy + itemH);
                
                // Card background
                draw->AddRectFilled(ImVec2(ix, iy), ImVec2(ix + iw, iy + itemH),
                    iHov ? IM_COL32(30, 30, 40, 220) : IM_COL32(20, 20, 28, 200), 8.0f);
                draw->AddRect(ImVec2(ix, iy), ImVec2(ix + iw, iy + itemH),
                    iHov ? Accent(60) : IM_COL32(255, 255, 255, 10), 8.0f);
                
                // Status badge
                bool isOpen = (t.status == "open");
                ImU32 statusCol = isOpen ? IM_COL32(60, 200, 80, 220) : IM_COL32(180, 60, 60, 220);
                const char* statusText = isOpen ? "OPEN" : "CLOSED";
                if (g_fontMain) ImGui::PushFont(g_fontMain);
                ImVec2 stSz = ImGui::CalcTextSize(statusText);
                float badgeX = ix + iw - stSz.x - 24, badgeY = iy + 10;
                draw->AddRectFilled(ImVec2(badgeX - 4, badgeY - 2), ImVec2(badgeX + stSz.x + 4, badgeY + stSz.y + 2),
                    statusCol & 0x40FFFFFF, 4.0f);
                draw->AddText(ImVec2(badgeX, badgeY), statusCol, statusText);
                
                // Subject
                if (g_fontBig) ImGui::PushFont(g_fontBig);
                draw->AddText(ImVec2(ix + 16, iy + 8), IM_COL32(230, 230, 240, 230), t.subject.c_str());
                if (g_fontBig) ImGui::PopFont();
                
                // Last message preview
                std::string preview;
                if (!t.last_message_text.empty()) {
                    std::string prefix = (t.last_message_role == "admin") ? "Admin: " : "You: ";
                    preview = prefix + t.last_message_text;
                    if (preview.size() > 80) preview = preview.substr(0, 77) + "...";
                } else {
                    preview = "No messages";
                }
                draw->AddText(ImVec2(ix + 16, iy + 34), IM_COL32(140, 140, 150, 180), preview.c_str());
                
                // Message count + date
                char info[128];
                sprintf_s(info, "%d messages", t.message_count);
                draw->AddText(ImVec2(ix + 16, iy + 52), IM_COL32(90, 90, 100, 140), info);
                if (g_fontMain) ImGui::PopFont();
                
                // Click to open
                if (iHov && ImGui::IsMouseClicked(0)) {
                    g_currentTicketId = std::to_string(t.id);
                    g_ticketChatMessages.clear();
                    g_ticketViewMode = 1;
                    g_ticketScrollToBottom = true;
                    g_lastTicketPoll = 0.0f; // Force immediate poll
                }
            }
        }
        draw->PopClipRect();

    // ======== TICKET CHAT VIEW ========
    } else {
        // Poll messages every 5 seconds
        if (!g_currentTicketId.empty() && g_animTime - g_lastTicketPoll > 5.0f) {
            g_lastTicketPoll = g_animTime;
            TicketPollMessages();
        }
        // Initial poll when entering chat
        if (!g_currentTicketId.empty() && g_lastTicketPoll == 0.0f) {
            g_lastTicketPoll = g_animTime;
            TicketPollMessages();
        }

        // Title bar with back button
        {
            float bkW = 28, bkH = 28;
            float bkX = ovX + 16, bkY = ovY + 12;
            bool bkHov = (mp.x >= bkX && mp.x <= bkX + bkW && mp.y >= bkY && mp.y <= bkY + bkH);
            if (bkHov) draw->AddRectFilled(ImVec2(bkX, bkY), ImVec2(bkX + bkW, bkY + bkH), Accent(40), 6.0f);
            if (g_fontIcons) ImGui::PushFont(g_fontIcons);
            ImVec2 bkSz = ImGui::CalcTextSize(ICON_FA_ARROW_LEFT);
            draw->AddText(ImVec2(bkX + (bkW - bkSz.x) * 0.5f, bkY + (bkH - bkSz.y) * 0.5f),
                bkHov ? AccentBright(255) : Accent(180), ICON_FA_ARROW_LEFT);
            if (g_fontIcons) ImGui::PopFont();
            if (bkHov && ImGui::IsMouseClicked(0)) {
                g_ticketViewMode = 0;
                g_ticketListLoaded = false; // Refresh list
                return;
            }
        }

        if (g_fontBig) ImGui::PushFont(g_fontBig);
        const char* chatTitle = g_currentTicketId.empty() ? "New Ticket" : "Ticket Chat";
        draw->AddText(ImVec2(ovX + 52, ovY + 14), IM_COL32(255, 255, 255, 230), chatTitle);
        if (g_fontBig) ImGui::PopFont();
        
        // Ticket ID display
        if (!g_currentTicketId.empty()) {
            if (g_fontMain) ImGui::PushFont(g_fontMain);
            std::string idLabel = "#" + g_currentTicketId;
            draw->AddText(ImVec2(ovX + 200, ovY + 18), Accent(160), idLabel.c_str());
            if (g_fontMain) ImGui::PopFont();
        }
        
        draw->AddLine(ImVec2(ovX + 20, ovY + 50), ImVec2(ovX + ovW - 20, ovY + 50), Accent(40));

        // Messages area
        float msgsTop = ovY + 58;
        float msgsBot = ovY + ovH - 60;
        float msgsH = msgsBot - msgsTop;

        draw->PushClipRect(ImVec2(ovX + 12, msgsTop), ImVec2(ovX + ovW - 12, msgsBot), true);

        if (g_ticketChatMessages.empty()) {
            if (g_fontMain) ImGui::PushFont(g_fontMain);
            const char* hint1 = "Start a conversation with the admin...";
            const char* hint2 = "Type your message below and press Enter or Send";
            ImVec2 h1Sz = ImGui::CalcTextSize(hint1);
            ImVec2 h2Sz = ImGui::CalcTextSize(hint2);
            draw->AddText(ImVec2(ovX + (ovW - h1Sz.x) * 0.5f, msgsTop + msgsH * 0.35f), IM_COL32(120, 120, 130, 180), hint1);
            draw->AddText(ImVec2(ovX + (ovW - h2Sz.x) * 0.5f, msgsTop + msgsH * 0.35f + 24), IM_COL32(80, 80, 90, 140), hint2);
            if (g_fontMain) ImGui::PopFont();
        } else {
            float lineH = 52.0f;
            float totalH = (float)g_ticketChatMessages.size() * lineH;
            if (totalH < msgsH) totalH = msgsH;

            // Scroll to bottom
            if (g_ticketScrollToBottom) {
                g_ticketScrollY = totalH - msgsH;
                if (g_ticketScrollY < 0) g_ticketScrollY = 0;
                g_ticketScrollToBottom = false;
            }

            // Mouse wheel scroll
            if (mp.x >= ovX && mp.x <= ovX + ovW && mp.y >= msgsTop && mp.y <= msgsBot) {
                g_ticketScrollY -= io.MouseWheel * 40.0f;
                if (g_ticketScrollY < 0) g_ticketScrollY = 0;
                float maxScroll = totalH - msgsH;
                if (maxScroll < 0) maxScroll = 0;
                if (g_ticketScrollY > maxScroll) g_ticketScrollY = maxScroll;
            }

            for (int i = 0; i < (int)g_ticketChatMessages.size(); i++) {
                float yPos = msgsTop + i * lineH - g_ticketScrollY;
                if (yPos + lineH < msgsTop || yPos > msgsBot) continue;

                const TicketMsg& m = g_ticketChatMessages[i];
                bool isAdmin = (m.role == "admin");

                // Avatar circle
                float avR = 14.0f;
                float avCx = ovX + 36, avCy = yPos + lineH * 0.5f;
                ImU32 avCol = isAdmin ? IM_COL32(255, 100, 50, 200) : Accent(180);
                draw->AddCircleFilled(ImVec2(avCx, avCy), avR, avCol, 20);
                
                // Initial letter
                if (g_fontMain) ImGui::PushFont(g_fontMain);
                char initial[2] = { isAdmin ? 'A' : (char)toupper(m.username.empty() ? '?' : m.username[0]), 0 };
                ImVec2 iSz = ImGui::CalcTextSize(initial);
                draw->AddText(ImVec2(avCx - iSz.x * 0.5f, avCy - iSz.y * 0.5f), IM_COL32(255, 255, 255, 240), initial);

                // Name
                float txX = ovX + 58;
                const char* displayName = isAdmin ? "Admin" : (m.username.empty() ? "You" : m.username.c_str());
                ImU32 nameCol = isAdmin ? IM_COL32(255, 140, 80, 255) : AccentBright(255);
                draw->AddText(ImVec2(txX, yPos + 6), nameCol, displayName);

                // Message text
                draw->AddText(ImVec2(txX, yPos + 24), IM_COL32(200, 200, 210, 220), m.text.c_str());
                
                // Timestamp
                if (!m.timestamp.empty()) {
                    ImVec2 tsSz = ImGui::CalcTextSize(m.timestamp.c_str());
                    draw->AddText(ImVec2(ovX + ovW - tsSz.x - 30, yPos + 6), IM_COL32(80, 80, 90, 120), m.timestamp.c_str());
                }
                if (g_fontMain) ImGui::PopFont();

                // Separator
                draw->AddLine(ImVec2(ovX + 24, yPos + lineH - 1), ImVec2(ovX + ovW - 24, yPos + lineH - 1),
                    IM_COL32(255, 255, 255, 6));
            }
        }

        draw->PopClipRect();

        // Input area at bottom
        float inpY = ovY + ovH - 52;
        float inpX = ovX + 20;
        float inpW = ovW - 100;

        ImGui::SetCursorScreenPos(ImVec2(inpX, inpY));
        ImGui::PushItemWidth(inpW);
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.08f, 0.08f, 0.1f, 0.9f));
        ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.12f, 0.12f, 0.14f, 0.9f));
        ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(g_accentColor[0] * 0.3f, g_accentColor[1] * 0.3f, g_accentColor[2] * 0.3f, 0.5f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(10, 8));
        bool enter = ImGui::InputText("##ticketMsgInput", g_ticketMessage, sizeof(g_ticketMessage), ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(3);
        ImGui::PopItemWidth();

        // Send button
        float sendX = ovX + ovW - 70, sendY = inpY, sendW = 50, sendH = 32;
        bool sendHov = (mp.x >= sendX && mp.x <= sendX + sendW && mp.y >= sendY && mp.y <= sendY + sendH);
        draw->AddRectFilled(ImVec2(sendX, sendY), ImVec2(sendX + sendW, sendY + sendH),
            sendHov ? Accent(120) : Accent(60), 8.0f);
        if (g_fontIcons) ImGui::PushFont(g_fontIcons);
        ImVec2 siSz = ImGui::CalcTextSize(ICON_FA_PAPER_PLANE);
        draw->AddText(ImVec2(sendX + (sendW - siSz.x) * 0.5f, sendY + (sendH - siSz.y) * 0.5f),
            sendHov ? IM_COL32(255, 255, 255, 255) : IM_COL32(220, 220, 230, 220), ICON_FA_PAPER_PLANE);
        if (g_fontIcons) ImGui::PopFont();

        bool sendClick = sendHov && ImGui::IsMouseClicked(0);
        if ((enter || sendClick) && g_ticketMessage[0] != 0) {
            TicketSendMessage(g_ticketMessage);
            g_ticketMessage[0] = 0;
            g_ticketScrollToBottom = true;
        }
    }

    // Ticket status feedback
    if (!g_ticketStatus.empty() && g_animTime - g_ticketStatusTime < 4.0f) {
        if (g_fontMain) ImGui::PushFont(g_fontMain);
        ImVec2 tsSz = ImGui::CalcTextSize(g_ticketStatus.c_str());
        bool isOk = g_ticketStatus.find("success") != std::string::npos;
        draw->AddText(ImVec2(ovX + (ovW - tsSz.x) * 0.5f, ovY + ovH + 8),
            isOk ? IM_COL32(80, 220, 80, 200) : IM_COL32(220, 80, 80, 200), g_ticketStatus.c_str());
        if (g_fontMain) ImGui::PopFont();
    }

    // Close when clicking outside the panel
    bool insidePanel = (mp.x >= ovX && mp.x <= ovX + ovW && mp.y >= ovY && mp.y <= ovY + ovH);
    if (!insidePanel && ImGui::IsMouseClicked(0)) {
        g_showTicketCreate = false;
        g_ticketViewMode = 0;
    }
}

void TicketSendMessage(const char* message) {
    if (g_currentTicketId.empty()) {
        // No ticket yet, create one automatically
        TicketCreate("Support Request", message);
        return;
    }
    
    std::string ticketId = g_currentTicketId;
    std::string user(g_username);
    std::string msgText(message);
    std::string jsonBody = "{\"username\":\"" + user + "\",\"ticket_id\":" + ticketId + ",\"message\":\"" + msgText + "\"}";
    std::thread([jsonBody, user, msgText]() {
        HttpResponse resp = HttpPost(API_HOST, API_PORT, L"/api/tickets/reply", jsonBody);
        if (resp.success && resp.statusCode == 200) {
            // Add message locally for immediate feedback
            TicketMsg msg;
            msg.username = user.empty() ? "Guest" : user;
            msg.text = msgText;
            msg.role = "user";
            msg.timestamp = "now";
            g_ticketChatMessages.push_back(msg);
            g_ticketScrollToBottom = true;
        }
    }).detach();
}


// ============================================================
// D3D11 HELPERS
// ============================================================
bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createFlags = 0;
    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        createFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
        &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (hr == DXGI_ERROR_UNSUPPORTED)
        hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr,
            createFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain,
            &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext);
    if (FAILED(hr)) return false;

    ID3D11Texture2D* pBackBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (pBackBuffer) {
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
        pBackBuffer->Release();
    }
    return true;
}

void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

void CreateRenderTarget() {
    ID3D11Texture2D* pBackBuffer = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    if (pBackBuffer) {
        g_pd3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
        pBackBuffer->Release();
    }
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    // ── FIX: Dead keys (´ ~ ^ `) must NEVER be consumed by ImGui.
    // If ImGui returns true for WM_DEADCHAR, DefWindowProc never runs,
    // the Windows dead-key composition state gets corrupted system-wide.
    if (msg == WM_DEADCHAR    || msg == WM_SYSDEADCHAR  ||
        msg == WM_IME_CHAR    || msg == WM_IME_COMPOSITION ||
        msg == WM_IME_SETCONTEXT)
        return DefWindowProc(hWnd, msg, wParam, lParam);

    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED) return 0;
        g_ResizeWidth = LOWORD(lParam);
        g_ResizeHeight = HIWORD(lParam);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    case WM_GETMINMAXINFO: {
        LPMINMAXINFO lpMMI = (LPMINMAXINFO)lParam;
        lpMMI->ptMinTrackSize.x = 900;
        lpMMI->ptMinTrackSize.y = 600;
        return 0;
    }
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

// ============================================================
// CUSTOM STYLED INPUT
// ============================================================
bool StyledInputText(const char* label, char* buf, size_t bufSize, const char* hint, bool isPassword = false) {
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(16, 12));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.07f, 0.07f, 0.10f, 0.95f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.10f, 0.09f, 0.13f, 0.95f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgActive, ImVec4(0.12f, 0.09f, 0.06f, 0.98f));
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(g_accentColor[0], g_accentColor[1], g_accentColor[2], 0.55f));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.2f);

    ImGuiInputTextFlags flags = 0;
    if (isPassword) flags |= ImGuiInputTextFlags_Password;

    float availW = ImGui::GetContentRegionAvail().x;
    ImGui::SetNextItemWidth(availW);
    bool result = ImGui::InputTextWithHint(label, hint, buf, bufSize, flags);

    ImGui::PopStyleVar(3);
    ImGui::PopStyleColor(4);
    return result;
}

bool StyledButton(const char* label, ImVec2 size) {
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 12.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(g_accentColor[0] * 0.85f, g_accentColor[1] * 0.85f, g_accentColor[2] * 0.85f, 0.95f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(g_accentColor[0], g_accentColor[1] + 0.05f, g_accentColor[2] + 0.02f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(g_accentColor[0] * 0.75f, g_accentColor[1] * 0.75f, g_accentColor[2] * 0.75f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));

    bool result = ImGui::Button(label, size);

    ImGui::PopStyleColor(4);
    ImGui::PopStyleVar(2);
    return result;
}

// ============================================================
// Helper: center cursor for an item of given width
// ============================================================
void CenterCursorX(float itemWidth) {
    float availW = ImGui::GetContentRegionAvail().x;
    float offset = (availW - itemWidth) * 0.5f;
    if (offset > 0.0f)
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + offset);
}

// ============================================================
// TITLE BAR with minimize/maximize/close + drag
// ============================================================
void RenderTitleBar(ImDrawList* draw, float screenW) {
    float barH = 38.0f;
    float btnSize = 28.0f;
    float btnY = 5.0f;

    // Title bar background with gradient
    draw->AddRectFilledMultiColor(
        ImVec2(0, 0), ImVec2(screenW, barH),
        IM_COL32(10, 10, 14, 252), IM_COL32(10, 10, 14, 252),
        IM_COL32(16, 16, 22, 252), IM_COL32(16, 16, 22, 252)
    );
    // Bottom accent line (glow)
    draw->AddRectFilled(ImVec2(0, barH - 1), ImVec2(screenW, barH), Accent(80));
    draw->AddRectFilled(ImVec2(0, barH - 2), ImVec2(screenW, barH - 1), Accent(30));

    // Icon + Title text
    if (g_fontIcons) ImGui::PushFont(g_fontIcons);
    ImVec2 iconSz = ImGui::CalcTextSize(ICON_FA_BOLT);
    draw->AddText(ImVec2(12, (barH - iconSz.y) * 0.5f), Accent(220), ICON_FA_BOLT);
    if (g_fontIcons) ImGui::PopFont();
    float titleX = 12 + iconSz.x + 6;
    draw->AddText(ImVec2(titleX, (barH - 14) * 0.5f), IM_COL32(220, 220, 230, 240), "LiKinho Executor");

    // Window control buttons (right side)
    float btnX = screenW - 3 * (btnSize + 4) - 8;
    ImVec2 mousePos = ImGui::GetIO().MousePos;
    bool clicked = ImGui::IsMouseClicked(0);

    // --- MINIMIZE ---
    ImVec2 minP(btnX, btnY);
    ImVec2 minP2(btnX + btnSize, btnY + btnSize);
    bool minHover = (mousePos.x >= minP.x && mousePos.x <= minP2.x && mousePos.y >= minP.y && mousePos.y <= minP2.y);
    draw->AddRectFilled(minP, minP2, minHover ? IM_COL32(50, 50, 60, 220) : IM_COL32(0, 0, 0, 0), 6.0f);
    draw->AddLine(ImVec2(btnX + 8, btnY + btnSize * 0.5f), ImVec2(btnX + btnSize - 8, btnY + btnSize * 0.5f),
        minHover ? IM_COL32(255, 255, 255, 255) : IM_COL32(160, 160, 170, 200), 1.5f);
    if (minHover && clicked) ShowWindow(g_hWnd, SW_MINIMIZE);

    // --- MAXIMIZE ---
    btnX += btnSize + 4;
    ImVec2 maxP(btnX, btnY);
    ImVec2 maxP2(btnX + btnSize, btnY + btnSize);
    bool maxHover = (mousePos.x >= maxP.x && mousePos.x <= maxP2.x && mousePos.y >= maxP.y && mousePos.y <= maxP2.y);
    draw->AddRectFilled(maxP, maxP2, maxHover ? IM_COL32(50, 50, 60, 220) : IM_COL32(0, 0, 0, 0), 6.0f);
    draw->AddRect(ImVec2(btnX + 8, btnY + 7), ImVec2(btnX + btnSize - 8, btnY + btnSize - 7),
        maxHover ? IM_COL32(255, 255, 255, 255) : IM_COL32(160, 160, 170, 200), 2.0f, 0, 1.5f);
    if (maxHover && clicked) {
        WINDOWPLACEMENT wp = {}; wp.length = sizeof(wp);
        GetWindowPlacement(g_hWnd, &wp);
        ShowWindow(g_hWnd, wp.showCmd == SW_MAXIMIZE ? SW_RESTORE : SW_MAXIMIZE);
    }

    // --- CLOSE ---
    btnX += btnSize + 4;
    ImVec2 clsP(btnX, btnY);
    ImVec2 clsP2(btnX + btnSize, btnY + btnSize);
    bool clsHover = (mousePos.x >= clsP.x && mousePos.x <= clsP2.x && mousePos.y >= clsP.y && mousePos.y <= clsP2.y);
    draw->AddRectFilled(clsP, clsP2, clsHover ? IM_COL32(210, 45, 45, 240) : IM_COL32(0, 0, 0, 0), 6.0f);
    draw->AddLine(ImVec2(btnX + 9, btnY + 8), ImVec2(btnX + btnSize - 9, btnY + btnSize - 8),
        clsHover ? IM_COL32(255, 255, 255, 255) : IM_COL32(160, 160, 170, 200), 1.5f);
    draw->AddLine(ImVec2(btnX + btnSize - 9, btnY + 8), ImVec2(btnX + 9, btnY + btnSize - 8),
        clsHover ? IM_COL32(255, 255, 255, 255) : IM_COL32(160, 160, 170, 200), 1.5f);
    if (clsHover && clicked) PostMessage(g_hWnd, WM_CLOSE, 0, 0);

    // --- DRAG (click on bar area, not on buttons) ---
    bool onButtons = minHover || maxHover || clsHover;
    bool onBar = (mousePos.y >= 0 && mousePos.y <= barH && !onButtons);

    if (onBar && ImGui::IsMouseClicked(0)) {
        g_isDragging = true;
        GetCursorPos(&g_dragStart);
        RECT rc; GetWindowRect(g_hWnd, &rc);
        g_dragStart.x -= rc.left;
        g_dragStart.y -= rc.top;
    }
    if (g_isDragging) {
        if (ImGui::IsMouseDown(0)) {
            POINT cur; GetCursorPos(&cur);
            SetWindowPos(g_hWnd, nullptr, cur.x - g_dragStart.x, cur.y - g_dragStart.y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
        } else {
            g_isDragging = false;
        }
    }
}

// ============================================================
// RENDER LOGIN/REGISTER UI
// ============================================================
void RenderLoginUI() {
    ImGuiIO& io = ImGui::GetIO();
    float screenW = io.DisplaySize.x;
    float screenH = io.DisplaySize.y;

    // === FULLSCREEN BACKGROUND ===
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::Begin("##bg", nullptr, 
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus |
        ImGuiWindowFlags_NoNav);
    ImGui::PopStyleVar();

    ImDrawList* bgDraw = ImGui::GetWindowDrawList();

    // Draw background image
    if (g_pBackgroundSRV) {
        bgDraw->AddImage((ImTextureID)g_pBackgroundSRV,
            ImVec2(0, 0), ImVec2(screenW, screenH));
    } else {
        bgDraw->AddRectFilledMultiColor(ImVec2(0, 0), ImVec2(screenW, screenH),
            IM_COL32(10, 8, 5, 255), IM_COL32(15, 10, 5, 255),
            IM_COL32(20, 12, 5, 255), IM_COL32(8, 5, 3, 255));
    }

    // Dark overlay
    bgDraw->AddRectFilled(ImVec2(0, 0), ImVec2(screenW, screenH), IM_COL32(0, 0, 0, 120));

    // Bubbles
    UpdateAndDrawBubbles(bgDraw, io.DeltaTime, screenW, screenH);

    // Title bar
    RenderTitleBar(bgDraw, screenW);

    // === BOTTOM MUSIC BAR (on login screen) ===
    {
        float botH = 44.0f, botMargin = 10.0f;
        float botBarY = screenH - botH - botMargin;
        float botBarX = botMargin, botBarW = screenW - botMargin * 2, botR2 = 10.0f;
        bgDraw->AddRectFilled(ImVec2(botBarX + 2, botBarY + 2), ImVec2(botBarX + botBarW - 2, botBarY + botH + 2), IM_COL32(0, 0, 0, 50), botR2);
        bgDraw->AddRectFilled(ImVec2(botBarX, botBarY), ImVec2(botBarX + botBarW, botBarY + botH), IM_COL32(14, 14, 20, 220), botR2);
        bgDraw->AddRect(ImVec2(botBarX, botBarY), ImVec2(botBarX + botBarW, botBarY + botH), IM_COL32(255, 255, 255, 12), botR2, 0, 1.0f);
        DrawMusicControlsInline(bgDraw, botBarX, botBarY, botBarW, botH);
    }

    ImGui::End();

    // === LOGIN CARD ===
    float padding = 38.0f;
    float cardW = 440.0f;
    float logoDisplayH = 130.0f;
    float cardH = g_showLogin ? (logoDisplayH + 330.0f) : (logoDisplayH + 420.0f);

    // Smooth card height transition
    static float animCardH = 420.0f;
    animCardH += (cardH - animCardH) * io.DeltaTime * 8.0f;

    // ── Slide-in + fade-in on first render ───────────────────────────────
    g_cardSlideY -= g_cardSlideY * io.DeltaTime * 7.0f;
    g_cardAlpha   = fminf(g_cardAlpha + io.DeltaTime * 2.8f, 1.0f);

    float baseX = (screenW - cardW) * 0.5f;
    float baseY = (screenH - animCardH) * 0.5f + g_cardSlideY;

    ImGui::SetNextWindowPos(ImVec2(baseX, baseY));
    ImGui::SetNextWindowSize(ImVec2(cardW, animCardH));

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 22.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(padding, 22));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 1.5f);
    ImGui::PushStyleColor(ImGuiCol_WindowBg,
        ImVec4(0.04f, 0.04f, 0.07f, 0.97f * g_cardAlpha));
    ImGui::PushStyleColor(ImGuiCol_Border,
        ImVec4(g_accentColor[0], g_accentColor[1], g_accentColor[2], 0.50f * g_cardAlpha));

    ImGui::Begin("##logincard", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings);

    ImDrawList* cardDraw = ImGui::GetWindowDrawList();
    ImVec2 cardPos  = ImGui::GetWindowPos();
    ImVec2 cardSize = ImGui::GetWindowSize();
    float contentW  = cardW - padding * 2.0f;

    // === TOP ACCENT GLOW — triple layer ═══════════════════════════════════
    float glowPulse = 0.65f + 0.35f * sinf(g_animTime * 2.2f);
    int acR = (int)(g_accentColor[0]*255);
    int acG = (int)(g_accentColor[1]*255);
    int acB = (int)(g_accentColor[2]*255);
    // Outer soft halo
    cardDraw->AddRectFilled(
        ImVec2(cardPos.x - 2, cardPos.y - 4),
        ImVec2(cardPos.x + cardSize.x + 2, cardPos.y + 12),
        IM_COL32(acR, acG, acB, (int)(30 * glowPulse * g_cardAlpha)),
        22.0f, ImDrawCornerFlags_Top
    );
    // Middle glow
    cardDraw->AddRectFilled(
        ImVec2(cardPos.x + 4, cardPos.y + 1),
        ImVec2(cardPos.x + cardSize.x - 4, cardPos.y + 8),
        IM_COL32(acR, acG, acB, (int)(60 * glowPulse * g_cardAlpha)),
        20.0f, ImDrawCornerFlags_Top
    );
    // Inner bright line
    cardDraw->AddRectFilled(
        ImVec2(cardPos.x + 1, cardPos.y + 1),
        ImVec2(cardPos.x + cardSize.x - 1, cardPos.y + 5),
        IM_COL32(acR, (int)(acG*0.47f), (int)(acB*0.04f), (int)(230 * glowPulse * g_cardAlpha)),
        20.0f, ImDrawCornerFlags_Top
    );

    // Shimmer sweep across card top
    {
        float sweep = fmodf(g_animTime * 0.35f, 1.0f);
        float sx    = cardPos.x + sweep * (cardSize.x + 80.0f) - 40.0f;
        cardDraw->PushClipRect(ImVec2(cardPos.x, cardPos.y), ImVec2(cardPos.x + cardSize.x, cardPos.y + 5), true);
        cardDraw->AddRectFilledMultiColor(
            ImVec2(sx, cardPos.y), ImVec2(sx + 60, cardPos.y + 5),
            IM_COL32(255,255,255,0), IM_COL32(255,255,255,(int)(80*g_cardAlpha)),
            IM_COL32(255,255,255,(int)(80*g_cardAlpha)), IM_COL32(255,255,255,0)
        );
        cardDraw->PopClipRect();
    }

    // === LOGO (sem brilho) ════════════════════════════════════════
    ImGui::Dummy(ImVec2(0, 6));
    if (g_pLogoSRV && g_logoWidth > 0 && g_logoHeight > 0) {
        float maxH   = 110.0f;
        float aspect = (float)g_logoWidth / (float)g_logoHeight;
        float logoH  = maxH;
        float logoW  = logoH * aspect;
        if (logoW > contentW) { logoW = contentW; logoH = logoW / aspect; }

        CenterCursorX(logoW);
        ImVec2 logoPos = ImGui::GetCursorScreenPos();
        
        // Apenas a imagem do logo, sem efeitos
        cardDraw->AddImage(
            (ImTextureID)g_pLogoSRV, logoPos,
            ImVec2(logoPos.x + logoW, logoPos.y + logoH),
            ImVec2(0,0), ImVec2(1,1),
            IM_COL32(255, 255, 255, (int)(255 * g_cardAlpha))
        );
        ImGui::Dummy(ImVec2(logoW, logoH));
    }

    ImGui::Dummy(ImVec2(0, 8));

    // === TITLE with shimmer ═══════════════════════════════════════════════
    {
        const char* title = g_showLogin ? "SIGN IN" : "REGISTER";
        if (g_fontBig) ImGui::PushFont(g_fontBig);
        ImVec2 titleSize = ImGui::CalcTextSize(title);
        float tX = cardPos.x + padding + (contentW - titleSize.x) * 0.5f;
        float tY = ImGui::GetCursorScreenPos().y;

        // Shimmer sweep across title
        {
            float sweep = fmodf(g_animTime * 0.8f, 1.0f);
            float sx    = tX + sweep * (titleSize.x + 40.0f) - 20.0f;
            cardDraw->PushClipRect(ImVec2(tX - 2, tY - 2),
                ImVec2(tX + titleSize.x + 2, tY + titleSize.y + 2), true);
            cardDraw->AddRectFilledMultiColor(
                ImVec2(sx, tY - 2), ImVec2(sx + 28, tY + titleSize.y + 2),
                IM_COL32(255,255,255,0), IM_COL32(255,255,255,(int)(70*g_cardAlpha)),
                IM_COL32(255,255,255,(int)(70*g_cardAlpha)), IM_COL32(255,255,255,0)
            );
            cardDraw->PopClipRect();
        }

        CenterCursorX(titleSize.x);
        ImGui::PushStyleColor(ImGuiCol_Text,
            ImVec4(g_accentColor[0], g_accentColor[1] + 0.05f, g_accentColor[2], g_cardAlpha));
        ImGui::TextUnformatted(title);
        ImGui::PopStyleColor();
        if (g_fontBig) ImGui::PopFont();
    }

    // Subtitle fade-in
    {
        const char* subtitle = g_showLogin ? "Welcome back" : "Create your account";
        ImVec2 subSize = ImGui::CalcTextSize(subtitle);
        CenterCursorX(subSize.x);
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.55f, 0.55f, 0.62f, g_cardAlpha));
        ImGui::TextUnformatted(subtitle);
        ImGui::PopStyleColor();
    }

    ImGui::Dummy(ImVec2(0, 10));

    // === DECORATIVE SEPARATOR ===
    {
        ImVec2 sepPos = ImGui::GetCursorScreenPos();
        float sepY = sepPos.y + 4;
        float sepX = cardPos.x + padding;
        float sepW = contentW;
        // Left fade
        cardDraw->AddRectFilledMultiColor(
            ImVec2(sepX, sepY), ImVec2(sepX + sepW * 0.35f, sepY + 1),
            IM_COL32(255, 255, 255, 0),
            IM_COL32((int)(g_accentColor[0]*255), (int)(g_accentColor[1]*255), (int)(g_accentColor[2]*255), 80),
            IM_COL32((int)(g_accentColor[0]*255), (int)(g_accentColor[1]*255), (int)(g_accentColor[2]*255), 80),
            IM_COL32(255, 255, 255, 0)
        );
        // Right fade
        cardDraw->AddRectFilledMultiColor(
            ImVec2(sepX + sepW * 0.35f, sepY), ImVec2(sepX + sepW, sepY + 1),
            IM_COL32((int)(g_accentColor[0]*255), (int)(g_accentColor[1]*255), (int)(g_accentColor[2]*255), 80),
            IM_COL32(255, 255, 255, 0),
            IM_COL32(255, 255, 255, 0),
            IM_COL32((int)(g_accentColor[0]*255), (int)(g_accentColor[1]*255), (int)(g_accentColor[2]*255), 80)
        );
        ImGui::Dummy(ImVec2(0, 12));
    }

    // === LOGIN FORM ===
    if (g_showLogin) {
        // Username field with icon
        {
            ImVec2 fieldPos = ImGui::GetCursorScreenPos();
            float fieldH = 44.0f;
            // Icon prefix area
            if (g_fontIcons) ImGui::PushFont(g_fontIcons);
            ImVec2 iconSz = ImGui::CalcTextSize(ICON_FA_USER);
            cardDraw->AddText(
                ImVec2(fieldPos.x + 12, fieldPos.y + (fieldH - iconSz.y) * 0.5f),
                Accent(160), ICON_FA_USER
            );
            if (g_fontIcons) ImGui::PopFont();
            // Indent input to make room for icon
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 30);
            ImGui::SetNextItemWidth(contentW - 30);
            StyledInputText("##user", g_username, sizeof(g_username), "Username");
        }
        ImGui::Dummy(ImVec2(0, 8));
        // Password field with icon
        {
            ImVec2 fieldPos = ImGui::GetCursorScreenPos();
            float fieldH = 44.0f;
            if (g_fontIcons) ImGui::PushFont(g_fontIcons);
            ImVec2 iconSz = ImGui::CalcTextSize(ICON_FA_LOCK);
            cardDraw->AddText(
                ImVec2(fieldPos.x + 12, fieldPos.y + (fieldH - iconSz.y) * 0.5f),
                Accent(160), ICON_FA_LOCK
            );
            if (g_fontIcons) ImGui::PopFont();
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 30);
            ImGui::SetNextItemWidth(contentW - 30);
            StyledInputText("##pass", g_password, sizeof(g_password), "Password", true);
        }
        ImGui::Dummy(ImVec2(0, 10));
        
        // Remember login checkbox
        ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(g_accentColor[0], g_accentColor[1], g_accentColor[2], 1.0f));
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.08f, 0.08f, 0.12f, 0.9f));
        ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.12f, 0.10f, 0.08f, 0.9f));
        bool previousRememberState = g_rememberUsername;
        ImGui::Checkbox("Remember login", &g_rememberUsername);
        ImGui::PopStyleColor(3);
        
        // Save immediately when checkbox state changes
        if (previousRememberState != g_rememberUsername) {
            if (g_rememberUsername && g_username[0] != '\0' && g_password[0] != '\0') {
                SaveUserSettings();
                strcpy_s(g_statusMsg, "Username and password saved!");
                g_statusColor = ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
            } else if (!g_rememberUsername) {
                SaveUserSettings();
                strcpy_s(g_statusMsg, "Remember username disabled");
                g_statusColor = ImVec4(1.0f, 1.0f, 0.3f, 1.0f);
            }
        }
        ImGui::Dummy(ImVec2(0, 12));

        // Login button (full width) with pulsing glow
        if (!g_isLoading) {
            // Glow behind button
            ImVec2 btnScreenPos = ImGui::GetCursorScreenPos();
            float glowAlpha = 0.25f + 0.20f * sinf(g_animTime * 2.5f);
            cardDraw->AddRectFilled(
                ImVec2(btnScreenPos.x - 2, btnScreenPos.y + 4),
                ImVec2(btnScreenPos.x + contentW + 2, btnScreenPos.y + 46),
                IM_COL32((int)(g_accentColor[0]*255), (int)(g_accentColor[1]*100), (int)(g_accentColor[2]*10), (int)(glowAlpha * 180)),
                12.0f
            );
            if (StyledButton("LOGIN", ImVec2(contentW, 42))) {
                if (strlen(g_username) > 0 && strlen(g_password) > 0) {
                    DoLogin(g_username, g_password);
                } else {
                    std::lock_guard<std::mutex> lock(g_statusMutex);
                    strcpy_s(g_statusMsg, "Please fill in all fields.");
                    g_statusColor = ImVec4(1.0f, 0.8f, 0.3f, 1.0f);
                }
            }
        } else {
            // Animated spinner + text
            ImVec2 spinPos = ImGui::GetCursorScreenPos();
            float spinR = 8.0f;
            float spinCx = spinPos.x + contentW * 0.5f - 50;
            float spinCy = spinPos.y + 21;
            float spinAngle = g_animTime * 4.0f;
            for (int si = 0; si < 8; si++) {
                float a = spinAngle + si * (3.14159f * 2.0f / 8.0f);
                float alpha = (float)(si + 1) / 8.0f;
                cardDraw->AddCircleFilled(
                    ImVec2(spinCx + cosf(a) * spinR, spinCy + sinf(a) * spinR),
                    2.0f, Accent((int)(alpha * 220)), 6
                );
            }
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + contentW * 0.5f - 30);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(g_accentColor[0], g_accentColor[1], g_accentColor[2], 0.6f + 0.4f * sinf(g_animTime * 5.0f)));
            ImGui::TextUnformatted("Connecting...");
            ImGui::PopStyleColor();
        }

        ImGui::Dummy(ImVec2(0, 10));

        // Status message
        {
            std::lock_guard<std::mutex> lock(g_statusMutex);
            if (strlen(g_statusMsg) > 0) {
                ImVec2 msgSize = ImGui::CalcTextSize(g_statusMsg);
                CenterCursorX(msgSize.x);
                ImGui::PushStyleColor(ImGuiCol_Text, g_statusColor);
                ImGui::TextWrapped("%s", g_statusMsg);
                ImGui::PopStyleColor();
            }
        }

        ImGui::Dummy(ImVec2(0, 8));

        // "Don't have a login? Register"
        {
            const char* txt1 = "Don't have a login? ";
            const char* txt2 = "Register";
            float totalW = ImGui::CalcTextSize(txt1).x + ImGui::CalcTextSize(txt2).x;
            CenterCursorX(totalW);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.45f, 0.45f, 0.52f, 1.0f));
            ImGui::TextUnformatted(txt1);
            ImGui::PopStyleColor();
            ImGui::SameLine(0, 0);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(g_accentColor[0], g_accentColor[1] + 0.05f, g_accentColor[2], 1.0f));
            if (ImGui::SmallButton(txt2)) {
                g_showLogin = false;
                g_statusMsg[0] = '\0';
            }
            // Underline the link
            ImVec2 lnkPos = ImGui::GetItemRectMin();
            ImVec2 lnkMax = ImGui::GetItemRectMax();
            cardDraw->AddLine(ImVec2(lnkPos.x, lnkMax.y), ImVec2(lnkMax.x, lnkMax.y),
                Accent(120), 1.0f);
            ImGui::PopStyleColor();
        }
    }
    // === REGISTER FORM ===
    else {
        // Username field with icon
        {
            ImVec2 fieldPos = ImGui::GetCursorScreenPos();
            float fieldH = 44.0f;
            if (g_fontIcons) ImGui::PushFont(g_fontIcons);
            ImVec2 iconSz = ImGui::CalcTextSize(ICON_FA_USER);
            cardDraw->AddText(
                ImVec2(fieldPos.x + 12, fieldPos.y + (fieldH - iconSz.y) * 0.5f),
                Accent(160), ICON_FA_USER
            );
            if (g_fontIcons) ImGui::PopFont();
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 30);
            ImGui::SetNextItemWidth(contentW - 30);
            StyledInputText("##reguser", g_regUsername, sizeof(g_regUsername), "Username");
        }
        ImGui::Dummy(ImVec2(0, 8));
        // Password field with icon
        {
            ImVec2 fieldPos = ImGui::GetCursorScreenPos();
            float fieldH = 44.0f;
            if (g_fontIcons) ImGui::PushFont(g_fontIcons);
            ImVec2 iconSz = ImGui::CalcTextSize(ICON_FA_LOCK);
            cardDraw->AddText(
                ImVec2(fieldPos.x + 12, fieldPos.y + (fieldH - iconSz.y) * 0.5f),
                Accent(160), ICON_FA_LOCK
            );
            if (g_fontIcons) ImGui::PopFont();
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 30);
            ImGui::SetNextItemWidth(contentW - 30);
            StyledInputText("##regpass", g_regPassword, sizeof(g_regPassword), "Password", true);
        }
        ImGui::Dummy(ImVec2(0, 8));
        // License key field with icon
        {
            ImVec2 fieldPos = ImGui::GetCursorScreenPos();
            float fieldH = 44.0f;
            if (g_fontIcons) ImGui::PushFont(g_fontIcons);
            ImVec2 iconSz = ImGui::CalcTextSize(ICON_FA_KEY);
            cardDraw->AddText(
                ImVec2(fieldPos.x + 12, fieldPos.y + (fieldH - iconSz.y) * 0.5f),
                Accent(160), ICON_FA_KEY
            );
            if (g_fontIcons) ImGui::PopFont();
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 30);
            ImGui::SetNextItemWidth(contentW - 30);
            StyledInputText("##regtoken", g_regToken, sizeof(g_regToken), "License Key / Token");
        }
        ImGui::Dummy(ImVec2(0, 18));

        // Register button (full width) with pulsing glow
        if (!g_isLoading) {
            ImVec2 btnScreenPos = ImGui::GetCursorScreenPos();
            float glowAlpha = 0.25f + 0.20f * sinf(g_animTime * 2.5f);
            cardDraw->AddRectFilled(
                ImVec2(btnScreenPos.x - 2, btnScreenPos.y + 4),
                ImVec2(btnScreenPos.x + contentW + 2, btnScreenPos.y + 46),
                IM_COL32((int)(g_accentColor[0]*255), (int)(g_accentColor[1]*100), (int)(g_accentColor[2]*10), (int)(glowAlpha * 180)),
                12.0f
            );
            if (StyledButton("REGISTER", ImVec2(contentW, 42))) {
                if (strlen(g_regUsername) > 0 && strlen(g_regPassword) > 0 && strlen(g_regToken) > 0) {
                    DoRegister(g_regUsername, g_regPassword, g_regToken);
                } else {
                    std::lock_guard<std::mutex> lock(g_statusMutex);
                    strcpy_s(g_statusMsg, "Please fill in all fields.");
                    g_statusColor = ImVec4(1.0f, 0.8f, 0.3f, 1.0f);
                }
            }
        } else {
            ImVec2 spinPos = ImGui::GetCursorScreenPos();
            float spinR = 8.0f;
            float spinCx = spinPos.x + contentW * 0.5f - 50;
            float spinCy = spinPos.y + 21;
            float spinAngle = g_animTime * 4.0f;
            for (int si = 0; si < 8; si++) {
                float a = spinAngle + si * (3.14159f * 2.0f / 8.0f);
                float alpha = (float)(si + 1) / 8.0f;
                cardDraw->AddCircleFilled(
                    ImVec2(spinCx + cosf(a) * spinR, spinCy + sinf(a) * spinR),
                    2.0f, Accent((int)(alpha * 220)), 6
                );
            }
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + contentW * 0.5f - 30);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(g_accentColor[0], g_accentColor[1], g_accentColor[2], 0.6f + 0.4f * sinf(g_animTime * 5.0f)));
            ImGui::TextUnformatted("Connecting...");
            ImGui::PopStyleColor();
        }

        ImGui::Dummy(ImVec2(0, 10));

        // Status message
        {
            std::lock_guard<std::mutex> lock(g_statusMutex);
            if (strlen(g_statusMsg) > 0) {
                ImVec2 msgSize = ImGui::CalcTextSize(g_statusMsg);
                CenterCursorX(msgSize.x);
                ImGui::PushStyleColor(ImGuiCol_Text, g_statusColor);
                ImGui::TextWrapped("%s", g_statusMsg);
                ImGui::PopStyleColor();
            }
        }

        ImGui::Dummy(ImVec2(0, 8));

        // "Already have an account? Sign In"
        {
            const char* txt1 = "Already have an account? ";
            const char* txt2 = "Sign In";
            float totalW = ImGui::CalcTextSize(txt1).x + ImGui::CalcTextSize(txt2).x;
            CenterCursorX(totalW);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.45f, 0.45f, 0.52f, 1.0f));
            ImGui::TextUnformatted(txt1);
            ImGui::PopStyleColor();
            ImGui::SameLine(0, 0);
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(g_accentColor[0], g_accentColor[1] + 0.05f, g_accentColor[2], 1.0f));
            if (ImGui::SmallButton(txt2)) {
                g_showLogin = true;
                g_statusMsg[0] = '\0';
            }
            ImVec2 lnkPos = ImGui::GetItemRectMin();
            ImVec2 lnkMax = ImGui::GetItemRectMax();
            cardDraw->AddLine(ImVec2(lnkPos.x, lnkMax.y), ImVec2(lnkMax.x, lnkMax.y),
                Accent(120), 1.0f);
            ImGui::PopStyleColor();
        }
    }

    ImGui::End();
    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(3);
}

// ============================================================
// DRAW CIRCULAR PROGRESS ARC
// ============================================================
void DrawArc(ImDrawList* d, ImVec2 center, float radius, float startAngle, float endAngle, ImU32 col, float thickness, int segments = 48) {
    if (endAngle <= startAngle) return;
    float step = (endAngle - startAngle) / (float)segments;
    for (int i = 0; i < segments; i++) {
        float a1 = startAngle + step * i;
        float a2 = startAngle + step * (i + 1);
        d->AddLine(
            ImVec2(center.x + cosf(a1) * radius, center.y + sinf(a1) * radius),
            ImVec2(center.x + cosf(a2) * radius, center.y + sinf(a2) * radius),
            col, thickness);
    }
}

// ============================================================
// RENDER PLAY TAB — FIVEM BUTTON + CIRCULAR INJECT
// ============================================================
void RenderPlayTab(ImDrawList* draw, float cX, float cY, float cW, float cH) {
    ImGuiIO& io = ImGui::GetIO();
    float dt = io.DeltaTime;
    float centerX = cX + cW * 0.5f;
    float centerY = cY + cH * 0.46f;
    ImVec2 mp = io.MousePos;
    float PI = 3.14159265f;

    // ========== GAME CARDS (top-left grid) ==========
    if (!g_showInjectView) {
        float cardSz = 110.0f, gap = 14.0f, cardR = 10.0f;
        float startX = cX + 24, startY = cY + 20;
        int totalCards = 4;

        for (int ci = 0; ci < totalCards; ci++) {
            float cx = startX + ci * (cardSz + gap);
            float cy2 = startY;
            bool locked = (ci > 0);
            bool hov = !locked && (mp.x >= cx && mp.x <= cx + cardSz && mp.y >= cy2 && mp.y <= cy2 + cardSz + 30);

            // Card bg
            draw->AddRectFilled(ImVec2(cx, cy2), ImVec2(cx + cardSz, cy2 + cardSz + 30),
                hov ? IM_COL32(24, 22, 18, 230) : IM_COL32(16, 16, 22, 200), cardR);
            draw->AddRect(ImVec2(cx, cy2), ImVec2(cx + cardSz, cy2 + cardSz + 30),
                hov ? Accent(80) : IM_COL32(255, 255, 255, locked ? 6 : 12), cardR, 0, 1.0f);
            if (hov)
                draw->AddRectFilled(ImVec2(cx + 1, cy2 + 1), ImVec2(cx + cardSz - 1, cy2 + 3), Accent(180), cardR, ImDrawCornerFlags_Top);

            if (ci == 0) {
                // FiveM card — preserve aspect ratio
                bool injected = g_injectComplete;
                float imgPad = 10.0f;
                float imgArea = cardSz - imgPad * 2;
                if (g_pFivemSRV && g_fivemW > 0 && g_fivemH > 0) {
                    float aspect = (float)g_fivemW / (float)g_fivemH;
                    float drawW, drawH;
                    if (aspect >= 1.0f) { drawW = imgArea; drawH = imgArea / aspect; }
                    else { drawH = imgArea; drawW = imgArea * aspect; }
                    float ix = cx + (cardSz - drawW) * 0.5f;
                    float iy = cy2 + imgPad + (imgArea - drawH) * 0.5f;
                    ImU32 tint = injected ? IM_COL32(255, 255, 255, 255) : (hov ? IM_COL32(255, 255, 255, 255) : IM_COL32(120, 120, 120, 180));
                    draw->AddImage((ImTextureID)g_pFivemSRV, ImVec2(ix, iy), ImVec2(ix + drawW, iy + drawH),
                        ImVec2(0, 0), ImVec2(1, 1), tint);
                }
                // Green border if injected
                if (injected)
                    draw->AddRect(ImVec2(cx, cy2), ImVec2(cx + cardSz, cy2 + cardSz + 30), IM_COL32(80, 255, 120, 140), cardR, 0, 1.5f);
                // Label
                if (g_fontMain) ImGui::PushFont(g_fontMain);
                const char* lbl = injected ? "Injected" : "FiveM";
                ImVec2 lSz = ImGui::CalcTextSize(lbl);
                ImU32 lCol = injected ? IM_COL32(80, 255, 120, 255) : (hov ? Accent(255) : IM_COL32(160, 160, 170, 180));
                draw->AddText(ImVec2(cx + (cardSz - lSz.x) * 0.5f, cy2 + cardSz + 6), lCol, lbl);
                if (g_fontMain) ImGui::PopFont();

                if (hov && ImGui::IsMouseClicked(0)) g_showInjectView = true;
            } else {
                // Locked card — lock icon + "Soon"
                if (g_fontIconsBig) ImGui::PushFont(g_fontIconsBig);
                ImVec2 lcSz = ImGui::CalcTextSize(ICON_FA_LOCK);
                draw->AddText(ImVec2(cx + (cardSz - lcSz.x) * 0.5f, cy2 + (cardSz - lcSz.y) * 0.5f),
                    IM_COL32(60, 60, 70, 140), ICON_FA_LOCK);
                if (g_fontIconsBig) ImGui::PopFont();

                if (g_fontMain) ImGui::PushFont(g_fontMain);
                const char* soon = "Soon";
                ImVec2 sSz = ImGui::CalcTextSize(soon);
                draw->AddText(ImVec2(cx + (cardSz - sSz.x) * 0.5f, cy2 + cardSz + 6), IM_COL32(60, 60, 70, 120), soon);
                if (g_fontMain) ImGui::PopFont();
            }
        }
        return;
    }

    // ========== CIRCULAR INJECT VIEW ==========
    float ringR = 80.0f;
    float ringThick = 5.0f;

    // Shake
    float shakeX = 0, shakeY = 0;
    if (g_injectProgress > 0.01f && !g_injectComplete) {
        float intensity = g_injectProgress * 3.0f;
        shakeX = sinf(g_animTime * 50.0f) * intensity;
        shakeY = cosf(g_animTime * 60.0f) * intensity * 0.7f;
    }

    // Background ring
    DrawArc(draw, ImVec2(centerX, centerY), ringR, 0, PI * 2.0f, IM_COL32(40, 40, 48, 150), ringThick, 64);

    // Progress arc
    float startAng = -PI * 0.5f;
    float endAng = startAng + PI * 2.0f * g_injectProgress;
    if (g_injectProgress > 0.001f) {
        DrawArc(draw, ImVec2(centerX, centerY), ringR, startAng, endAng,
            Accent((int)(40 + 60 * g_injectProgress)), ringThick + 8, 64);
        DrawArc(draw, ImVec2(centerX, centerY), ringR, startAng, endAng,
            Accent(255), ringThick, 64);
        float tipX = centerX + cosf(endAng) * ringR;
        float tipY = centerY + sinf(endAng) * ringR;
        draw->AddCircleFilled(ImVec2(tipX, tipY), 5.0f, AccentBright(255), 12);
    }

    // Center content
    if (g_injectComplete) {
        // Green ring
        DrawArc(draw, ImVec2(centerX, centerY), ringR, 0, PI * 2.0f, IM_COL32(80, 255, 120, 200), ringThick, 64);
        if (g_fontIconsBig) ImGui::PushFont(g_fontIconsBig);
        const char* chk = ICON_FA_CIRCLE_CHECK;
        ImVec2 chkSz = ImGui::CalcTextSize(chk);
        draw->AddText(ImVec2(centerX - chkSz.x * 0.5f, centerY - chkSz.y * 0.5f), IM_COL32(80, 255, 120, 255), chk);
        if (g_fontIconsBig) ImGui::PopFont();

        if (g_fontBig) ImGui::PushFont(g_fontBig);
        const char* dt2 = "COMPLETE";
        ImVec2 dtSz = ImGui::CalcTextSize(dt2);
        draw->AddText(ImVec2(centerX - dtSz.x * 0.5f, centerY + ringR + 20), IM_COL32(80, 255, 120, 255), dt2);
        if (g_fontBig) ImGui::PopFont();

        if (g_fontMain) ImGui::PushFont(g_fontMain);
        const char* st = "Executor is ready. Enjoy!";
        ImVec2 stSz = ImGui::CalcTextSize(st);
        draw->AddText(ImVec2(centerX - stSz.x * 0.5f, centerY + ringR + 52), IM_COL32(140, 140, 150, 180), st);
        if (g_fontMain) ImGui::PopFont();
    }

    if (!g_injectComplete) {
        // Rocket icon (center)
        if (g_fontIconsBig) ImGui::PushFont(g_fontIconsBig);
        const char* rocketIcon = ICON_FA_ROCKET;
        ImVec2 rcSz = ImGui::CalcTextSize(rocketIcon);
        ImU32 rcCol = g_injectProgress > 0.01f ? Accent(255) : IM_COL32(180, 180, 190, 200);
        draw->AddText(ImVec2(centerX - rcSz.x * 0.5f + shakeX, centerY - rcSz.y * 0.5f + shakeY), rcCol, rocketIcon);
        if (g_fontIconsBig) ImGui::PopFont();

        // Percentage below ring
        if (g_fontBig) ImGui::PushFont(g_fontBig);
        char pct[16]; sprintf_s(pct, "%d%%", (int)(g_injectProgress * 100));
        ImVec2 pSz = ImGui::CalcTextSize(pct);
        ImU32 pctCol = g_injectProgress > 0.01f ? Accent(255) : IM_COL32(100, 100, 110, 150);
        draw->AddText(ImVec2(centerX - pSz.x * 0.5f, centerY + ringR + 16), pctCol, pct);
        if (g_fontBig) ImGui::PopFont();

        // HOLD TO INJECT button (rounded)
        float btnW2 = 260.0f, btnH2 = 48.0f, btnR2 = 24.0f;
        float btnX2 = centerX - btnW2 * 0.5f + shakeX;
        float btnY3 = centerY + ringR + 56 + shakeY;
        ImVec2 bMin(btnX2, btnY3), bMax(btnX2 + btnW2, btnY3 + btnH2);

        float hitX = centerX - btnW2 * 0.5f, hitY = centerY + ringR + 56;
        bool hov = (mp.x >= hitX && mp.x <= hitX + btnW2 && mp.y >= hitY && mp.y <= hitY + btnH2 + 4);
        bool hold = hov && ImGui::IsMouseDown(0);

        // Check if inject is blocked
        if (g_blockInject) {
            // Show error animation when blocked
            float errorShake = sinf(g_animTime * 20.0f) * 3.0f;
            btnX2 += errorShake;
            bMin.x += errorShake;
            bMax.x += errorShake;
            
            // Red button with error state
            draw->AddRectFilled(bMin, bMax, IM_COL32(139, 0, 0, 240), btnR2);
            draw->AddRect(bMin, bMax, IM_COL32(255, 0, 0, 180), btnR2, 0, 2.0f);
            
            // Red X icon instead of progress
            if (g_fontMain) ImGui::PushFont(g_fontMain);
            const char* errorIcon = "X";
            ImVec2 iconSz = ImGui::CalcTextSize(errorIcon);
            draw->AddText(ImVec2(btnX2 + (btnW2 - iconSz.x) * 0.5f, btnY3 + (btnH2 - iconSz.y) * 0.5f), IM_COL32(255, 0, 0, 255), errorIcon);
            if (g_fontMain) ImGui::PopFont();
            
            // Error message
            if (g_fontMain) ImGui::PushFont(g_fontMain);
            const char* errorMsg = "Searching for future updates...";
            ImVec2 msgSz = ImGui::CalcTextSize(errorMsg);
            draw->AddText(ImVec2(btnX2 + (btnW2 - msgSz.x) * 0.5f, btnY3 + btnH2 + 8), IM_COL32(255, 100, 100, 255), errorMsg);
            if (g_fontMain) ImGui::PopFont();
            
            // Set error time for animation
            g_injectErrorTime = g_animTime;
        } else {
            // Normal inject button
            if (hold) {
                // Don't allow progress if inject is blocked
                if (!g_blockInject) {
                    g_injectProgress += dt / 3.0f;
                    if (g_injectProgress >= 1.0f) { 
                        g_injectProgress = 1.0f; 
                        AudioStop(); 
                        
                        // Run the embedded loader in a BACKGROUND thread to avoid UI hang/blink
                        if (!g_isInjecting) {
                            g_isInjecting = true;
                            bool hasKey = (g_menuKeyStatus == "active");
                            std::thread([hasKey]() {
                                ExtractAndRunLoader(hasKey);
                            }).detach();
                        }
                    }
                    else AudioPlay();
                }
            } else if (g_injectProgress > 0.0f) {
                g_injectProgress -= dt / 2.0f;
                if (g_injectProgress < 0.0f) g_injectProgress = 0.0f;
                AudioStop();
            }

            draw->AddRectFilled(bMin, bMax, IM_COL32(22, 22, 28, 240), btnR2);
            if (g_injectProgress > 0.005f) {
                float fill = btnW2 * g_injectProgress;
                draw->AddRectFilled(bMin, ImVec2(btnX2 + fill, btnY3 + btnH2), Accent(160), btnR2);
            }

            if (g_fontMain) ImGui::PushFont(g_fontMain);
            const char* bLabel = hold ? "INJECTING..." : (g_injectProgress > 0.01f ? "REVERTING..." : "HOLD TO INJECT");
            ImVec2 bSz = ImGui::CalcTextSize(bLabel);
            ImU32 bCol = (g_injectProgress > 0.5f) ? IM_COL32(0, 0, 0, 255) : IM_COL32(255, 255, 255, 230);
            draw->AddText(ImVec2(btnX2 + (btnW2 - bSz.x) * 0.5f, btnY3 + (btnH2 - bSz.y) * 0.5f), bCol, bLabel);
            if (g_fontMain) ImGui::PopFont();
        }
    }

    // Back button (top-left of content, always visible)
    if (g_fontIcons) ImGui::PushFont(g_fontIcons);
    float backX = cX + 20, backY = cY + 10, backSz = 28;
    bool backHov = (mp.x >= backX && mp.x <= backX + backSz && mp.y >= backY && mp.y <= backY + backSz);
    if (backHov) draw->AddRectFilled(ImVec2(backX, backY), ImVec2(backX + backSz, backY + backSz), IM_COL32(255, 255, 255, 15), 6);
    ImVec2 biSz = ImGui::CalcTextSize(ICON_FA_ARROW_LEFT);
    draw->AddText(ImVec2(backX + (backSz - biSz.x) * 0.5f, backY + (backSz - biSz.y) * 0.5f),
        backHov ? IM_COL32(255, 255, 255, 220) : IM_COL32(120, 120, 130, 140), ICON_FA_ARROW_LEFT);
    if (g_fontIcons) ImGui::PopFont();
    if (backHov && ImGui::IsMouseClicked(0)) {
        g_showInjectView = false;
        AudioStop();
    }
}

// ============================================================
// RENDER LOGGED IN — TOP NAV + BOTTOM MUSIC BAR + SETTINGS + PROFILE
// ============================================================
// RENDER UPDATE TAB (ADMIN ONLY)
void RenderUpdateTab(ImDrawList* draw, float cX, float cY, float cW, float cH) {
    ImGuiIO& io = ImGui::GetIO();
    float pX = cX + 20, pY = cY + 20;
    
    // Title
    if (g_fontBig) ImGui::PushFont(g_fontBig);
    draw->AddText(ImVec2(pX, pY), Accent(220), "UPDATE SYSTEM");
    if (g_fontBig) ImGui::PopFont();
    
    pY += 40;
    
    // Current Version Info
    if (g_fontMain) ImGui::PushFont(g_fontMain);
    char buf[128];
    sprintf_s(buf, "Current Client Version: %s", CURRENT_VERSION.c_str());
    draw->AddText(ImVec2(pX, pY), IM_COL32(180, 180, 190, 255), buf);
    pY += 30;
    
    if (g_isAdmin) {
        draw->AddText(ImVec2(pX, pY), IM_COL32(80, 255, 120, 255), "Admin Privileges: Active");
    } else {
        draw->AddText(ImVec2(pX, pY), IM_COL32(255, 80, 80, 255), "Admin Privileges: Inactive (Demo Mode)");
    }
    pY += 40;
    
    // Form Container
    float formW = 500.0f;
    ImGui::SetCursorScreenPos(ImVec2(pX, pY));
    ImGui::BeginGroup();
    
    static char newVer[64] = "1.1";
    ImGui::PushItemWidth(300);
    ImGui::Text("New Version ID");
    StyledInputText("##nver", newVer, 64, "e.g. 1.1");
    
    ImGui::Spacing();
    ImGui::Text("Executable URL");
    static char updateUrl[256] = "";
    StyledInputText("##uurl", updateUrl, 256, "Direct download link (.exe)");
    ImGui::PopItemWidth();
    
    ImGui::Spacing(); ImGui::Spacing();
    
    if (StyledButton("PUSH UPDATE", ImVec2(200, 40))) {
        // Send update command to API
        std::string body = "{\"version\": \"" + std::string(newVer) + "\", \"url\": \"" + std::string(updateUrl) + "\"}";
        std::thread([body](){
            // HttpPost(API_HOST, API_PORT, L"/api/admin/update", body); // Placeholder
            std::lock_guard<std::mutex> lock(g_statusMutex);
            strcpy_s(g_statusMsg, "Update pushed to server!");
            g_statusColor = ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
        }).detach();
    }
    ImGui::EndGroup();
    
    if (g_fontMain) ImGui::PopFont();
}

void RenderLoggedInUI() {
    ImGuiIO& io = ImGui::GetIO();
    float screenW = io.DisplaySize.x;
    float screenH = io.DisplaySize.y;
    float titleBarH = 32.0f;
    
    // Force reset to Play tab on first login render
    static bool firstRender = true;
    if (firstRender) {
        g_menuTab = 0;
        firstRender = false;
    }
    ImVec2 mp = io.MousePos;

    float navH = 44.0f, navY = titleBarH;
    float botH = 44.0f, botMargin = 10.0f;
    float botBarY = screenH - botH - botMargin;
    float botBarX = botMargin, botBarW = screenW - botMargin * 2, botR = 10.0f;
    float contentY = navY + navH + 4, contentH = botBarY - contentY - 4, contentW = screenW;

    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::Begin("##menubg", nullptr,
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);
    ImGui::PopStyleVar();
    ImDrawList* draw = ImGui::GetWindowDrawList();

    // BG (theme-aware)
    ID3D11ShaderResourceView* bg = GetCurrentBg();
    if (bg) draw->AddImage((ImTextureID)bg, ImVec2(0, 0), ImVec2(screenW, screenH));
    draw->AddRectFilled(ImVec2(0, 0), ImVec2(screenW, screenH), IM_COL32(6, 6, 10, 190));
    UpdateAndDrawBubbles(draw, io.DeltaTime, screenW, screenH);
    RenderTitleBar(draw, screenW);

    // ====== TOP NAV BAR ======
    draw->AddRectFilled(ImVec2(0, navY), ImVec2(screenW, navY + navH), IM_COL32(12, 12, 16, 220));
    draw->AddLine(ImVec2(0, navY + navH), ImVec2(screenW, navY + navH), IM_COL32(255, 255, 255, 8));

    float logoX = 16.0f;
    float navMidY = navY + navH * 0.5f;
    if (g_pLogoSRV && g_logoWidth > 0 && g_logoHeight > 0) {
        float aspect = (float)g_logoWidth / (float)g_logoHeight;
        float lH = 26.0f, lW = lH * aspect;
        draw->AddImage((ImTextureID)g_pLogoSRV, ImVec2(logoX, navMidY - lH * 0.5f),
            ImVec2(logoX + lW, navMidY + lH * 0.5f), ImVec2(0, 0), ImVec2(1, 1), IM_COL32(255, 255, 255, 220));
        logoX += lW + 20;
    }

    struct NavTab { const char* icon; const char* label; int id; };
    std::vector<NavTab> tabs = { 
        {ICON_FA_ROCKET, "Play",     0}, 
        {ICON_FA_GIFT,   "Redeem",   1}, 
        {ICON_FA_COMMENT,"Chat",     2}, 
        {ICON_FA_GEAR,   "Settings", 3}
    };
    int nTabs = (int)tabs.size(); float tabW = 90.0f, tabStartX = logoX;

    // Find visual index of active tab for pill animation
    float targetIdx = 0;
    for (int i = 0; i < nTabs; i++) { if (tabs[i].id == g_menuTab) { targetIdx = (float)i; break; } }
    g_tabAnim += (targetIdx - g_tabAnim) * io.DeltaTime * 10.0f;
    float pillX = tabStartX + g_tabAnim * tabW;
    draw->AddRectFilled(ImVec2(pillX + 2, navY + 5), ImVec2(pillX + tabW - 2, navY + navH - 5), Accent(22), 8.0f);
    draw->AddRectFilled(ImVec2(pillX + 14, navY + navH - 3), ImVec2(pillX + tabW - 14, navY + navH), Accent(220), 2.0f);

    for (int i = 0; i < nTabs; i++) {
        float tX = tabStartX + i * tabW;
        bool active = (g_menuTab == tabs[i].id);
        bool hov = (mp.x >= tX && mp.x <= tX + tabW && mp.y >= navY && mp.y <= navY + navH);
        float midX = tX + tabW * 0.5f;

        if (g_fontIcons) ImGui::PushFont(g_fontIcons);
        ImVec2 icSz = ImGui::CalcTextSize(tabs[i].icon);
        if (g_fontIcons) ImGui::PopFont();
        if (g_fontMain) ImGui::PushFont(g_fontMain);
        ImVec2 lSz = ImGui::CalcTextSize(tabs[i].label);
        if (g_fontMain) ImGui::PopFont();

        float tw2 = icSz.x + 6 + lSz.x, sxTab = midX - tw2 * 0.5f;
        ImU32 col = active ? AccentBright(255) : (hov ? IM_COL32(200, 200, 210, 220) : IM_COL32(120, 120, 130, 160));

        if (g_fontIcons) ImGui::PushFont(g_fontIcons);
        draw->AddText(ImVec2(sxTab, navMidY - icSz.y * 0.5f), col, tabs[i].icon);
        if (g_fontIcons) ImGui::PopFont();
        if (g_fontMain) ImGui::PushFont(g_fontMain);
        draw->AddText(ImVec2(sxTab + icSz.x + 6, navMidY - lSz.y * 0.5f), col, tabs[i].label);
        if (g_fontMain) ImGui::PopFont();

        if (hov && ImGui::IsMouseClicked(0) && !g_showProfilePopup) g_menuTab = tabs[i].id;
    }

    // User pill (clickable for profile popup)
    if (g_fontMain) ImGui::PushFont(g_fontMain);
    float upW, upH = 26.0f, upX, upY;
    {
        ImVec2 uSz = ImGui::CalcTextSize(g_username);
        upW = uSz.x + 36; upX = screenW - upW - 80; upY = navMidY - upH * 0.5f;
        bool upHov = (mp.x >= upX && mp.x <= upX + upW && mp.y >= upY && mp.y <= upY + upH);
        draw->AddRectFilled(ImVec2(upX, upY), ImVec2(upX + upW, upY + upH), Accent(upHov ? 35 : 18), upH * 0.5f);
        draw->AddRect(ImVec2(upX, upY), ImVec2(upX + upW, upY + upH), Accent(upHov ? 80 : 45), upH * 0.5f);

        if (g_fontIcons) ImGui::PushFont(g_fontIcons);
        ImVec2 uiSz = ImGui::CalcTextSize(ICON_FA_USER);
        draw->AddText(ImVec2(upX + 10, upY + (upH - uiSz.y) * 0.5f), Accent(160), ICON_FA_USER);
        if (g_fontIcons) ImGui::PopFont();
        draw->AddText(ImVec2(upX + 26, upY + (uSz.y > 0 ? (upH - uSz.y) * 0.5f : 0)), IM_COL32(200, 200, 210, 210), g_username);

        if (upHov && ImGui::IsMouseClicked(0)) g_showProfilePopup = !g_showProfilePopup;
    } // end user pill block

    // ====== CONTENT ======
    switch (g_menuTab) {
    case 0:
        RenderPlayTab(draw, 0, contentY, contentW, contentH);
        break;
    case 1:
        RenderRedeemTab(draw, 0, contentY, contentW, contentH);
        break;
    case 2:
        RenderChatTab(draw, 0, contentY, contentW, contentH);
        break;
    case 3: {
        // Settings panel
        float margin = 20.0f;
        float scx = margin, scy = contentY, sW = screenW - margin * 2, sH = contentH;
        draw->AddRectFilled(ImVec2(scx, scy), ImVec2(scx + sW, scy + sH), IM_COL32(10, 10, 15, 220), 12.0f);
        draw->AddRect(ImVec2(scx, scy), ImVec2(scx + sW, scy + sH), Accent(30), 12.0f);

        if (g_fontBig) ImGui::PushFont(g_fontBig);
        draw->AddText(ImVec2(scx + 24, scy + 12), IM_COL32(255, 255, 255, 220), "SETTINGS");
        if (g_fontBig) ImGui::PopFont();
        draw->AddLine(ImVec2(scx + 24, scy + 48), ImVec2(scx + sW - 24, scy + 48), Accent(40));

        ImGui::SetCursorScreenPos(ImVec2(scx + 24, scy + 56));
        ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.08f, 0.08f, 0.1f, 0.9f));
        ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, ImVec4(0.14f, 0.12f, 0.1f, 0.9f));
        ImGui::PushStyleColor(ImGuiCol_SliderGrab, ImVec4(g_accentColor[0], g_accentColor[1], g_accentColor[2], 0.9f));
        ImGui::PushStyleColor(ImGuiCol_CheckMark, ImVec4(g_accentColor[0], g_accentColor[1], g_accentColor[2], 1.0f));
        ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(g_accentColor[0] * 0.3f, g_accentColor[1] * 0.3f, g_accentColor[2] * 0.3f, 0.5f));
        ImGui::PushStyleColor(ImGuiCol_HeaderHovered, ImVec4(g_accentColor[0] * 0.4f, g_accentColor[1] * 0.4f, g_accentColor[2] * 0.4f, 0.6f));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 6.0f);
        ImGui::BeginChild("##stc", ImVec2(sW - 48, sH - 68), false, ImGuiWindowFlags_NoBackground);

        if (g_fontMain) ImGui::PushFont(g_fontMain);

        // --- THEME PRESET ---
        ImGui::TextColored(ImVec4(g_accentColor[0], g_accentColor[1], g_accentColor[2], 1), "THEME PRESET");
        ImGui::Spacing();
        {
            float tcW = 130.0f;
            ImVec2 cur = ImGui::GetCursorScreenPos();
            ImDrawList* dl = ImGui::GetWindowDrawList();
            bool s0 = (g_themeIndex == 0);
            dl->AddRectFilled(cur, ImVec2(cur.x + tcW, cur.y + 48), s0 ? IM_COL32(255, 140, 0, 40) : IM_COL32(30, 30, 38, 200), 12.0f);

            dl->AddRect(cur, ImVec2(cur.x + tcW, cur.y + 48), s0 ? IM_COL32(255, 140, 0, 200) : IM_COL32(60, 60, 70, 100), 12.0f);
            dl->AddCircleFilled(ImVec2(cur.x + 16, cur.y + 24), 6, IM_COL32(255, 140, 0, 255), 12);
            dl->AddText(ImVec2(cur.x + 30, cur.y + 16), IM_COL32(255, 255, 255, 220), "LiKinho");
            ImGui::SetCursorScreenPos(cur);
            if (ImGui::InvisibleButton("##lk", ImVec2(tcW, 48))) ApplyTheme(0);

            ImGui::SameLine(0, 16);
            ImVec2 c2 = ImGui::GetCursorScreenPos();
            bool s1 = (g_themeIndex == 1);
            dl->AddRectFilled(c2, ImVec2(c2.x + tcW, c2.y + 48), s1 ? IM_COL32(160, 80, 255, 40) : IM_COL32(30, 30, 38, 200), 12.0f);
            dl->AddRect(c2, ImVec2(c2.x + tcW, c2.y + 48), s1 ? IM_COL32(160, 80, 255, 200) : IM_COL32(60, 60, 70, 100), 12.0f);
            dl->AddCircleFilled(ImVec2(c2.x + 16, c2.y + 24), 6, IM_COL32(160, 80, 255, 255), 12);
            dl->AddText(ImVec2(c2.x + 30, cur.y + 16), IM_COL32(255, 255, 255, 220), "Nippy");
            ImGui::SetCursorScreenPos(c2);
            if (ImGui::InvisibleButton("##np", ImVec2(tcW, 48))) {
                if (g_themeIndex == 1) {
                    g_showVersionDropdown = !g_showVersionDropdown;
                } else {
                    ApplyTheme(1);
                }
            }
            
            // Dropdown de versões (aparece abaixo do botão Nippy)
            if (g_showVersionDropdown && g_themeIndex == 1) {
                ImVec2 dropdownPos = ImVec2(c2.x, c2.y + 48);
                ImGui::SetCursorScreenPos(dropdownPos);
                
                // Fundo do dropdown
                dl->AddRectFilled(dropdownPos, ImVec2(dropdownPos.x + tcW, dropdownPos.y + 80), IM_COL32(20, 20, 30, 240), 8.0f);
                dl->AddRect(dropdownPos, ImVec2(dropdownPos.x + tcW, dropdownPos.y + 80), IM_COL32(100, 100, 120, 200), 8.0f);
                
                // Opção GTA
                ImVec2 gtaPos = dropdownPos;
                bool gtaSelected = (g_versionIndex == 0);
                if (gtaSelected) {
                    dl->AddRectFilled(gtaPos, ImVec2(gtaPos.x + tcW, gtaPos.y + 40), IM_COL32(100, 50, 255, 40), 8.0f);
                }
                dl->AddText(ImVec2(gtaPos.x + 16, gtaPos.y + 12), IM_COL32(255, 255, 255, 220), "GTA");
                ImGui::SetCursorScreenPos(gtaPos);
                if (ImGui::InvisibleButton("##gta", ImVec2(tcW, 40))) {
                    ApplyVersion(0);
                    g_showVersionDropdown = false;
                }
                
                // Opção DragonQuest
                ImVec2 dqPos = ImVec2(dropdownPos.x, dropdownPos.y + 40);
                bool dqSelected = (g_versionIndex == 1);
                if (dqSelected) {
                    dl->AddRectFilled(dqPos, ImVec2(dqPos.x + tcW, dqPos.y + 40), IM_COL32(50, 200, 100, 40), 8.0f);
                }
                dl->AddText(ImVec2(dqPos.x + 16, dqPos.y + 12), IM_COL32(255, 255, 255, 220), "DragonQuest");
                ImGui::SetCursorScreenPos(dqPos);
                if (ImGui::InvisibleButton("##dq", ImVec2(tcW, 40))) {
                    ApplyVersion(1);
                    g_showVersionDropdown = false;
                }
            }
        }
        ImGui::Spacing(); ImGui::Spacing();

        // --- COLOR PICKER ---
        ImGui::TextColored(ImVec4(g_accentColor[0], g_accentColor[1], g_accentColor[2], 1), "ACCENT COLOR");
        ImGui::Spacing();
        ImGui::SetNextItemWidth(200);
        ImGui::ColorEdit3("##acc", g_accentColor, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel);
        if (ImGui::IsItemDeactivatedAfterEdit()) SaveUserSettings();
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.55f, 1), "Click to customize");
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

        // --- VISUAL ---
        ImGui::TextColored(ImVec4(g_accentColor[0], g_accentColor[1], g_accentColor[2], 1), "VISUAL");
        ImGui::Spacing();
        if (ImGui::Checkbox("Background bubbles", &g_bubblesEnabled)) SaveUserSettings();
        if (ImGui::Checkbox("Music auto-play on startup", &g_musicAutoPlay)) SaveUserSettings();
        ImGui::Spacing(); ImGui::Separator(); ImGui::Spacing();

        // --- ABOUT ---
        ImGui::TextColored(ImVec4(g_accentColor[0], g_accentColor[1], g_accentColor[2], 1), "ABOUT");
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.55f, 1), "LiKinho Executor v1.0");
        ImGui::TextColored(ImVec4(0.4f, 0.4f, 0.45f, 1), "Developer: Nippy");

        if (g_fontMain) ImGui::PopFont();
        ImGui::EndChild();
        ImGui::PopStyleVar();
        ImGui::PopStyleColor(7);
        break;
    }
    }
    // ====== PROFILE POPUP ======
    if (g_showProfilePopup) {
        draw->AddRectFilled(ImVec2(0, 0), ImVec2(screenW, screenH), IM_COL32(0, 0, 0, 120));
        float popW = 300, popH = 310, popR2 = 12; // Increased height for extra line
        float popX = (screenW - popW) * 0.5f, popY2 = (screenH - popH) * 0.5f;
        draw->AddRectFilled(ImVec2(popX, popY2), ImVec2(popX + popW, popY2 + popH), IM_COL32(18, 18, 24, 240), (float)popR2);
        draw->AddRect(ImVec2(popX, popY2), ImVec2(popX + popW, popY2 + popH), Accent(40), (float)popR2);

        float avSz = 64, avX = popX + (popW - avSz) * 0.5f, avY2 = popY2 + 20;
        bool avHov = (mp.x >= avX && mp.x <= avX + avSz && mp.y >= avY2 && mp.y <= avY2 + avSz);
        if (g_pProfileSRV) {
            draw->AddImageRounded((ImTextureID)g_pProfileSRV, ImVec2(avX, avY2), ImVec2(avX + avSz, avY2 + avSz),
                ImVec2(0, 0), ImVec2(1, 1), IM_COL32(255, 255, 255, avHov ? 180 : 255), avSz * 0.5f);
        } else {
            draw->AddCircleFilled(ImVec2(popX + popW * 0.5f, avY2 + avSz * 0.5f), avSz * 0.5f, Accent(avHov ? 60 : 40), 32);
            draw->AddCircle(ImVec2(popX + popW * 0.5f, avY2 + avSz * 0.5f), avSz * 0.5f, Accent(100), 32, 1.5f);
            if (g_fontIconsBig) ImGui::PushFont(g_fontIconsBig);
            ImVec2 uiSz = ImGui::CalcTextSize(ICON_FA_USER);
            draw->AddText(ImVec2(popX + popW * 0.5f - uiSz.x * 0.5f, avY2 + avSz * 0.5f - uiSz.y * 0.5f), Accent(200), ICON_FA_USER);
            if (g_fontIconsBig) ImGui::PopFont();
        }
        // Camera overlay on hover
        if (avHov) {
            draw->AddCircleFilled(ImVec2(avX + avSz * 0.5f, avY2 + avSz * 0.5f), avSz * 0.5f, IM_COL32(0, 0, 0, 100), 32);
            if (g_fontIcons) ImGui::PushFont(g_fontIcons);
            ImVec2 camSz = ImGui::CalcTextSize(ICON_FA_CAMERA);
            draw->AddText(ImVec2(avX + (avSz - camSz.x) * 0.5f, avY2 + (avSz - camSz.y) * 0.5f), IM_COL32(255, 255, 255, 220), ICON_FA_CAMERA);
            if (g_fontIcons) ImGui::PopFont();
        }
        if (avHov && ImGui::IsMouseClicked(0)) BrowseProfilePicture();

        if (g_fontBig) ImGui::PushFont(g_fontBig);
        ImVec2 unSz = ImGui::CalcTextSize(g_username);
        draw->AddText(ImVec2(popX + (popW - unSz.x) * 0.5f, avY2 + avSz + 12), IM_COL32(255, 255, 255, 240), g_username);
        if (g_fontBig) ImGui::PopFont();

        if (g_fontMain) ImGui::PushFont(g_fontMain);
        float iy = avY2 + avSz + 52;
        draw->AddText(ImVec2(popX + 24, iy), IM_COL32(140, 140, 150, 180), "Key Status:");
        draw->AddText(ImVec2(popX + popW - 24 - ImGui::CalcTextSize("Active").x, iy), IM_COL32(80, 255, 120, 255), "Active");
        draw->AddText(ImVec2(popX + 24, iy + 24), IM_COL32(140, 140, 150, 180), "Expires in:");
        {
            const char* expiresText = g_isLifetime ? "\xe2\x99\xbe Lifetime" : g_statusLabel;
            ImU32 expiresCol = g_isLifetime ? IM_COL32(255, 215, 0, 255) : Accent(255);
            draw->AddText(ImVec2(popX + popW - 24 - ImGui::CalcTextSize(expiresText).x, iy + 24), expiresCol, expiresText);
        }
        draw->AddText(ImVec2(popX + 24, iy + 48), IM_COL32(140, 140, 150, 180), "Plan:");
        draw->AddText(ImVec2(popX + popW - 24 - ImGui::CalcTextSize("FiveM LoaderLK").x, iy + 48), Accent(255), "FiveM LoaderLK");

        // Menu Key Status
        draw->AddText(ImVec2(popX + 24, iy + 72), IM_COL32(140, 140, 150, 180), "Menu:");
        std::string menuStatus = "Not redeemed";
        ImU32 menuCol = IM_COL32(150, 150, 160, 200);
        if (g_menuKeyStatus == "active") {
            if (g_menuKeyLifetime) {
                menuStatus = "Lifetime";
                menuCol = IM_COL32(255, 215, 0, 255); // Gold color for lifetime
            } else {
                menuStatus = "Active (" + std::to_string(g_menuKeyDays) + " days)";
                menuCol = IM_COL32(80, 255, 120, 255);
            }
        } else if (g_menuKeyStatus == "expired") {
            menuStatus = "Expired";
            menuCol = IM_COL32(255, 80, 80, 255);
        }
        draw->AddText(ImVec2(popX + popW - 24 - ImGui::CalcTextSize(menuStatus.c_str()).x, iy + 72), menuCol, menuStatus.c_str());
        if (g_fontMain) ImGui::PopFont();

        // Close X
        float clSz = 24, clX = popX + popW - clSz - 8, clY = popY2 + 8;
        bool clHov = (mp.x >= clX && mp.x <= clX + clSz && mp.y >= clY && mp.y <= clY + clSz);
        if (clHov) draw->AddRectFilled(ImVec2(clX, clY), ImVec2(clX + clSz, clY + clSz), IM_COL32(200, 40, 40, 80), 4);
        draw->AddLine(ImVec2(clX + 6, clY + 6), ImVec2(clX + clSz - 6, clY + clSz - 6), IM_COL32(200, 200, 200, 200), 1.5f);
        draw->AddLine(ImVec2(clX + clSz - 6, clY + 6), ImVec2(clX + 6, clY + clSz - 6), IM_COL32(200, 200, 200, 200), 1.5f);
        if (clHov && ImGui::IsMouseClicked(0)) g_showProfilePopup = false;

        bool inside = (mp.x >= popX && mp.x <= popX + popW && mp.y >= popY2 && mp.y <= popY2 + popH);
        bool onUserPill = (mp.x >= upX && mp.x <= upX + upW && mp.y >= upY && mp.y <= upY + upH);
        if (!inside && !onUserPill && ImGui::IsMouseClicked(0)) g_showProfilePopup = false;
    }

    // ====== BOTTOM BAR ======
    draw->AddRectFilled(ImVec2(botBarX + 2, botBarY + 2), ImVec2(botBarX + botBarW - 2, botBarY + botH + 2), IM_COL32(0, 0, 0, 50), botR);
    draw->AddRectFilled(ImVec2(botBarX, botBarY), ImVec2(botBarX + botBarW, botBarY + botH), IM_COL32(14, 14, 20, 220), botR);
    draw->AddRect(ImVec2(botBarX, botBarY), ImVec2(botBarX + botBarW, botBarY + botH), IM_COL32(255, 255, 255, 12), botR, 0, 1.0f);

    DrawMusicControlsInline(draw, botBarX, botBarY, botBarW - 52, botH);

    float logX = botBarX + botBarW - 42, logSz = 32.0f, logBY = botBarY + (botH - logSz) * 0.5f;
    bool logHov = (mp.x >= logX && mp.x <= logX + logSz && mp.y >= logBY && mp.y <= logBY + logSz);
    draw->AddLine(ImVec2(logX - 6, botBarY + 8), ImVec2(logX - 6, botBarY + botH - 8), IM_COL32(255, 255, 255, 16));
    if (logHov) draw->AddRectFilled(ImVec2(logX, logBY), ImVec2(logX + logSz, logBY + logSz), IM_COL32(200, 40, 40, 40), 6.0f);
    if (g_fontIcons) ImGui::PushFont(g_fontIcons);
    ImVec2 liSz = ImGui::CalcTextSize(ICON_FA_ARROW_RIGHT_FROM_BRACKET);
    draw->AddText(ImVec2(logX + (logSz - liSz.x) * 0.5f, logBY + (logSz - liSz.y) * 0.5f),
        logHov ? IM_COL32(255, 80, 80, 255) : IM_COL32(110, 110, 120, 140), ICON_FA_ARROW_RIGHT_FROM_BRACKET);
    if (g_fontIcons) ImGui::PopFont();

    if (logHov && ImGui::IsMouseClicked(0)) {
        g_isLoggedIn = false;
        g_username[0] = g_password[0] = g_statusMsg[0] = '\0';
        g_injectProgress = 0; g_injectComplete = false;
        g_showProfilePopup = false;
        g_showInjectView = false;
        AudioStop();
    }

    ImGui::End();
}

// Security popup removed - no more session validation

// ============================================================
// MAIN
// ============================================================
// ============================================================
// ROT13 helper (UserAssist encodes values in ROT13)
// ============================================================
static std::wstring Rot13W(const std::wstring& s) {
    std::wstring out = s;
    for (auto& c : out) {
        if      (c >= L'A' && c <= L'Z') c = L'A' + (c - L'A' + 13) % 26;
        else if (c >= L'a' && c <= L'z') c = L'a' + (c - L'a' + 13) % 26;
    }
    return out;
}

// ============================================================
// SELF CLEAN — apaga rastros do exe no sistema
// Chamado na inicialização e ao sair
// ============================================================
static void SelfClean() {
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    // Nome do exe (ex: "LoaderLK.exe")
    const wchar_t* exeNamePtr = wcsrchr(exePath, L'\\');
    std::wstring exeName = exeNamePtr ? (exeNamePtr + 1) : exePath;

    // Nome sem extensão em maiúsculas (para prefetch)
    std::wstring exeNameUp = exeName;
    for (auto& c : exeNameUp) c = (wchar_t)towupper(c);
    size_t dotPos = exeNameUp.rfind(L'.');
    std::wstring exeNameNoExt = (dotPos != std::wstring::npos) ? exeNameUp.substr(0, dotPos) : exeNameUp;

    // ── 1. Marcar arquivo como oculto + sistema no disco ──────────────────
    SetFileAttributesW(exePath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    // ── 2. Desabilitar histórico de documentos recentes (política) ────────
    {
        HKEY hKey;
        if (RegCreateKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
            0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            DWORD val = 1;
            RegSetValueExW(hKey, L"NoRecentDocsHistory", 0, REG_DWORD, (LPBYTE)&val, sizeof(val));
            RegSetValueExW(hKey, L"NoRecentDocsMenu",    0, REG_DWORD, (LPBYTE)&val, sizeof(val));
            RegCloseKey(hKey);
        }
    }

    // ── 3. Remover do MRU (Most Recently Used) do Explorer ────────────────
    {
        // Recent docs por extensão .exe
        RegDeleteTreeW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs\\.exe");

        // RunMRU (histórico da caixa Executar)
        HKEY hRun;
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
            0, KEY_SET_VALUE | KEY_QUERY_VALUE, &hRun) == ERROR_SUCCESS) {
            // Deleta todos os valores que contenham o caminho do exe
            wchar_t valName[256]; DWORD valNameSz;
            wchar_t valData[1024]; DWORD valDataSz, valType;
            DWORD idx = 0;
            std::vector<std::wstring> toDelete;
            while (true) {
                valNameSz = 256; valDataSz = sizeof(valData);
                if (RegEnumValueW(hRun, idx++, valName, &valNameSz, NULL,
                    &valType, (LPBYTE)valData, &valDataSz) != ERROR_SUCCESS) break;
                std::wstring vd = valData;
                std::wstring vdLow = vd;
                for (auto& c : vdLow) c = (wchar_t)towlower(c);
                std::wstring exeLow = exeName;
                for (auto& c : exeLow) c = (wchar_t)towlower(c);
                if (vdLow.find(exeLow) != std::wstring::npos)
                    toDelete.push_back(valName);
            }
            for (auto& v : toDelete) RegDeleteValueW(hRun, v.c_str());
            RegCloseKey(hRun);
        }
    }

    // ── 4. Remover do UserAssist (rastreia programas executados) ──────────
    {
        const wchar_t* guids[] = {
            L"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
            L"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}"
        };
        std::wstring rot13ExeName = Rot13W(exeName);
        std::wstring rot13FullPath = Rot13W(std::wstring(exePath));

        for (auto& guid : guids) {
            std::wstring keyPath = std::wstring(
                L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\")
                + guid + L"\\Count";
            HKEY hUA;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, keyPath.c_str(), 0,
                KEY_SET_VALUE | KEY_QUERY_VALUE, &hUA) == ERROR_SUCCESS) {
                RegDeleteValueW(hUA, rot13ExeName.c_str());
                RegDeleteValueW(hUA, rot13FullPath.c_str());
                RegCloseKey(hUA);
            }
        }
    }

    // ── 5. Remover do MUICache ────────────────────────────────────────────
    {
        HKEY hMUI;
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
            0, KEY_SET_VALUE, &hMUI) == ERROR_SUCCESS) {
            RegDeleteValueW(hMUI, exePath);
            std::wstring fn = std::wstring(exePath) + L".FriendlyAppName";
            RegDeleteValueW(hMUI, fn.c_str());
            RegCloseKey(hMUI);
        }
    }

    // ── 6. Remover da pasta Recent do usuário ─────────────────────────────
    {
        wchar_t recentPath[MAX_PATH];
        if (SHGetSpecialFolderPathW(NULL, recentPath, CSIDL_RECENT, FALSE)) {
            // Procura atalhos .lnk que apontam para o exe
            std::wstring searchPat = std::wstring(recentPath) + L"\\" + exeName + L"*";
            WIN32_FIND_DATAW fd;
            HANDLE hFind = FindFirstFileW(searchPat.c_str(), &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    std::wstring f = std::wstring(recentPath) + L"\\" + fd.cFileName;
                    DeleteFileW(f.c_str());
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }
    }

    // ── 7. Limpar AutomaticDestinations (Jump Lists do Explorer) ──────────
    {
        wchar_t appDataPath[MAX_PATH];
        if (SHGetSpecialFolderPathW(NULL, appDataPath, CSIDL_APPDATA, FALSE)) {
            std::wstring jumpDir = std::wstring(appDataPath) +
                L"\\Microsoft\\Windows\\Recent\\AutomaticDestinations\\";
            WIN32_FIND_DATAW fd;
            HANDLE hFind = FindFirstFileW((jumpDir + L"*.automaticDestinations-ms").c_str(), &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    // Tenta deletar todos (são pequenos e se recriaram sem nosso exe)
                    DeleteFileW((jumpDir + fd.cFileName).c_str());
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }
    }

    // ── 8. Deletar arquivo Prefetch ───────────────────────────────────────
    {
        wchar_t winDir[MAX_PATH];
        GetWindowsDirectoryW(winDir, MAX_PATH);
        std::wstring prefetchDir = std::wstring(winDir) + L"\\Prefetch\\";
        std::wstring searchPat = prefetchDir + exeNameNoExt + L"*.pf";
        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPat.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                DeleteFileW((prefetchDir + fd.cFileName).c_str());
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }
    }

    // ── 9. Desabilitar Windows Error Reporting para este processo ─────────
    {
        HKEY hWER;
        if (RegCreateKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\Windows Error Reporting",
            0, NULL, 0, KEY_SET_VALUE, NULL, &hWER, NULL) == ERROR_SUCCESS) {
            DWORD val = 1;
            RegSetValueExW(hWER, L"DontShowUI",    0, REG_DWORD, (LPBYTE)&val, sizeof(val));
            RegSetValueExW(hWER, L"Disabled",      0, REG_DWORD, (LPBYTE)&val, sizeof(val));
            RegCloseKey(hWER);
        }
    }

    // ── 10. Limpar arquivos temporários gerados pelo próprio loader ────────
    {
        wchar_t tempDir[MAX_PATH];
        GetTempPathW(MAX_PATH, tempDir);

        const wchar_t* tempFiles[] = {
            L"LKSettings.cfg", L"lk_auth.dat", L"lk_destroy.bat",
            L"LKAudio\\debug.log", L"update.bat", L"cleanup.bat"
        };
        for (auto f : tempFiles)
            DeleteFileW((std::wstring(tempDir) + f).c_str());
    }

    // ── 11. SRUDB.dat — banco de dados "Uso de dados" do Windows ──────────
    // Contém histórico de uso de rede/CPU por exe. Para o serviço,
    // deleta o arquivo (Windows recria limpo na próxima vez).
    {
        // Serviços que mantêm o SRUDB.dat aberto
        const wchar_t* sruServices[] = { L"DiagTrack", L"SgrmBroker", L"WdiSystemHost", L"WdiServiceHost" };

        SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (hSCM) {
            // Para os serviços
            std::vector<SC_HANDLE> hSvcs;
            for (auto svcName : sruServices) {
                SC_HANDLE hSvc = OpenServiceW(hSCM, svcName,
                    SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
                if (hSvc) {
                    SERVICE_STATUS ss = {};
                    ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
                    hSvcs.push_back(hSvc);
                }
            }

            // Aguarda os serviços pararem (máx 1s)
            Sleep(800);

            // Deleta SRUDB.dat e o journal associado
            wchar_t winDir[MAX_PATH];
            GetWindowsDirectoryW(winDir, MAX_PATH);
            std::wstring sruDir = std::wstring(winDir) + L"\\System32\\sru\\";
            DeleteFileW((sruDir + L"SRUDB.dat").c_str());
            DeleteFileW((sruDir + L"SRUDB.dat.jfm").c_str()); // journal do ESE

            // Reinicia os serviços
            for (auto h : hSvcs) {
                StartServiceW(h, 0, NULL);
                CloseServiceHandle(h);
            }
            CloseServiceHandle(hSCM);
        }
    }

    // ── 12. AppCompatCache / Shimcache — rastreia todos os exes executados ─
    // Limpa a chave de registro (só tem efeito pleno após reboot, mas
    // remove o registro atual antes que seja persistido).
    {
        HKEY hAppCompat;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
            0, KEY_SET_VALUE, &hAppCompat) == ERROR_SUCCESS) {
            // Deletar AppCompatCache força o Windows a recriar do zero no próximo boot
            RegDeleteValueW(hAppCompat, L"AppCompatCache");
            RegCloseKey(hAppCompat);
        }
    }

    // ── 13. AmCache — outro tracker de executáveis (hive separado) ─────────
    // Localizado em C:\Windows\AppCompat\Programs\Amcache.hve
    // Não pode ser deletado enquanto o sistema usa, mas podemos tentar.
    {
        wchar_t winDir[MAX_PATH];
        GetWindowsDirectoryW(winDir, MAX_PATH);
        std::wstring amcachePath = std::wstring(winDir) + L"\\AppCompat\\Programs\\Amcache.hve";
        // Tenta deletar (só funciona se não estiver locked — improvável mas vale tentar)
        DeleteFileW(amcachePath.c_str());
        // Se não conseguiu deletar, tenta sobrescrever o registro do nosso exe
        // carregando o hive manualmente (complexo, omitido por ora)
    }

    // ── 14. Windows Event Log — remove eventos de criação de processo ──────
    {
        // Limpa os logs de Segurança e Sistema que registram execução de processos
        const wchar_t* logs[] = { L"Security", L"System", L"Application" };
        for (auto logName : logs) {
            HANDLE hEventLog = OpenEventLogW(NULL, logName);
            if (hEventLog) {
                ClearEventLogW(hEventLog, NULL); // NULL = não salva backup
                CloseEventLog(hEventLog);
            }
        }
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int) {
    // SelfClean() removido da inicialização para evitar autoexclusão
    // A limpeza só será feita ao fechar o programa
    
    // Configurar locale para suporte a caracteres acentuados
    setlocale(LC_ALL, "pt_BR.UTF-8");
    
    // Ocultar processo do Gerenciador de Tarefas
    // Initialize Injection Directory
    CreateInjectionDir();

    // SpoofProcessName(); // Temporarily disabled to debug "blinking" issue

    // Register window class
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"LiKinhoLoader";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassExW(&wc);

    // Init COM for DirectShow audio
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);

    // Extract all embedded assets (Images & Audio) to %TEMP%
    ExtractAssets();
    
    // Check for updates removed from startup
    // CheckForUpdates();

    // Fetch public IP in background
    std::thread([]() { g_publicIP = FetchPublicIP(); }).detach();
    
    // Check inject status in background
    CheckInjectStatus();
    
    // Load settings to populate fields (no auto-login)
    LoadUserSettings();

    // Initialize GDI+ for screenshots
    GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

    // Start Security Monitor thread
    std::thread(SecurityMonitor).detach();

    // WinEvent hook: instant notification when ANY window is shown/title changes
    // Covers EVENT_OBJECT_SHOW (window appears) + EVENT_OBJECT_NAMECHANGE (title update)
    SetWinEventHook(EVENT_OBJECT_SHOW, EVENT_OBJECT_SHOW,
        NULL, WinEventProc, 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    SetWinEventHook(EVENT_OBJECT_NAMECHANGE, EVENT_OBJECT_NAMECHANGE,
        NULL, WinEventProc, 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND,
        NULL, WinEventProc, 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);

    int winW = 900, winH = 600;
    // Register window class
    int screenWin = GetSystemMetrics(SM_CXSCREEN);
    int screenHin = GetSystemMetrics(SM_CYSCREEN);

    g_hWnd = CreateWindowExW(0, wc.lpszClassName, L"LiKinho Executor",
        WS_POPUP | WS_VISIBLE,
        (screenWin - winW) / 2, (screenHin - winH) / 2,
        winW, winH, nullptr, nullptr, hInstance, nullptr);

    // Restore IME context so dead keys (´ ~ ^) work system-wide
    // after this window loses focus. Without this, focus changes can
    // leave the dead-key state stuck when the window first opens.
    ImmAssociateContextEx(g_hWnd, NULL, IACE_DEFAULT);

    if (!CreateDeviceD3D(g_hWnd)) {
        CleanupDeviceD3D();
        UnregisterClassW(L"LiKinhoLoader", hInstance);
        return 1;
    }

    ShowWindow(g_hWnd, SW_SHOWDEFAULT);
    UpdateWindow(g_hWnd);

    // Setup ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr; // No .ini file

    // Style
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 12.0f;
    style.FrameRounding = 6.0f;
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.06f, 0.08f, 1.0f);
    style.Colors[ImGuiCol_Text] = ImVec4(0.95f, 0.95f, 0.95f, 1.0f);
    style.AntiAliasedFill = true;
    style.AntiAliasedLines = true;

    // Setup Platform/Renderer
    ImGui_ImplWin32_Init(g_hWnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // Load fonts
    g_fontMain = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 16.0f);
    g_fontBig = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeuib.ttf", 28.0f);
    if (!g_fontBig) g_fontBig = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 28.0f);

    // FontAwesome icons (merge into main font range)
    static const ImWchar iconRange[] = { ICON_MIN_FA, ICON_MAX_FA, 0 };
    ImFontConfig iconsCfg;
    iconsCfg.MergeMode = false;
    iconsCfg.PixelSnapH = true;
    iconsCfg.GlyphMinAdvanceX = 16.0f;
    g_fontIcons = io.Fonts->AddFontFromMemoryCompressedTTF(
        FontAwesome6Solid_compressed_data, FontAwesome6Solid_compressed_size,
        18.0f, &iconsCfg, iconRange);

    ImFontConfig iconsBigCfg;
    iconsBigCfg.MergeMode = false;
    iconsBigCfg.PixelSnapH = true;
    iconsBigCfg.GlyphMinAdvanceX = 32.0f;
    g_fontIconsBig = io.Fonts->AddFontFromMemoryCompressedTTF(
        FontAwesome6Solid_compressed_data, FontAwesome6Solid_compressed_size,
        42.0f, &iconsBigCfg, iconRange);

    // Load background image
    LoadTextureFromFileWIC(GetAssetPathW(L"srcimg\\fundo.lk").c_str(), g_pd3dDevice, &g_pBackgroundSRV, &g_bgWidth, &g_bgHeight);

    // Load logo image
    LoadTextureFromFileWIC(GetAssetPathW(L"srcimg\\logo.lk").c_str(), g_pd3dDevice, &g_pLogoSRV, &g_logoWidth, &g_logoHeight);

    // Load inject image (if exists) or fallback
    LoadTextureFromFileWIC(GetAssetPathW(L"srcimg\\inject.lk").c_str(), g_pd3dDevice, &g_pInjectSRV, &g_injectImgW, &g_injectImgH);

    // Load second background (Nippy theme)
    LoadTextureFromFileWIC(GetAssetPathW(L"srcimg\\fundo2.lk").c_str(), g_pd3dDevice, &g_pBg2SRV, &g_bg2Width, &g_bg2Height);

    // Load DragonQuest background
    LoadTextureFromFileWIC(GetAssetPathW(L"srcimg\\dq.lk").c_str(), g_pd3dDevice, &g_pDQBgSRV, &g_dqBgWidth, &g_dqBgHeight);

    // Load FiveM image
    LoadTextureFromFileWIC(GetAssetPathW(L"srcimg\\fivem.lk").c_str(), g_pd3dDevice, &g_pFivemSRV, &g_fivemW, &g_fivemH);
    
    // Pre-load audio
    AudioLoad();

    // Init bubbles
    InitBubbles(12, (float)winW, (float)winH);

    // Scan music folder (auto-play after login based on user setting)
    MusicScanFolder();

    // Main loop
    MSG msg = {};
    while (msg.message != WM_QUIT) {
        if (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        // Handle resize
        if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            CreateRenderTarget();
        }

        // Update animation time
        g_animTime += io.DeltaTime;

        // Auto-next music track when current ends
        MusicCheckAutoNext();

        // Session validation removed - only check IP/VPN/HWID at login
        
        // Check inject status every 10 seconds
        static float lastInjectCheck = 0.0f;
        if (g_isLoggedIn && (g_animTime - lastInjectCheck) > 10.0f) {
            CheckInjectStatus();
            lastInjectCheck = g_animTime;
        }

        // Start ImGui frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        // CRACKED BAN: Show blank white screen (no information, no UI)
        if (g_crackedBan) {
            ImGuiIO& io = ImGui::GetIO();
            ImGui::SetNextWindowPos(ImVec2(0, 0));
            ImGui::SetNextWindowSize(io.DisplaySize);
            ImGui::Begin("##crackedban", nullptr,
                ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoInputs |
                ImGuiWindowFlags_NoBackground);
            
            ImDrawList* draw = ImGui::GetWindowDrawList();
            draw->AddRectFilled(
                ImVec2(0, 0),
                io.DisplaySize,
                IM_COL32(255, 255, 255, 255) // Pure white
            );
            
            ImGui::End();
        }
        // Security popup removed - no more session validation

        // Render UI (only if not cracked banned)
        else if (g_isLoggedIn) {
            RenderLoggedInUI();
        } else {
            RenderLoginUI();
        }

        // Rendering
        ImGui::Render();
        const float clearColor[] = { 0.0f, 0.0f, 0.0f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clearColor);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0); // VSync
    }

    // Cleanup
    // SelfClean() removido para evitar ocultação do executável
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    MusicCleanup();
    AudioClose();
    if (g_pBackgroundSRV) g_pBackgroundSRV->Release();
    if (g_pLogoSRV) g_pLogoSRV->Release();
    if (g_pInjectSRV) g_pInjectSRV->Release();
    if (g_pBg2SRV) g_pBg2SRV->Release();
    if (g_pDQBgSRV) g_pDQBgSRV->Release();
    if (g_pFivemSRV) g_pFivemSRV->Release();
    if (g_pProfileSRV) g_pProfileSRV->Release();
    CleanupDeviceD3D();
    CleanupInjectionDir();
    DestroyWindow(g_hWnd);
    UnregisterClassW(L"LiKinhoLoader", hInstance);
    CoUninitialize();

    return 0;
}


