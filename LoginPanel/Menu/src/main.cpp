#pragma once
#include <Gui/Overlay/Overlay.hpp>
#include <Includes/Includes.hpp>
#include <Core/SDK/Memory.hpp>
#include <Includes/Utils.hpp>
#include <Core/SDK/SDK.hpp>
// FiveM_SDK removed - Lua execution happens in the injected DLL, not in the EXE
#include <Core/Core.hpp>
#include <Gui/gui.hpp>
#include <winternl.h>
#include <windows.h>
#include <dwmapi.h>
#include <tchar.h>
#include <vector>
#include <regex>
#include <string>
#include <TlHelp32.h>

#include <Security/AntiCrack.hpp>
#include <Includes/CustomWidgets/Custom.hpp>

#include <Utils/DllExtractor.hpp>

using namespace Core;

HMODULE g_hMod = NULL;

bool InjectDLL(DWORD processId, const std::string& dllPath)
{
	// Check if DLL file exists
	if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES)
		return false;

	// Open target process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
	if (!hProcess) return false;

	// Allocate memory in remote process for DLL path string
	void* pRemoteMem = VirtualAllocEx(hProcess, nullptr, dllPath.size() + 1,
		MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pRemoteMem) {
		CloseHandle(hProcess);
		return false;
	}

	// Write DLL path into remote process memory
	WriteProcessMemory(hProcess, pRemoteMem, dllPath.c_str(), dllPath.size() + 1, nullptr);

	// Create remote thread calling LoadLibraryA with our DLL path
	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
		(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"),
		pRemoteMem, 0, nullptr);

	if (hThread) {
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
	}

	VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	return hThread != nullptr;
}

DWORD WINAPI MenuThread(LPVOID lpParam)
{
	// --- Security Check ---
	// std::string args(__argv[0]); 
	// ----------------------

	// Extracting embedded DLLs is redundant and fails in explorer.exe due to permissions.
	// The LoaderLK already extracts all files to a temporary folder.

	if (!Mem.GetMaxPrivileges(GetCurrentProcess()))
	{
		return 0;
	}

	// Initialize GDI+ for screenshots
	Gdiplus::GdiplusStartupInput gdiplusStartupInput;
	ULONG_PTR gdiplusToken;
	Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

	while (!g_Variables.g_hGameWindow)
	{
		g_Variables.g_hGameWindow = FindWindowA(xorstr("grcWindow"), nullptr);
		if (g_Variables.g_hGameWindow)
		{
			auto WindowInfo = Utils::GetWindowPosAndSize(g_Variables.g_hGameWindow);
			g_Variables.g_vGameWindowSize = WindowInfo.second;
			g_Variables.g_vGameWindowPos = WindowInfo.first;
			g_Variables.g_vGameWindowCenter = { g_Variables.g_vGameWindowSize.x / 2, g_Variables.g_vGameWindowSize.y / 2 };
			
			// Force FiveM window to foreground so overlay appears over it
			SetForegroundWindow(g_Variables.g_hGameWindow);
			Sleep(100); // Small delay to ensure window focus transition
			
			break;
		}
		Sleep(500);
	}

	GetWindowThreadProcessId(g_Variables.g_hGameWindow, &g_Variables.ProcIdFiveM);

	// Build base path: same folder as this DLL (MenuLoader.dll)
	char dllFolderPath[MAX_PATH];
	GetModuleFileNameA(g_hMod, dllFolderPath, MAX_PATH);
	std::string basePath(dllFolderPath);
	basePath = basePath.substr(0, basePath.find_last_of('\\') + 1);

	// List of dependencies to inject into FiveM process
	std::vector<std::string> dependencies = {
		"vcruntime140.dll",
		"msvcp140.dll",
		"vcruntime140_1.dll",
		"msvcp140_1.dll",
		"D3DCompiler_43.dll",
		"d3dx9_43.dll",
		"d3dx10_43.dll",
		"d3dx11_43.dll"
	};

	// Inject each dependency
	for (const auto& dep : dependencies) {
		InjectDLL(g_Variables.ProcIdFiveM, basePath + dep);
	}

	// Finally inject the Executor DLL (LK_Executor.dll) into FiveM process
	InjectDLL(g_Variables.ProcIdFiveM, basePath + "LK_Executor.dll");
	
	std::thread(&AntiCrack::DoProtect).detach();
	Core::SetupOffsets();
	
	// Read Menu Key status from temp file (set by LoaderLK)
	char tempPath[MAX_PATH];
	GetTempPathA(MAX_PATH, tempPath);
	std::string authPath = std::string(tempPath) + "lk_auth.dat";
	std::ifstream authFile(authPath);
	if (authFile.is_open()) {
		std::string status;
		std::getline(authFile, status);
		if (status == "active") {
			g_MenuInfo.HasMenuKey = true;
		}
		// Optional: delete file after reading for security? 
		// authFile.close();
		// DeleteFileA(authPath.c_str());
	}

	// DLL injection handles Lua execution - EXE just provides the UI overlay
	
	Gui::cOverlay.Render();

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		g_hMod = hModule;
		DisableThreadLibraryCalls(hModule);
		CreateThread(NULL, 0, MenuThread, NULL, 0, NULL);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

std::string hwid;