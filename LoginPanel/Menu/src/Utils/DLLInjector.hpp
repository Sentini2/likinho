#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <iostream>

namespace DLLInjector
{
    // Find process ID by name
    DWORD GetProcessIdByName(const char* processName)
    {
        DWORD processId = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if (snapshot != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32 processEntry;
            processEntry.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(snapshot, &processEntry))
            {
                do
                {
                    if (_stricmp(processEntry.szExeFile, processName) == 0)
                    {
                        processId = processEntry.th32ProcessID;
                        break;
                    }
                } while (Process32Next(snapshot, &processEntry));
            }
            CloseHandle(snapshot);
        }
        
        return processId;
    }

    // Inject DLL into target process
    bool InjectDLL(DWORD processId, const char* dllPath)
    {
        // Open target process
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess)
        {
            return false;
        }

        // Allocate memory in target process
        size_t dllPathLen = strlen(dllPath) + 1;
        LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, dllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pDllPath)
        {
            CloseHandle(hProcess);
            return false;
        }

        // Write DLL path to target process memory
        if (!WriteProcessMemory(hProcess, pDllPath, dllPath, dllPathLen, NULL))
        {
            VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Get LoadLibraryA address
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
        if (!pLoadLibrary)
        {
            VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Create remote thread to load DLL
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
            (LPTHREAD_START_ROUTINE)pLoadLibrary, pDllPath, 0, NULL);
        
        if (!hThread)
        {
            VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }

        // Wait for thread to finish
        WaitForSingleObject(hThread, INFINITE);

        // Cleanup
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hThread);
        CloseHandle(hProcess);

        return true;
    }

    // Find any FiveM GTA process (any build)
    DWORD FindFiveMProcess()
    {
        DWORD processId = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if (snapshot != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32 processEntry;
            processEntry.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(snapshot, &processEntry))
            {
                do
                {
                    std::string name = processEntry.szExeFile;
                    // Match FiveM_GTAProcess.exe or FiveM_b####_GTAProcess.exe
                    if (name == "FiveM_GTAProcess.exe" ||
                        (name.find("FiveM_b") == 0 && name.find("_GTAProcess.exe") != std::string::npos))
                    {
                        processId = processEntry.th32ProcessID;
                        break;
                    }
                } while (Process32Next(snapshot, &processEntry));
            }
            CloseHandle(snapshot);
        }
        
        return processId;
    }

    // Inject Executor DLL into FiveM process
    bool InjectExecutorDLL()
    {
        // Find any FiveM GTA process
        DWORD fivemPid = FindFiveMProcess();
        if (fivemPid == 0)
        {
            MessageBoxA(NULL, "FiveM GTA process not found!\nMake sure FiveM is running and you're in a server or story mode.", "Injection Error", MB_OK | MB_ICONERROR);
            return false;
        }

        // Get current directory
        char currentDir[MAX_PATH];
        GetModuleFileNameA(NULL, currentDir, MAX_PATH);
        std::string exePath(currentDir);
        std::string exeDir = exePath.substr(0, exePath.find_last_of("\\/"));

        // Try to find DLL in multiple locations
        std::vector<std::string> possiblePaths = {
            exeDir + "\\d3d9.dll",  // Same directory as EXE
            exeDir + "\\..\\FiveM Executor\\x64\\Release\\d3d9.dll",
            exeDir + "\\FiveM Executor.dll"  // Fallback
        };

        for (const auto& dllPath : possiblePaths)
        {
            // Check if file exists
            DWORD attrib = GetFileAttributesA(dllPath.c_str());
            if (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY))
            {
                // File exists, try to inject
                if (InjectDLL(fivemPid, dllPath.c_str()))
                {
                    MessageBoxA(NULL, ("Executor DLL injected successfully!\nPath: " + dllPath).c_str(), "Injection Success", MB_OK | MB_ICONINFORMATION);
                    return true;
                }
            }
        }

        MessageBoxA(NULL, "Could not find d3d9.dll in any expected location!", "Injection Error", MB_OK | MB_ICONERROR);
        return false;
    }
}
