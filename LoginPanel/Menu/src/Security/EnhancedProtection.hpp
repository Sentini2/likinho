#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <thread>
#include <algorithm>

// Ultra-fast protection system - detects and kills cracking tools INSTANTLY
namespace EnhancedProtection {

    // Lista completa de processos bloqueados
    static const std::vector<std::string> BLACKLISTED_PROCESSES = {
        // Debuggers
        "x64dbg.exe", "x32dbg.exe", "ollydbg.exe", "windbg.exe", "ida64.exe", "ida.exe", "idag.exe", "idag64.exe",
        "immunitydebugger.exe", "immunity debugger.exe", "hyperdbg.exe",
        
        // Process Monitors
        "processhacker.exe", "processhacker2.exe", "processhacker3.exe", "procexp.exe", "procexp64.exe", 
        "systeminformer.exe", "systemexplorer.exe", "process explorer.exe",
        
        // Hex Editors
        "hxd.exe", "010editor.exe", "hexworkshop.exe", "hexedit.exe", "hex editor.exe", "hexeditor.exe",
        "hexfiend.exe", "frhed.exe", "wxhexeditor.exe",
        
        // PE Tools
        "pe-bear.exe", "cff explorer.exe", "cffexplorer.exe", "lordpe.exe", "petools.exe", "pestudio.exe",
        "pe explorer.exe", "peexplorer.exe", "resource hacker.exe", "resourcehacker.exe",
        
        // Dumpers
        "scylla.exe", "scylla_x64.exe", "scylla_x86.exe", "megadumper.exe", "extremedumper.exe",
        "procdump.exe", "procdump64.exe", "ksdumper.exe",
        
        // Network Sniffers
        "wireshark.exe", "fiddler.exe", "charles.exe", "burpsuite.exe", "mitmproxy.exe",
        "httpdebugger.exe", "httpdebuggerui.exe", "httpanalyzer.exe",
        
        // Disassemblers
        "ghidra.exe", "ghidrarun.exe", "binaryninja.exe", "hopper.exe", "radare2.exe", "r2.exe",
        "cutter.exe", "iaito.exe",
        
        // Cheat Tools
        "cheatengine.exe", "cheat engine.exe", "cheatengine-x86_64.exe", "cheatengine-i386.exe",
        "artmoney.exe", "gameguardian.exe", "scanmem.exe",
        
        // Decompilers
        "dnspy.exe", "dnspy-x86.exe", "ilspy.exe", "dotpeek.exe", "justdecompile.exe",
        
        // Other Analysis Tools
        "procmon.exe", "procmon64.exe", "apimonitor.exe", "api monitor.exe", "regshot.exe",
        "die.exe", "detectiteasy.exe", "exeinfope.exe", "peid.exe", "protection_id.exe",
        "strings.exe", "strings64.exe", "dependency walker.exe", "depends.exe"
    };

    // Lista de títulos de janela suspeitos
    static const std::vector<std::string> BLACKLISTED_WINDOW_TITLES = {
        "process hacker", "system informer", "x64dbg", "x32dbg", "ollydbg", "windbg",
        "debugger", "cheat engine", "http debugger", "wireshark", "dnspy", "ida pro",
        "ghidra", "binary ninja", "hex editor", "hxd", "010 editor", "pe-bear",
        "cff explorer", "scylla", "megadumper", "fiddler", "burp suite", "hopper",
        "radare2", "cutter", "pestudio", "resource hacker", "apimonitor", "process monitor",
        "process explorer", "procmon", "detect it easy", "exeinfo", "protection id"
    };

    // Kill process instantly without any delay
    inline void KillProcessInstantly(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess) {
            TerminateProcess(hProcess, 1);
            CloseHandle(hProcess);
        } else {
            // If we can't kill the process, exit ourselves to prevent analysis
            ExitProcess(1);
        }
    }

    // Thread 1: Ultra-fast process scanner (50ms interval)
    inline void ProcessScanner() {
        while (true) {
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe32;
                pe32.dwSize = sizeof(PROCESSENTRY32);
                
                if (Process32First(hSnapshot, &pe32)) {
                    do {
                        std::string processName = pe32.szExeFile;
                        std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);
                        
                        for (const auto& blacklisted : BLACKLISTED_PROCESSES) {
                            if (processName == blacklisted) {
                                KillProcessInstantly(pe32.th32ProcessID);
                                break;
                            }
                        }
                    } while (Process32Next(hSnapshot, &pe32));
                }
                CloseHandle(hSnapshot);
            }
            Sleep(50); // 50ms = ultra-fast detection
        }
    }

    // Thread 2: Window title scanner (50ms interval)
    static BOOL CALLBACK WindowEnumCallback(HWND hWnd, LPARAM lParam) {
        if (!IsWindowVisible(hWnd)) return TRUE;
        
        char title[256];
        if (GetWindowTextA(hWnd, title, sizeof(title)) > 0) {
            std::string sTitle = title;
            std::transform(sTitle.begin(), sTitle.end(), sTitle.begin(), ::tolower);
            
            for (const auto& blacklisted : BLACKLISTED_WINDOW_TITLES) {
                if (sTitle.find(blacklisted) != std::string::npos) {
                    DWORD pid = 0;
                    GetWindowThreadProcessId(hWnd, &pid);
                    if (pid != 0) {
                        KillProcessInstantly(pid);
                    }
                    return FALSE;
                }
            }
        }
        return TRUE;
    }

    inline void WindowScanner() {
        while (true) {
            EnumWindows(WindowEnumCallback, 0);
            Sleep(50);
        }
    }

    // Thread 3: Handle scanner - detect processes with handles to our process
    inline void HandleScanner() {
        while (true) {
            DWORD currentPid = GetCurrentProcessId();
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe32;
                pe32.dwSize = sizeof(PROCESSENTRY32);
                
                if (Process32First(hSnapshot, &pe32)) {
                    do {
                        if (pe32.th32ProcessID == currentPid || pe32.th32ProcessID == 4) continue;
                        
                        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
                        if (hProcess) {
                            // Check if this process has a handle to us
                            HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, currentPid);
                            if (hTargetProcess) {
                                // This process can access us - might be a debugger
                                char exePath[MAX_PATH];
                                if (GetModuleFileNameExA(hProcess, NULL, exePath, MAX_PATH)) {
                                    std::string processName = exePath;
                                    std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);
                                    
                                    // Check if it's a known analysis tool
                                    for (const auto& blacklisted : BLACKLISTED_PROCESSES) {
                                        if (processName.find(blacklisted) != std::string::npos) {
                                            CloseHandle(hTargetProcess);
                                            CloseHandle(hProcess);
                                            KillProcessInstantly(pe32.th32ProcessID);
                                            break;
                                        }
                                    }
                                }
                                CloseHandle(hTargetProcess);
                            }
                            CloseHandle(hProcess);
                        }
                    } while (Process32Next(hSnapshot, &pe32));
                }
                CloseHandle(hSnapshot);
            }
            Sleep(100); // Slightly slower as this is more intensive
        }
    }

    // Thread 4: Anti-debugging checks
    inline void AntiDebugScanner() {
        while (true) {
            // IsDebuggerPresent
            if (IsDebuggerPresent()) {
                ExitProcess(1);
            }
            
            // CheckRemoteDebuggerPresent
            BOOL debuggerPresent = FALSE;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
            if (debuggerPresent) {
                ExitProcess(1);
            }
            
            // NtQueryInformationProcess check
            typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);
            pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(
                GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
            
            if (NtQIP) {
                DWORD debugPort = 0;
                NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL); // ProcessDebugPort
                if (debugPort != 0) {
                    ExitProcess(1);
                }
            }
            
            Sleep(100);
        }
    }

    // Main protection starter - launches all threads
    inline void StartProtection() {
        std::thread(ProcessScanner).detach();
        std::thread(WindowScanner).detach();
        std::thread(HandleScanner).detach();
        std::thread(AntiDebugScanner).detach();
    }
}
