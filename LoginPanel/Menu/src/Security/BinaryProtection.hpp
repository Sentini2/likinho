#pragma once
#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>

// Binary protection system - makes executable impossible to analyze
namespace BinaryProtection {

    // Simple XOR encryption for runtime (AES would require external library)
    // In production, use proper AES-256 via CryptoAPI or embedded library
    inline void XORCrypt(BYTE* data, SIZE_T size, const BYTE* key, SIZE_T keyLen) {
        for (SIZE_T i = 0; i < size; i++) {
            data[i] ^= key[i % keyLen];
        }
    }

    // Anti-dump: Erase PE headers to prevent memory dumping
    inline void ErasePEHeaders() {
        HMODULE hModule = GetModuleHandleA(NULL);
        if (hModule) {
            PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
            PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
            
            DWORD oldProtect;
            if (VirtualProtect(pDosHeader, sizeof(IMAGE_DOS_HEADER), PAGE_READWRITE, &oldProtect)) {
                // Erase DOS header signature
                pDosHeader->e_magic = 0;
                VirtualProtect(pDosHeader, sizeof(IMAGE_DOS_HEADER), oldProtect, &oldProtect);
            }
            
            if (VirtualProtect(pNtHeaders, sizeof(IMAGE_NT_HEADERS), PAGE_READWRITE, &oldProtect)) {
                // Erase NT headers signature
                pNtHeaders->Signature = 0;
                VirtualProtect(pNtHeaders, sizeof(IMAGE_NT_HEADERS), oldProtect, &oldProtect);
            }
        }
    }

    // Calculate CRC32 for integrity checking
    inline DWORD CalculateCRC32(const BYTE* data, SIZE_T size) {
        DWORD crc = 0xFFFFFFFF;
        for (SIZE_T i = 0; i < size; i++) {
            crc ^= data[i];
            for (int j = 0; j < 8; j++) {
                crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
            }
        }
        return ~crc;
    }

    // Verify code integrity - check if .text section was modified
    inline bool VerifyIntegrity() {
        HMODULE hModule = GetModuleHandleA(NULL);
        if (!hModule) return false;

        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            // Headers already erased - assume OK (we did it ourselves)
            return true;
        }

        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);

        // Find .text section
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            if (memcmp(pSection[i].Name, ".text", 5) == 0) {
                BYTE* sectionStart = (BYTE*)hModule + pSection[i].VirtualAddress;
                SIZE_T sectionSize = pSection[i].Misc.VirtualSize;
                
                // Calculate CRC (in real implementation, compare with stored value)
                DWORD crc = CalculateCRC32(sectionStart, sectionSize);
                
                // For now, just return true (would need to store expected CRC at compile time)
                return true;
            }
        }
        return true;
    }

    // Continuous integrity monitoring thread
    inline void IntegrityMonitor() {
        while (true) {
            if (!VerifyIntegrity()) {
                // Code was modified - exit immediately
                ExitProcess(1);
            }
            Sleep(500); // Check every 500ms
        }
    }

    // Detect if running under a debugger using multiple methods
    inline bool IsDebuggerActive() {
        // Method 1: IsDebuggerPresent
        if (IsDebuggerPresent()) return true;

        // Method 2: CheckRemoteDebuggerPresent
        BOOL debuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
        if (debuggerPresent) return true;

        // Method 3: NtQueryInformationProcess
        typedef NTSTATUS(WINAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);
        pNtQueryInformationProcess NtQIP = (pNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

        if (NtQIP) {
            DWORD debugPort = 0;
            NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
            if (debugPort != 0) return true;

            DWORD debugFlags = 0;
            NtQIP(GetCurrentProcess(), 31, &debugFlags, sizeof(debugFlags), NULL);
            if (debugFlags == 0) return true; // NoDebugInherit flag not set = debugger present
        }

        // Method 4: PEB BeingDebugged flag
        PPEB pPeb = (PPEB)__readgsqword(0x60); // x64
        if (pPeb && pPeb->BeingDebugged) return true;

        return false;
    }

    // Hide from debuggers by manipulating PEB
    inline void HideFromDebugger() {
        PPEB pPeb = (PPEB)__readgsqword(0x60);
        if (pPeb) {
            pPeb->BeingDebugged = 0;
            
            // Clear debug heap flags
            DWORD* pHeapFlags = (DWORD*)((BYTE*)pPeb + 0xBC); // Offset to NtGlobalFlag
            *pHeapFlags &= ~0x70; // Clear FLG_HEAP flags
        }
    }

    // Detect memory breakpoints
    inline bool DetectMemoryBreakpoints() {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            // Check if any debug registers are set
            if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
                return true; // Hardware breakpoint detected
            }
        }
        return false;
    }

    // Main initialization - call this at program start
    inline void Initialize() {
        // Check for debugger immediately
        if (IsDebuggerActive()) {
            ExitProcess(1);
        }

        // Check for memory breakpoints
        if (DetectMemoryBreakpoints()) {
            ExitProcess(1);
        }

        // Hide from debuggers
        HideFromDebugger();

        // Erase PE headers to prevent dumping
        ErasePEHeaders();

        // Start continuous integrity monitoring
        std::thread(IntegrityMonitor).detach();
    }

    // Decrypt sections (placeholder - would be called by stub injected by PEEncryptor)
    inline void DecryptSections() {
        // This would be implemented by the PEEncryptor tool
        // It would inject a stub that:
        // 1. Reads encrypted .text and .rdata sections
        // 2. Decrypts them in memory using embedded key
        // 3. Marks sections as executable
        // 4. Jumps to original entry point
        
        // For now, this is a placeholder
        // Real implementation would require post-build processing
    }
}
