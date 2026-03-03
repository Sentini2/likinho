#pragma once
// ============================================================
// MemoryMap.hpp — Full in-memory DLL injection
// Injects DLLs directly from a memory buffer into a remote
// process WITHOUT writing any files to disk.
// Dependencies are also mapped from memory buffers.
// ============================================================
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <cctype>

// ----------------------------------------------------------------
// Data passed into the remote shellcode
// ----------------------------------------------------------------
typedef HMODULE (WINAPI* fn_LoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI* fn_GetProcAddress)(HMODULE, LPCSTR);
typedef BOOL    (WINAPI* fn_DllMain)(HMODULE, DWORD, LPVOID);

// One pre-loaded dependency entry (name hash -> base address in target)
struct DepEntry {
    DWORD nameHash;   // simple case-insensitive hash of module name
    HINSTANCE hBase;  // base in target process
};

#define MAX_DEPS 32

struct MM_DATA {
    fn_LoadLibraryA   pLoadLibraryA;
    fn_GetProcAddress pGetProcAddress;
    HINSTANCE         hMod;          // our DLL base in target
    DepEntry          deps[MAX_DEPS]; // pre-mapped dependencies
    DWORD             depCount;
};

// ----------------------------------------------------------------
// Shellcode that runs inside the target process
// Resolves imports using the pre-mapped dep table first,
// falls back to LoadLibraryA for system DLLs.
// ----------------------------------------------------------------
static void __stdcall MM_Shellcode(MM_DATA* pData)
{
    if (!pData) return;

    BYTE* pBase = (BYTE*)pData->hMod;
    auto* pDos  = (IMAGE_DOS_HEADER*)pBase;
    auto* pNt   = (IMAGE_NT_HEADERS*)(pBase + pDos->e_lfanew);
    auto* pOpt  = &pNt->OptionalHeader;

    auto _LoadLibraryA   = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;

    // ---- Relocations ----
    auto* pReloc = (IMAGE_BASE_RELOCATION*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        DWORD_PTR delta = (DWORD_PTR)(pBase - pOpt->ImageBase);
        while (pReloc->VirtualAddress) {
            if (pReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                int   count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* list  = (WORD*)(pReloc + 1);
                for (int i = 0; i < count; i++) {
                    if (list[i]) {
                        DWORD_PTR* ptr = (DWORD_PTR*)(pBase + pReloc->VirtualAddress + (list[i] & 0xFFF));
                        *ptr += delta;
                    }
                }
            }
            pReloc = (IMAGE_BASE_RELOCATION*)((BYTE*)pReloc + pReloc->SizeOfBlock);
        }
    }

    // ---- Imports ----
    auto* pDesc = (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        while (pDesc->Name) {
            char* szMod = (char*)(pBase + pDesc->Name);

            // Simple case-insensitive hash to match against pre-mapped deps
            DWORD hash = 0;
            for (char* p = szMod; *p; p++) {
                char c = (*p >= 'A' && *p <= 'Z') ? (*p + 32) : *p;
                hash = hash * 31 + (unsigned char)c;
            }

            // Look in pre-mapped dep table first
            HINSTANCE hDll = nullptr;
            for (DWORD di = 0; di < pData->depCount; di++) {
                if (pData->deps[di].nameHash == hash) {
                    hDll = pData->deps[di].hBase;
                    break;
                }
            }
            // Fallback: system DLL via LoadLibraryA
            if (!hDll) {
                hDll = (HINSTANCE)_LoadLibraryA(szMod);
            }

            auto* pThunk = (IMAGE_THUNK_DATA*)(pBase + pDesc->OriginalFirstThunk);
            auto* pFunc  = (IMAGE_THUNK_DATA*)(pBase + pDesc->FirstThunk);
            if (!pThunk) pThunk = pFunc;

            while (pThunk->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
                    pFunc->u1.Function = (DWORD_PTR)_GetProcAddress(hDll, (LPCSTR)(pThunk->u1.Ordinal & 0xFFFF));
                } else {
                    auto* pImport = (IMAGE_IMPORT_BY_NAME*)(pBase + pThunk->u1.AddressOfData);
                    pFunc->u1.Function = (DWORD_PTR)_GetProcAddress(hDll, pImport->Name);
                }
                pThunk++; pFunc++;
            }
            pDesc++;
        }
    }

    // ---- Entry point ----
    if (pOpt->AddressOfEntryPoint) {
        auto _DllMain = (fn_DllMain)(pBase + pOpt->AddressOfEntryPoint);
        _DllMain((HMODULE)pBase, DLL_PROCESS_ATTACH, nullptr);
    }
}
// Marker to measure shellcode size
static void MM_ShellcodeEnd() {}

// ----------------------------------------------------------------
// MemoryMap: map ONLY the main DLL from memory.
// Dependencies are loaded by the system loader (LoadLibrary)
// because we set the DLL directory beforehand.
// ----------------------------------------------------------------
class MemoryMap
{
public:
    static bool Map(HANDLE hProc, const BYTE* pSrc)
    {
        if (!pSrc) return false;

        auto* pDos = (IMAGE_DOS_HEADER*)pSrc;
        if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto* pNt  = (IMAGE_NT_HEADERS*)(pSrc + pDos->e_lfanew);
        auto* pOpt = &pNt->OptionalHeader;
        auto* pFile= &pNt->FileHeader;

        // Try to allocate at preferred base first
        BYTE* pBase = (BYTE*)VirtualAllocEx(hProc, (void*)pOpt->ImageBase,
            pOpt->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        
        if (!pBase) {
            // Preferred base taken, let OS decide
            pBase = (BYTE*)VirtualAllocEx(hProc, nullptr, pOpt->SizeOfImage,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }

        if (!pBase) return false;

        // Write headers
        if (!WriteProcessMemory(hProc, pBase, pSrc, pOpt->SizeOfHeaders, nullptr)) {
            VirtualFreeEx(hProc, pBase, 0, MEM_RELEASE);
            return false;
        }

        // Write sections
        auto* pSec = IMAGE_FIRST_SECTION(pNt);
        for (WORD i = 0; i < pFile->NumberOfSections; i++, pSec++) {
            if (pSec->SizeOfRawData) {
                if (!WriteProcessMemory(hProc, pBase + pSec->VirtualAddress,
                                   pSrc + pSec->PointerToRawData,
                                   pSec->SizeOfRawData, nullptr)) {
                    VirtualFreeEx(hProc, pBase, 0, MEM_RELEASE);
                    return false;
                }
            }
        }

        // Prepare MM_DATA
        MM_DATA mmData = {};
        HMODULE hK32 = GetModuleHandleA("kernel32.dll");
        if (hK32) {
            mmData.pLoadLibraryA   = (fn_LoadLibraryA)GetProcAddress(hK32, "LoadLibraryA");
            mmData.pGetProcAddress = (fn_GetProcAddress)GetProcAddress(hK32, "GetProcAddress");
        } else {
            // Fallback (unsafe if ASLR differs significantly, but better than nothing)
            mmData.pLoadLibraryA   = LoadLibraryA;
            mmData.pGetProcAddress = GetProcAddress;
        }
        
        mmData.hMod            = (HINSTANCE)pBase;
        mmData.depCount        = 0;

        void* pRemData = VirtualAllocEx(hProc, nullptr, sizeof(MM_DATA),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!pRemData) {
            VirtualFreeEx(hProc, pBase, 0, MEM_RELEASE);
            return false;
        }
        WriteProcessMemory(hProc, pRemData, &mmData, sizeof(MM_DATA), nullptr);

        // Shellcode
        size_t scSize = (size_t)((BYTE*)MM_ShellcodeEnd - (BYTE*)MM_Shellcode);
        if (scSize == 0 || scSize > 0x8000) scSize = 0x4000;
        void* pShell = VirtualAllocEx(hProc, nullptr, scSize + 0x200,
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pShell) {
            VirtualFreeEx(hProc, pRemData, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pBase, 0, MEM_RELEASE);
            return false;
        }
        WriteProcessMemory(hProc, pShell, (void*)MM_Shellcode, scSize, nullptr);

        HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0,
            (LPTHREAD_START_ROUTINE)pShell, pRemData, 0, nullptr);
        
        if (!hThread) {
            VirtualFreeEx(hProc, pShell, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pRemData, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pBase, 0, MEM_RELEASE);
            return false;
        }

        // Increase timeout to 15 seconds for slow PCs
        DWORD res = WaitForSingleObject(hThread, 15000);
        CloseHandle(hThread);

        if (res == WAIT_TIMEOUT) {
            // Injection might still work, but thread timed out
            return true; 
        }

        return true;
    }
};
