#include "includes.h"
#include <map>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include "include/xorstr/xorstr.hpp"
#include "cfx/resource.h"
#include "cfx/resource_manager.h"
#include "cfx/resource_creator.h"
#include "../SharedExecutor.hpp"

// Globals for Executor
static HANDLE hSharedMem = NULL;
static SharedExecutorData* pShared = nullptr;

void ExecuteScript(const std::string& script, const std::string& customPrefix)
{
    auto& creator = ResourceCreator::Instance();

    // Set resource name from customPrefix (default: "likinho")
    // The ResourceCreator always creates its own resource

    // Execute through ResourceCreator
    bool success = creator.ExecuteScript(script);
    
    if (!success) {
        // Log the error
        OutputDebugStringA(("ExecuteScript failed: " + creator.GetStatus() + "\n").c_str());
    }
}

void SharedMemoryLoop()
{
    // Create shared memory (DLL creates it)
    hSharedMem = CreateSharedMemory(true);
    if (!hSharedMem) return;

    pShared = MapSharedMemory(hSharedMem);
    if (!pShared) return;

    // Zero out
    memset(pShared, 0, sizeof(SharedExecutorData));
    pShared->dllReady = true; // Signal immediately that DLL is injected
    pShared->resourceReady = false;
    strcpy_s(pShared->statusMessage, "Conectado. Injetor Pronto.");

    // Initialize ResourceCreator
    auto& creator = ResourceCreator::Instance();
    
    // Try to initialize (will wait for DLLs)
    if (creator.Initialize()) {
        pShared->dllReady = true;
        pShared->resourceReady = creator.IsReady();
        strcpy_s(pShared->resourceName, creator.GetResourceName().c_str());
        strcpy_s(pShared->statusMessage, creator.GetStatus().c_str());
    } else {
        pShared->dllReady = true; // DLL is connected, even if resource failed
        pShared->resourceReady = false;
        strcpy_s(pShared->resourceName, creator.GetResourceName().c_str());
        strcpy_s(pShared->statusMessage, creator.GetStatus().c_str());
    }

    while (true)
    {
        Sleep(50);

        if (!pShared) break;

        // Update status
        if (!pShared->dllReady && creator.IsReady()) {
            pShared->dllReady = true;
        }
        pShared->resourceReady = creator.IsReady();

        // Handle execute script request
        if (pShared->executeFlag)
        {
            std::string script(pShared->scriptBuffer);
            std::string customPrefix(pShared->customPrefix);

            strcpy_s(pShared->statusMessage, "Executando...");

            try {
                ExecuteScript(script, customPrefix);
                strcpy_s(pShared->statusMessage, creator.GetStatus().c_str());
            }
            catch (...) {
                strcpy_s(pShared->statusMessage, "Execution failed!");
            }

            pShared->executeFlag = false;
        }

        // Handle reset/uninject request
        if (pShared->resetFlag)
        {
            strcpy_s(pShared->statusMessage, "Resetando...");
            
            try {
                creator.ResetAll();
                strcpy_s(pShared->statusMessage, creator.GetStatus().c_str());
            }
            catch (...) {
                strcpy_s(pShared->statusMessage, "Reset failed!");
            }

            pShared->resetFlag = false;
        }
    }
}

BOOL WINAPI DllMain(HMODULE hMod, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hMod);
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)SharedMemoryLoop, hMod, 0, nullptr);
        break;
    case DLL_PROCESS_DETACH:
        ResourceCreator::Instance().Shutdown();
        if (pShared) {
            pShared->dllReady = false;
            UnmapViewOfFile(pShared);
        }
        if (hSharedMem) CloseHandle(hSharedMem);
        break;
    }
    return TRUE;
}

