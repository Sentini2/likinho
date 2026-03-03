#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <Core/SDK/Memory.hpp>

namespace FiveM {

    // Forward declarations
    class ResourceManager;
    class Resource;

    // Pattern for ResourceManager global pointer
    // Pattern: 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8D 05 ? ? ? ? 48 89 05
    // This is a LEA instruction that loads the ResourceManager pointer
    inline const char* RESOURCE_MANAGER_PATTERN = "48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8D 05 ? ? ? ? 48 89 05";

    // Get the ResourceManager instance
    inline ResourceManager* GetResourceManager() {
        static ResourceManager* cachedManager = nullptr;
        
        if (cachedManager) {
            return cachedManager;
        }

        // Get citizen-scripting-lua.dll base
        uintptr_t scriptingDll = (uintptr_t)GetModuleHandleA("citizen-scripting-lua.dll");
        if (!scriptingDll) {
            return nullptr;
        }

        // Find the pattern
        std::vector<uint8_t> pattern = Core::Mem.Pattern2Vector(RESOURCE_MANAGER_PATTERN);
        uintptr_t patternAddr = Core::Mem.FindSignature(pattern, scriptingDll, 0x500000); // Search first 5MB

        if (!patternAddr) {
            return nullptr;
        }

        // Resolve the LEA instruction (7 bytes: 48 8D 0D + 4 byte offset)
        uintptr_t globalPtr = Core::Mem.ResolveRelativeAddress(patternAddr, 7);

        // Read the actual ResourceManager pointer
        cachedManager = Core::Mem.Read<ResourceManager*>(globalPtr);
        return cachedManager;
    }

    // Simplified ResourceManager structure (based on fx::ResourceManagerImpl)
    class ResourceManager {
    public:
        char pad_0x0000[0x10];  // vTable + base class data
        
        // Get resource by name
        Resource* GetResource(const std::string& name);
        
        // Create a new custom resource
        Resource* CreateResource(const std::string& name);
    };

    // Simplified Resource structure
    class Resource {
    public:
        char pad_0x0000[0x8];   // vTable
        std::string m_name;      // Resource name
        char pad_after_name[0x100]; // Other members
        
        // Execute Lua code in this resource's context
        bool ExecuteScript(const std::string& code);
    };

    // Initialize the "likinho" resource with full Lua environment
    Resource* InitializeLiKinhoResource();

    // Execute Lua code through the "likinho" resource
    bool ExecuteInLiKinho(const std::string& code);
}


