#pragma once
#include <windows.h>
#include <string>

// Forward declarations
extern "C" {
    #include <Includes/lua.h>
    #include <Includes/lualib.h>
    #include <Includes/lauxlib.h>
}

namespace FiveM {

    // Lua Environment Manager for the LiKinho resource
    class LuaEnvironment {
    private:
        lua_State* L;
        bool initialized;

    public:
        LuaEnvironment();
        ~LuaEnvironment();

        // Initialize the Lua state
        bool Initialize();

        // Execute Lua code
        bool ExecuteString(const std::string& code);

        // Execute Lua file
        bool ExecuteFile(const std::string& filepath);

        // Get the Lua state
        lua_State* GetState() { return L; }

        // Check if initialized
        bool IsInitialized() const { return initialized; }

        // Register a C function to Lua
        void RegisterFunction(const char* name, lua_CFunction func);

        // Register the Citizen API
        void RegisterCitizenAPI();

    private:
        // Error handler
        void HandleError(const std::string& error);
    };

    // Global Lua environment instance for LiKinho
    extern LuaEnvironment* g_LiKinhoLua;

    // Initialize the global Lua environment
    bool InitializeLuaEnvironment();

    // Execute code in the LiKinho Lua environment
    bool ExecuteLuaCode(const std::string& code);
}


