#include "LuaEnvironment.hpp"
#include "CitizenAPI.hpp"
#include <iostream>

namespace FiveM {

    // Global Lua environment instance
    LuaEnvironment* g_LiKinhoLua = nullptr;

    LuaEnvironment::LuaEnvironment() : L(nullptr), initialized(false) {
    }

    LuaEnvironment::~LuaEnvironment() {
        if (L) {
            lua_close(L);
            L = nullptr;
        }
        initialized = false;
    }

    bool LuaEnvironment::Initialize() {
        if (initialized) {
            return true;
        }

        // Create new Lua state
        L = luaL_newstate();
        if (!L) {
            HandleError("Failed to create Lua state");
            return false;
        }

        // Load standard Lua libraries
        luaL_openlibs(L);

        // Register Citizen API
        RegisterCitizenAPI();

        initialized = true;
        std::cout << "[LiKinho] Lua environment initialized successfully" << std::endl;
        return true;
    }

    bool LuaEnvironment::ExecuteString(const std::string& code) {
        if (!initialized) {
            HandleError("Lua environment not initialized");
            return false;
        }

        // Load the string
        if (luaL_loadstring(L, code.c_str()) != LUA_OK) {
            std::string error = lua_tostring(L, -1);
            lua_pop(L, 1);
            HandleError("Lua load error: " + error);
            return false;
        }

        // Execute the loaded chunk
        if (lua_pcall(L, 0, LUA_MULTRET, 0) != LUA_OK) {
            std::string error = lua_tostring(L, -1);
            lua_pop(L, 1);
            HandleError("Lua execution error: " + error);
            return false;
        }

        return true;
    }

    bool LuaEnvironment::ExecuteFile(const std::string& filepath) {
        if (!initialized) {
            HandleError("Lua environment not initialized");
            return false;
        }

        // Load the file
        if (luaL_loadfile(L, filepath.c_str()) != LUA_OK) {
            std::string error = lua_tostring(L, -1);
            lua_pop(L, 1);
            HandleError("Lua file load error: " + error);
            return false;
        }

        // Execute the loaded file
        if (lua_pcall(L, 0, LUA_MULTRET, 0) != LUA_OK) {
            std::string error = lua_tostring(L, -1);
            lua_pop(L, 1);
            HandleError("Lua file execution error: " + error);
            return false;
        }

        return true;
    }

    void LuaEnvironment::RegisterFunction(const char* name, lua_CFunction func) {
        if (!initialized || !L) {
            return;
        }

        lua_register(L, name, func);
    }

    void LuaEnvironment::RegisterCitizenAPI() {
        if (!initialized || !L) {
            return;
        }

        // Create Citizen table
        lua_newtable(L);

        // Register Citizen.InvokeNative
        lua_pushcfunction(L, Citizen_InvokeNative);
        lua_setfield(L, -2, "InvokeNative");

        // Register Citizen.CreateThread
        lua_pushcfunction(L, Citizen_CreateThread);
        lua_setfield(L, -2, "CreateThread");

        // Register Citizen.Wait
        lua_pushcfunction(L, Citizen_Wait);
        lua_setfield(L, -2, "Wait");

        // Register Citizen.SetTimeout
        lua_pushcfunction(L, Citizen_SetTimeout);
        lua_setfield(L, -2, "SetTimeout");

        // Set the Citizen table as a global
        lua_setglobal(L, "Citizen");

        std::cout << "[LiKinho] Citizen API registered" << std::endl;
    }

    void LuaEnvironment::HandleError(const std::string& error) {
        std::cerr << "[LiKinho] ERROR: " << error << std::endl;
    }

    // Global functions
    bool InitializeLuaEnvironment() {
        if (g_LiKinhoLua) {
            return g_LiKinhoLua->IsInitialized();
        }

        g_LiKinhoLua = new LuaEnvironment();
        return g_LiKinhoLua->Initialize();
    }

    bool ExecuteLuaCode(const std::string& code) {
        if (!g_LiKinhoLua || !g_LiKinhoLua->IsInitialized()) {
            std::cerr << "[LiKinho] Lua environment not initialized" << std::endl;
            return false;
        }

        return g_LiKinhoLua->ExecuteString(code);
    }
}


