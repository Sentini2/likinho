#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

// Forward declarations
extern "C" {
    #include <Includes/lua.h>
    #include <Includes/lualib.h>
    #include <Includes/lauxlib.h>
}

// Forward declare NativeContext from NativeInvoker.hpp
namespace FiveM {
    struct NativeContext;
    typedef void(*NativeHandler)(NativeContext* context);
}

namespace FiveM {

    // Get native handler by hash
    NativeHandler GetNativeHandler(uint64_t hash);

    // Invoke a native with the given hash and arguments
    uint64_t InvokeNative(uint64_t hash, const std::vector<uint64_t>& args);

    // Citizen API functions (exposed to Lua)
    
    // Citizen.InvokeNative(hash, ...)
    int Citizen_InvokeNative(lua_State* L);

    // Citizen.CreateThread(function)
    int Citizen_CreateThread(lua_State* L);

    // Citizen.Wait(ms)
    int Citizen_Wait(lua_State* L);

    // Citizen.SetTimeout(ms, function)
    int Citizen_SetTimeout(lua_State* L);

    // Initialize the native invoker system
    bool InitializeNativeInvoker();

    // Thread management
    struct LuaThread {
        lua_State* L;
        int functionRef;
        uint32_t wakeTime;
        bool active;
    };

    // Thread manager
    class ThreadManager {
    private:
        std::vector<LuaThread> threads;

    public:
        void CreateThread(lua_State* L, int functionRef);
        void Update();
        void WaitThread(lua_State* L, uint32_t ms);
    };

    extern ThreadManager* g_ThreadManager;
}
