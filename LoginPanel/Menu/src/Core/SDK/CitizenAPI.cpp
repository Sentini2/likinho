#include "CitizenAPI.hpp"
#include "NativeInvoker.hpp"
#include <iostream>
#include <chrono>

namespace FiveM {

    ThreadManager* g_ThreadManager = nullptr;

    // Citizen.InvokeNative implementation
    int Citizen_InvokeNative(lua_State* L) {
        // Get the number of arguments
        int argc = lua_gettop(L);
        if (argc < 1) {
            lua_pushnil(L);
            return 1;
        }

        // First argument is the native hash
        uint64_t hash = 0;
        if (lua_isinteger(L, 1)) {
            hash = lua_tointeger(L, 1);
        } else if (lua_isnumber(L, 1)) {
            hash = (uint64_t)lua_tonumber(L, 1);
        } else {
            lua_pushnil(L);
            return 1;
        }

        // Collect remaining arguments
        std::vector<uint64_t> args;
        for (int i = 2; i <= argc; i++) {
            if (lua_isinteger(L, i)) {
                args.push_back(lua_tointeger(L, i));
            } else if (lua_isnumber(L, i)) {
                args.push_back((uint64_t)lua_tonumber(L, i));
            } else if (lua_isstring(L, i)) {
                args.push_back((uint64_t)lua_tostring(L, i));
            } else if (lua_isboolean(L, i)) {
                args.push_back(lua_toboolean(L, i) ? 1 : 0);
            } else {
                args.push_back(0);
            }
        }

        // Invoke the native
        uint64_t result = InvokeNative(hash, args);

        // Push result
        lua_pushinteger(L, result);
        return 1;
    }

    // Citizen.CreateThread implementation
    int Citizen_CreateThread(lua_State* L) {
        if (!lua_isfunction(L, 1)) {
            return 0;
        }

        // Store the function reference
        lua_pushvalue(L, 1);
        int ref = luaL_ref(L, LUA_REGISTRYINDEX);

        // Create thread
        if (g_ThreadManager) {
            g_ThreadManager->CreateThread(L, ref);
        }

        return 0;
    }

    // Citizen.Wait implementation
    int Citizen_Wait(lua_State* L) {
        uint32_t ms = 0;
        if (lua_isinteger(L, 1)) {
            ms = lua_tointeger(L, 1);
        }

        if (g_ThreadManager) {
            g_ThreadManager->WaitThread(L, ms);
        }

        return lua_yield(L, 0);
    }

    // Citizen.SetTimeout implementation
    int Citizen_SetTimeout(lua_State* L) {
        if (!lua_isinteger(L, 1) || !lua_isfunction(L, 2)) {
            return 0;
        }

        uint32_t ms = lua_tointeger(L, 1);
        
        // Store the function reference
        lua_pushvalue(L, 2);
        int ref = luaL_ref(L, LUA_REGISTRYINDEX);

        // Create delayed thread
        if (g_ThreadManager) {
            g_ThreadManager->CreateThread(L, ref);
            g_ThreadManager->WaitThread(L, ms);
        }

        return 0;
    }

    // ThreadManager implementation
    void ThreadManager::CreateThread(lua_State* L, int functionRef) {
        LuaThread thread;
        thread.L = L;
        thread.functionRef = functionRef;
        thread.wakeTime = 0;
        thread.active = true;
        threads.push_back(thread);

        std::cout << "[LiKinho] Thread created (ref: " << functionRef << ")" << std::endl;
    }

    void ThreadManager::Update() {
        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

        for (auto& thread : threads) {
            if (!thread.active) continue;

            if (now >= thread.wakeTime) {
                // Resume the thread
                lua_rawgeti(thread.L, LUA_REGISTRYINDEX, thread.functionRef);
                
                if (lua_pcall(thread.L, 0, 0, 0) != LUA_OK) {
                    std::string error = lua_tostring(thread.L, -1);
                    lua_pop(thread.L, 1);
                    std::cerr << "[LiKinho] Thread error: " << error << std::endl;
                    thread.active = false;
                }
            }
        }

        // Remove inactive threads
        threads.erase(
            std::remove_if(threads.begin(), threads.end(),
                [](const LuaThread& t) { return !t.active; }),
            threads.end()
        );
    }

    void ThreadManager::WaitThread(lua_State* L, uint32_t ms) {
        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

        for (auto& thread : threads) {
            if (thread.L == L && thread.active) {
                thread.wakeTime = now + ms;
                break;
            }
        }
    }

    bool InitializeNativeInvoker() {
        if (!g_ThreadManager) {
            g_ThreadManager = new ThreadManager();
        }
        return true;
    }
}


