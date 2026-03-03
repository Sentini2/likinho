#pragma once
#include <windows.h>
#include <string>
#include <cstdint>
#include <intrin.h>
#include <functional>
#include <vector>

// ============================================================
// ResourceCreator - Cria resource "likinho" do zero
// Funciona em story mode e servidores
// ============================================================

// Forward declare lua_State (opaque pointer)
struct lua_State;

// Lua C function type
typedef int (*lua_CFunction)(lua_State* L);

// luaL_Reg structure (name + function pairs)
struct luaL_Reg {
    const char* name;
    lua_CFunction func;
};

class ResourceCreator {
public:
    // Singleton
    static ResourceCreator& Instance() {
        static ResourceCreator inst;
        return inst;
    }

    // Initialize - resolve all function pointers
    bool Initialize();

    // Check if ready (direct lua OR runtime connect)
    bool IsReady() const { return m_initialized; }

    // Execute a Lua script
    bool ExecuteScript(const std::string& script);

    // Get status message
    const std::string& GetStatus() const { return m_status; }

    // Get resource name
    const std::string& GetResourceName() const { return m_resourceName; }

    // Cleanup
    void Shutdown();

    // Reset - para todas as resources hijacked e reinicia limpas
    void ResetAll();

    // Friend declaration for custom_print callback
    friend int custom_print(lua_State* L);

private:
    ResourceCreator() : m_resourceName(GenerateRandomName()) {}
    ~ResourceCreator() { Shutdown(); }

    // Resolve DLL base addresses
    bool ResolveDLLs();

    // Resolve Lua functions from citizen-scripting-lua.dll
    bool ResolveLuaFunctions();

    // Create our own lua_State
    bool CreateLuaState();

    // Register custom print that shows "script:likinho"
    void RegisterCustomFunctions();

    // ===== Function pointer types =====
    
    // Lua C API functions (resolved by pattern scan)
    typedef lua_State* (*fn_luaL_newstate)();
    typedef void (*fn_luaL_openlibs)(lua_State* L);
    typedef int (*fn_luaL_loadstring)(lua_State* L, const char* s);
    typedef int (*fn_luaL_loadbufferx)(lua_State* L, const char* buff, size_t sz, const char* name, const char* mode);
    typedef int (*fn_lua_pcallk)(lua_State* L, int nargs, int nresults, int errfunc, intptr_t ctx, lua_CFunction k);
    typedef const char* (*fn_lua_tolstring)(lua_State* L, int idx, size_t* len);
    typedef void (*fn_lua_pushcclosure)(lua_State* L, lua_CFunction fn, int n);
    typedef void (*fn_lua_setglobal)(lua_State* L, const char* name);
    typedef void (*fn_lua_getglobal)(lua_State* L, const char* name);
    typedef int (*fn_lua_gettop)(lua_State* L);
    typedef void (*fn_lua_settop)(lua_State* L, int idx);
    typedef void (*fn_lua_pushstring)(lua_State* L, const char* s);
    typedef void (*fn_lua_pushinteger)(lua_State* L, long long n);
    typedef void (*fn_lua_pushnumber)(lua_State* L, double n);
    typedef void (*fn_lua_pushboolean)(lua_State* L, int b);
    typedef void (*fn_lua_pushnil)(lua_State* L);
    typedef int (*fn_lua_type)(lua_State* L, int idx);
    typedef void (*fn_lua_createtable)(lua_State* L, int narr, int nrec);
    typedef void (*fn_lua_rawseti)(lua_State* L, int idx, long long n);
    typedef void (*fn_lua_close)(lua_State* L);
    typedef int (*fn_lua_toboolean)(lua_State* L, int idx);
    typedef long long (*fn_lua_tointegerx)(lua_State* L, int idx, int* isnum);
    typedef double (*fn_lua_tonumberx)(lua_State* L, int idx, int* isnum);

    // FiveM resource functions
    typedef void* (*fn_GetCurrent)(bool);
    typedef void* (*fn_CreateResourceManager)();
    typedef lua_State* (*fn_lua_rpmalloc_state)(void*&);
    typedef luaL_Reg* (*fn_GetLuaLibs)();
    typedef luaL_Reg* (*fn_GetCitizenLibs)();

    // ===== Resolved pointers =====
    uintptr_t m_scriptingLuaBase = 0;
    uintptr_t m_resourcesCoreBase = 0;
    uintptr_t m_scriptingCoreBase = 0;

    // Lua C API
    fn_luaL_newstate     p_luaL_newstate = nullptr;
    fn_luaL_openlibs     p_luaL_openlibs = nullptr;
    fn_luaL_loadstring   p_luaL_loadstring = nullptr;
    fn_luaL_loadbufferx  p_luaL_loadbufferx = nullptr;
    fn_lua_pcallk        p_lua_pcallk = nullptr;
    fn_lua_tolstring     p_lua_tolstring = nullptr;
    fn_lua_pushcclosure  p_lua_pushcclosure = nullptr;
    fn_lua_setglobal     p_lua_setglobal = nullptr;
    fn_lua_getglobal     p_lua_getglobal = nullptr;
    fn_lua_gettop        p_lua_gettop = nullptr;
    fn_lua_settop        p_lua_settop = nullptr;
    fn_lua_pushstring    p_lua_pushstring = nullptr;
    fn_lua_pushinteger   p_lua_pushinteger = nullptr;
    fn_lua_pushnumber    p_lua_pushnumber = nullptr;
    fn_lua_pushboolean   p_lua_pushboolean = nullptr;
    fn_lua_pushnil       p_lua_pushnil = nullptr;
    fn_lua_type          p_lua_type = nullptr;
    fn_lua_createtable   p_lua_createtable = nullptr;
    fn_lua_rawseti       p_lua_rawseti = nullptr;
    fn_lua_close         p_lua_close = nullptr;
    fn_lua_toboolean     p_lua_toboolean = nullptr;
    fn_lua_tointegerx    p_lua_tointegerx = nullptr;
    fn_lua_tonumberx     p_lua_tonumberx = nullptr;

    // FiveM functions
    fn_GetCurrent          p_GetCurrent = nullptr;
    fn_CreateResourceManager p_CreateResourceManager = nullptr;
    fn_lua_rpmalloc_state  p_lua_rpmalloc_state = nullptr;
    fn_GetLuaLibs          p_GetLuaLibs = nullptr;
    fn_GetCitizenLibs      p_GetCitizenLibs = nullptr;

    // State
    lua_State* m_luaState = nullptr;
    bool m_initialized = false;
    std::string m_status = "Nao inicializado";
    std::string m_resourceName;
    std::vector<std::string> m_usedResourceNames; // Resources usadas (nome original)
    
    // Generate random resource name
    static std::string GenerateRandomName() {
        static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        std::string name = "likinho";
        srand((unsigned int)(__rdtsc() & 0xFFFFFFFF));
        for (int i = 0; i < 8; i++) {
            name += chars[rand() % (sizeof(chars) - 1)];
        }
        return name;
    }

    // Pattern scanning helpers
    uintptr_t FindPattern(uintptr_t base, size_t size, const char* pattern, const char* mask);
    uintptr_t ScanForStringRef(uintptr_t base, size_t size, const char* str);
};


