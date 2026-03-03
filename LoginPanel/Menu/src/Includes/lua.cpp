#include <Includes/lua.h>
#include <windows.h>
#include <iostream>

// Global function pointers
luaL_newstate_t luaL_newstate = nullptr;
lua_close_t lua_close = nullptr;
luaL_openlibs_t luaL_openlibs = nullptr;
luaL_loadstring_t luaL_loadstring = nullptr;
luaL_loadfile_t luaL_loadfile = nullptr;
lua_pcall_t lua_pcall = nullptr;
lua_pushcfunction_t lua_pushcfunction = nullptr;
lua_setfield_t lua_setfield = nullptr;
lua_setglobal_t lua_setglobal = nullptr;
lua_newtable_t lua_newtable = nullptr;
lua_tostring_t lua_tostring = nullptr;
lua_tointeger_t lua_tointeger = nullptr;
lua_tonumber_t lua_tonumber = nullptr;
lua_toboolean_t lua_toboolean = nullptr;
lua_isinteger_t lua_isinteger = nullptr;
lua_isnumber_t lua_isnumber = nullptr;
lua_isstring_t lua_isstring = nullptr;
lua_isboolean_t lua_isboolean = nullptr;
lua_isfunction_t lua_isfunction = nullptr;
lua_pushinteger_t lua_pushinteger = nullptr;
lua_pushnumber_t lua_pushnumber = nullptr;
lua_pushnil_t lua_pushnil = nullptr;
lua_pushvalue_t lua_pushvalue = nullptr;
lua_pop_t lua_pop = nullptr;
lua_gettop_t lua_gettop = nullptr;
luaL_ref_t luaL_ref = nullptr;
lua_rawgeti_t lua_rawgeti = nullptr;
lua_yield_t lua_yield = nullptr;

bool InitializeLuaFunctions() {
    // Try to load from citizen-scripting-lua.dll
    HMODULE luaDll = GetModuleHandleA("citizen-scripting-lua.dll");
    if (!luaDll) {
        std::cerr << "[LiKinho] Failed to get citizen-scripting-lua.dll handle" << std::endl;
        return false;
    }

    // Load all function pointers
    luaL_newstate = (luaL_newstate_t)GetProcAddress(luaDll, "luaL_newstate");
    lua_close = (lua_close_t)GetProcAddress(luaDll, "lua_close");
    luaL_openlibs = (luaL_openlibs_t)GetProcAddress(luaDll, "luaL_openlibs");
    luaL_loadstring = (luaL_loadstring_t)GetProcAddress(luaDll, "luaL_loadstring");
    luaL_loadfile = (luaL_loadfile_t)GetProcAddress(luaDll, "luaL_loadfile");
    lua_pcall = (lua_pcall_t)GetProcAddress(luaDll, "lua_pcall");
    lua_pushcfunction = (lua_pushcfunction_t)GetProcAddress(luaDll, "lua_pushcclosure");
    lua_setfield = (lua_setfield_t)GetProcAddress(luaDll, "lua_setfield");
    lua_setglobal = (lua_setglobal_t)GetProcAddress(luaDll, "lua_setglobal");
    lua_newtable = (lua_newtable_t)GetProcAddress(luaDll, "lua_createtable");
    lua_tostring = (lua_tostring_t)GetProcAddress(luaDll, "lua_tolstring");
    lua_tointeger = (lua_tointeger_t)GetProcAddress(luaDll, "lua_tointegerx");
    lua_tonumber = (lua_tonumber_t)GetProcAddress(luaDll, "lua_tonumberx");
    lua_toboolean = (lua_toboolean_t)GetProcAddress(luaDll, "lua_toboolean");
    lua_isinteger = (lua_isinteger_t)GetProcAddress(luaDll, "lua_isinteger");
    lua_isnumber = (lua_isnumber_t)GetProcAddress(luaDll, "lua_isnumber");
    lua_isstring = (lua_isstring_t)GetProcAddress(luaDll, "lua_isstring");
    lua_isboolean = (lua_isboolean_t)GetProcAddress(luaDll, "lua_isboolean");
    lua_isfunction = (lua_isfunction_t)GetProcAddress(luaDll, "lua_isfunction");
    lua_pushinteger = (lua_pushinteger_t)GetProcAddress(luaDll, "lua_pushinteger");
    lua_pushnumber = (lua_pushnumber_t)GetProcAddress(luaDll, "lua_pushnumber");
    lua_pushnil = (lua_pushnil_t)GetProcAddress(luaDll, "lua_pushnil");
    lua_pushvalue = (lua_pushvalue_t)GetProcAddress(luaDll, "lua_pushvalue");
    lua_pop = (lua_pop_t)GetProcAddress(luaDll, "lua_settop"); // lua_pop is a macro
    lua_gettop = (lua_gettop_t)GetProcAddress(luaDll, "lua_gettop");
    luaL_ref = (luaL_ref_t)GetProcAddress(luaDll, "luaL_ref");
    lua_rawgeti = (lua_rawgeti_t)GetProcAddress(luaDll, "lua_rawgeti");
    lua_yield = (lua_yield_t)GetProcAddress(luaDll, "lua_yieldk");

    // Check if critical functions were loaded
    if (!luaL_newstate || !lua_close || !luaL_openlibs) {
        std::cerr << "[LiKinho] Failed to load critical Lua functions" << std::endl;
        return false;
    }

    std::cout << "[LiKinho] Lua functions initialized from FiveM DLL" << std::endl;
    return true;
}


