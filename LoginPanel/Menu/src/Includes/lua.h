// Minimal Lua header stubs for FiveM integration
// These definitions allow compilation without full Lua SDK
// FiveM has Lua embedded, so we only need the interface definitions

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// Lua types
typedef struct lua_State lua_State;
typedef int (*lua_CFunction) (lua_State *L);
typedef double lua_Number;
typedef long long lua_Integer;

// Lua constants
#define LUA_OK 0
#define LUA_MULTRET (-1)
#define LUA_REGISTRYINDEX (-10000)

// Lua API functions (will be resolved at runtime from FiveM's Lua DLL)
typedef lua_State* (*luaL_newstate_t)();
typedef void (*lua_close_t)(lua_State* L);
typedef void (*luaL_openlibs_t)(lua_State* L);
typedef int (*luaL_loadstring_t)(lua_State* L, const char* s);
typedef int (*luaL_loadfile_t)(lua_State* L, const char* filename);
typedef int (*lua_pcall_t)(lua_State* L, int nargs, int nresults, int errfunc);
typedef void (*lua_pushcfunction_t)(lua_State* L, lua_CFunction f);
typedef void (*lua_setfield_t)(lua_State* L, int idx, const char* k);
typedef void (*lua_setglobal_t)(lua_State* L, const char* name);
typedef void (*lua_newtable_t)(lua_State* L);
typedef const char* (*lua_tostring_t)(lua_State* L, int idx);
typedef lua_Integer (*lua_tointeger_t)(lua_State* L, int idx);
typedef lua_Number (*lua_tonumber_t)(lua_State* L, int idx);
typedef int (*lua_toboolean_t)(lua_State* L, int idx);
typedef int (*lua_isinteger_t)(lua_State* L, int idx);
typedef int (*lua_isnumber_t)(lua_State* L, int idx);
typedef int (*lua_isstring_t)(lua_State* L, int idx);
typedef int (*lua_isboolean_t)(lua_State* L, int idx);
typedef int (*lua_isfunction_t)(lua_State* L, int idx);
typedef void (*lua_pushinteger_t)(lua_State* L, lua_Integer n);
typedef void (*lua_pushnumber_t)(lua_State* L, lua_Number n);
typedef void (*lua_pushnil_t)(lua_State* L);
typedef void (*lua_pushvalue_t)(lua_State* L, int idx);
typedef void (*lua_pop_t)(lua_State* L, int n);
typedef int (*lua_gettop_t)(lua_State* L);
typedef int (*luaL_ref_t)(lua_State* L, int t);
typedef void (*lua_rawgeti_t)(lua_State* L, int idx, lua_Integer n);
typedef int (*lua_yield_t)(lua_State* L, int nresults);

// Global function pointers (will be initialized from FiveM's Lua DLL)
extern luaL_newstate_t luaL_newstate;
extern lua_close_t lua_close;
extern luaL_openlibs_t luaL_openlibs;
extern luaL_loadstring_t luaL_loadstring;
extern luaL_loadfile_t luaL_loadfile;
extern lua_pcall_t lua_pcall;
extern lua_pushcfunction_t lua_pushcfunction;
extern lua_setfield_t lua_setfield;
extern lua_setglobal_t lua_setglobal;
extern lua_newtable_t lua_newtable;
extern lua_tostring_t lua_tostring;
extern lua_tointeger_t lua_tointeger;
extern lua_tonumber_t lua_tonumber;
extern lua_toboolean_t lua_toboolean;
extern lua_isinteger_t lua_isinteger;
extern lua_isnumber_t lua_isnumber;
extern lua_isstring_t lua_isstring;
extern lua_isboolean_t lua_isboolean;
extern lua_isfunction_t lua_isfunction;
extern lua_pushinteger_t lua_pushinteger;
extern lua_pushnumber_t lua_pushnumber;
extern lua_pushnil_t lua_pushnil;
extern lua_pushvalue_t lua_pushvalue;
extern lua_pop_t lua_pop;
extern lua_gettop_t lua_gettop;
extern luaL_ref_t luaL_ref;
extern lua_rawgeti_t lua_rawgeti;
extern lua_yield_t lua_yield;

// Helper macro for lua_register
#define lua_register(L,n,f) (lua_pushcfunction(L, (f)), lua_setglobal(L, (n)))

// Initialize Lua function pointers from FiveM's DLL
bool InitializeLuaFunctions();

#ifdef __cplusplus
}
#endif
