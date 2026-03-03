#pragma once
// ============================================================
// FiveM Resource Offsets - Discovered by Export Scanner
// Build: b3570 (Aug 19 2025)
// ============================================================
// Offsets RELATIVOS ao base address de cada DLL
// Uso: GetModuleHandleA("dll") + offset = endereco_real
// ============================================================

#include <cstdint>

namespace FiveM {

// citizen-resources-core.dll
namespace ResourcesCore {
    constexpr uintptr_t CreateResourceManager = 0x248b0;
    constexpr uintptr_t ResourceManager_GetCurrent = 0x24ae0;
    constexpr uintptr_t CreateComponent = 0xe5c0;
    constexpr uintptr_t TriggerEvent = 0x1ddf0;
    constexpr uintptr_t QueueEvent_Manager = 0x1d960;
    constexpr uintptr_t QueueEvent_Resource = 0x1d940;
    constexpr uintptr_t HandleTriggerEvent = 0x1d930;
    constexpr uintptr_t ResourceEventComponent_ctor = 0x1c8f0;
    constexpr uintptr_t ResourceEventManagerComponent_ctor = 0x1c920;
    constexpr uintptr_t ResourceMetaDataComponent_ctor = 0x39a40;
    constexpr uintptr_t EventReassemblyComponent_Create = 0x11780;
    constexpr uintptr_t EventReassemblyImpl_AttachToObject = 0x11330;
    constexpr uintptr_t ResourceEventComponent_AttachToObject = 0x1d610;
    constexpr uintptr_t ResourceEventManagerComponent_AttachToObject = 0x1d790;
    constexpr uintptr_t Resource_OnInitializeInstance = 0xb2590;
    constexpr uintptr_t ResourceManager_OnInitializeInstance = 0xb26d0;
    constexpr uintptr_t SetCallRefCallback = 0x25930;
}

// citizen-scripting-lua.dll
namespace ScriptingLua {
    constexpr uintptr_t lua_rpmalloc_state = 0x2d64d0;
    constexpr uintptr_t lua_rpmalloc_free = 0x2d6630;
    constexpr uintptr_t GetCitizenLibs = 0x2dde50;
    constexpr uintptr_t GetLuaLibs = 0x2dde60;
    constexpr uintptr_t lua_fx_opendebug = 0x48ad0;
    constexpr uintptr_t lua_fx_openio = 0x4d140;
    constexpr uintptr_t lua_fx_openos = 0x526d0;
    constexpr uintptr_t CreateComponent = 0x47810;
}

// citizen-scripting-core.dll
namespace ScriptingCore {
    constexpr uintptr_t NativeInvoke = 0x5d2b0;
    constexpr uintptr_t NativeFromHash = 0x5d180;
    constexpr uintptr_t NativeFromCacheIndex = 0x5d150;
    constexpr uintptr_t GetMetaField = 0x5d230;
    constexpr uintptr_t PushMetaPointer = 0x5da80;
    constexpr uintptr_t ResourceScriptingComponent_Tick = 0x54520;
    constexpr uintptr_t UpdateScriptInitialization = 0x545a0;
    constexpr uintptr_t CreateComponent = 0x10470;
}

} // namespace FiveM

// ============================================================
// Macros de compatibilidade para uso direto
// ============================================================
#define OFFSET_GETCURRENT               FiveM::ResourcesCore::ResourceManager_GetCurrent
#define OFFSET_CREATE_RESOURCE_MANAGER  FiveM::ResourcesCore::CreateResourceManager
#define OFFSET_LUA_RPMALLOC_STATE       FiveM::ScriptingLua::lua_rpmalloc_state
#define OFFSET_GETLUALLIBS              FiveM::ScriptingLua::GetLuaLibs
#define OFFSET_GETCITIZENLIBS           FiveM::ScriptingLua::GetCitizenLibs

