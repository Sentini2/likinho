#include "resource_creator.h"
#include "resource_manager.h"
#include "resource.h"
#include "fivem_offsets.h"
#include <iostream>
#include <sstream>
#include <map>
#include <thread>
#include <chrono>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

// ============================================================
// Pattern Scanning - procura bytes dentro de uma regiao de memoria
// ============================================================

// ============================================================
// Memory Safety - Verifica se a regiao e legivel
// ============================================================

static bool IsMemReadable(uintptr_t addr, size_t size) {
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
        DWORD mask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
        bool readable = !!(mbi.Protect & mask);
        if (readable && mbi.State == MEM_COMMIT) {
            // Check if the entire range is within the same region or multiple readable regions
            size_t remaining = (uintptr_t)mbi.BaseAddress + mbi.RegionSize - addr;
            if (remaining >= size) return true;
            return IsMemReadable(addr + remaining, size - remaining);
        }
    }
    return false;
}

// ============================================================
// Pattern Scanning - procura bytes dentro de uma regiao de memoria
// ============================================================

uintptr_t ResourceCreator::FindPattern(uintptr_t base, size_t size, const char* pattern, const char* mask) {
    if (!IsMemReadable(base, size)) return 0;

    size_t patLen = strlen(mask);
    for (size_t i = 0; i <= size - patLen; i++) {
        bool found = true;
        for (size_t j = 0; j < patLen; j++) {
            if (mask[j] != '?' && pattern[j] != *(char*)(base + i + j)) {
                found = false;
                break;
            }
        }
        if (found) return base + i;
    }
    return 0;
}

// ============================================================
// String Scanning - procura referencia a uma string na secao .rdata
// e depois acha codigo que referencia essa string
// ============================================================

uintptr_t ResourceCreator::ScanForStringRef(uintptr_t base, size_t size, const char* str) {
    if (!IsMemReadable(base, size)) return 0;

    size_t strLen = strlen(str);
    
    // Passo 1: Achar a string nos dados do modulo
    uintptr_t strAddr = 0;
    for (size_t i = 0; i < size - strLen; i++) {
        if (memcmp((void*)(base + i), str, strLen) == 0) {
            strAddr = base + i;
            break;
        }
    }
    
    if (!strAddr) return 0;
    
    // Passo 2: Achar instrucao LEA que referencia essa string
    // Em x64, LEA usa RIP-relative addressing: 48 8D xx [4 bytes offset]
    for (size_t i = 0; i < size - 7; i++) {
        if (!IsMemReadable(base + i, 7)) continue;
        uint8_t* code = (uint8_t*)(base + i);
        
        // LEA reg, [rip+disp32] = 48 8D 0D/05/15/1D/25/2D/35/3D [4 bytes]
        // Tambem pode ser 4C 8D para R8-R15
        if ((code[0] == 0x48 || code[0] == 0x4C) && code[1] == 0x8D) {
            uint8_t modrm = code[2];
            // ModRM com mod=00 e r/m=101 = RIP-relative
            if ((modrm & 0xC7) == 0x05) {
                int32_t disp = *(int32_t*)(code + 3);
                uintptr_t target = (uintptr_t)(code + 7) + disp;
                if (target == strAddr) {
                    return base + i;
                }
            }
        }
    }
    
    return 0;
}

// ============================================================
// Achar funcao que contem uma referencia a string
// Volta para tras do ponto de referencia para achar o inicio da funcao
// ============================================================

static uintptr_t FindFunctionStart(uintptr_t stringRefAddr, uintptr_t moduleBase) {
    // Procura para tras por um padrao tipico de inicio de funcao:
    // - 40 55 (push rbp com REX prefix)
    // - 48 89 5C 24 (mov [rsp+xx], rbx - save non-volatile)
    // - 48 83 EC (sub rsp, imm8)
    // - CC (int3 padding before function)
    // - C3 (ret from previous function)
    
    for (uintptr_t addr = stringRefAddr; addr > stringRefAddr - 0x1000; addr--) {
        if (!IsMemReadable(addr, 1)) continue;
        uint8_t* code = (uint8_t*)addr;
        
        // Check if previous byte is CC (int3) or C3 (ret) - marks function boundary
        if (addr > moduleBase) {
            if (!IsMemReadable(addr - 1, 1)) continue;
            uint8_t prevByte = *(uint8_t*)(addr - 1);
            if (prevByte == 0xCC || prevByte == 0xC3) {
                // This could be the start of our function
                // Verify it looks like a function prologue
                if (code[0] == 0x48 || code[0] == 0x40 || code[0] == 0x55 || code[0] == 0x53) {
                    return addr;
                }
            }
        }
    }
    
    return 0;
}

// ============================================================
// Resolve DLLs
// ============================================================

bool ResourceCreator::ResolveDLLs() {
    m_status = "Procurando DLLs do FiveM...";

    // Tentar varias vezes (DLLs podem demorar para carregar)
    for (int attempt = 0; attempt < 30; attempt++) {
        m_scriptingLuaBase = (uintptr_t)GetModuleHandleA("citizen-scripting-lua.dll");
        m_resourcesCoreBase = (uintptr_t)GetModuleHandleA("citizen-resources-core.dll");
        m_scriptingCoreBase = (uintptr_t)GetModuleHandleA("citizen-scripting-core.dll");
        
        // Precisamos pelo menos da scripting-lua para story mode
        if (m_scriptingLuaBase) {
            m_status = "DLLs encontradas!";
            
            // Log quais foram encontradas
            std::string found = "DLLs: lua=";
            found += m_scriptingLuaBase ? "OK" : "NO";
            found += " core=";
            found += m_resourcesCoreBase ? "OK" : "NO";
            found += " scripting=";
            found += m_scriptingCoreBase ? "OK" : "NO";
            OutputDebugStringA(found.c_str());
            
            return true;
        }
        
        Sleep(500);
    }

    m_status = "ERRO: citizen-scripting-lua.dll nao encontrada";
    return false;
}

// ============================================================
// Resolve Lua Functions via String Scanning
// ============================================================

bool ResourceCreator::ResolveLuaFunctions() {
    m_status = "Resolvendo funcoes Lua...";
    
    if (!m_scriptingLuaBase) return false;
    
    // Obter tamanho do modulo
    MODULEINFO modInfo = {};
    GetModuleInformation(GetCurrentProcess(), (HMODULE)m_scriptingLuaBase, &modInfo, sizeof(modInfo));
    size_t moduleSize = modInfo.SizeOfImage;
    
    OutputDebugStringA(("[ResourceCreator] Modulo citizen-scripting-lua.dll tamanho: " + std::to_string(moduleSize)).c_str());
    
    // ============================================================
    // Resolver funcoes EXPORTADAS (via GetProcAddress dos nomes mangled)
    // ============================================================
    
    HMODULE hLuaDll = (HMODULE)m_scriptingLuaBase;
    HMODULE hResCor = (HMODULE)m_resourcesCoreBase;
    
    // FiveM exported functions - usar offsets conhecidos
    if (m_scriptingLuaBase) {
        p_lua_rpmalloc_state = (fn_lua_rpmalloc_state)(m_scriptingLuaBase + OFFSET_LUA_RPMALLOC_STATE);
        p_GetLuaLibs = (fn_GetLuaLibs)(m_scriptingLuaBase + OFFSET_GETLUALLIBS);
        p_GetCitizenLibs = (fn_GetCitizenLibs)(m_scriptingLuaBase + OFFSET_GETCITIZENLIBS);
        
        OutputDebugStringA("[ResourceCreator] Funcoes FiveM exportadas resolvidas via offset");
    }
    
    if (m_resourcesCoreBase) {
        p_GetCurrent = (fn_GetCurrent)(m_resourcesCoreBase + OFFSET_GETCURRENT);
        p_CreateResourceManager = (fn_CreateResourceManager)(m_resourcesCoreBase + OFFSET_CREATE_RESOURCE_MANAGER);
        
        OutputDebugStringA("[ResourceCreator] ResourceManager resolvido via offset");
    }
    
    // ============================================================
    // Resolver funcoes Lua via SCAN DE STRINGS
    // Lua 5.4 tem strings conhecidas que sao referenciadas por funcoes especificas
    // ============================================================
    
    OutputDebugStringA("[ResourceCreator] Iniciando scan de strings para funcoes Lua...");
    
    // --- luaL_loadbufferx ---
    // A funcao luaL_loadbufferx referencia a string "bt" para validar o mode
    // E tambem "=[string \"%s\"]" para o nome do chunk
    {
        uintptr_t ref = ScanForStringRef(m_scriptingLuaBase, moduleSize, "=[string \"%s\"]");
        if (ref) {
            uintptr_t funcStart = FindFunctionStart(ref, m_scriptingLuaBase);
            if (funcStart) {
                p_luaL_loadbufferx = (fn_luaL_loadbufferx)funcStart;
                OutputDebugStringA(("[ResourceCreator] luaL_loadbufferx encontrado em: 0x" + 
                    std::to_string(funcStart - m_scriptingLuaBase)).c_str());
            }
        }
    }
    
    // --- lua_pcallk ---
    // lua_pcallk (ou luaD_pcall chamado por ele) usa mensagens de erro internas
    // A funcao lua_pcallk chama luaD_rawrunprotected e ajusta o call info
    // Vamos procurar pela string "cannot resume dead coroutine" que esta no modulo
    // e navegar pela funcao lua_resume para achar lua_pcallk perto
    // 
    // ALTERNATIVA: Podemos achar lua_pcallk via padrao de bytes
    // lua_pcallk no Lua 5.4 tem assinatura: int lua_pcallk(L, nargs, nresults, errfunc, ctx, k)
    // 6 parametros = muito distinto em x64
    {
        // Procurar pelo padrao de lua_pcallk: 
        // A funcao compara errfunc (4o param) com 0 e faz ajustes
        // Em x64 MSVC: parametros em rcx, rdx, r8, r9, [rsp+28], [rsp+30]
        // Vamos procurar pela string "C stack overflow" que e usada em luaD_call/luaD_callnoyield
        // que e o caminho de chamada mais direto
        
        uintptr_t ref = ScanForStringRef(m_scriptingLuaBase, moduleSize, "C stack overflow");
        if (ref) {
            // A funcao que referencia "C stack overflow" e luaD_call ou luaD_precall
            // lua_pcallk esta normalmente ~200-500 bytes antes ou depois
            // Vamos usar outra abordagem: procurar lua_callk primeiro
            OutputDebugStringA("[ResourceCreator] Encontrado ref 'C stack overflow' - area de funcoes lua_call/pcall");
        }
    }
    
    // --- luaL_newstate ---
    // luaL_newstate chama lua_newstate com l_alloc como allocator
    // A string "not enough memory" e usada no default allocator l_alloc
    {
        // Na verdade, nao precisamos de luaL_newstate se temos lua_rpmalloc_state
        // lua_rpmalloc_state JA cria um lua_State
    }
    
    // --- lua_tolstring ---
    // lua_tolstring referencia "__tostring" para meta-method
    {
        uintptr_t ref = ScanForStringRef(m_scriptingLuaBase, moduleSize, "__tostring");
        if (ref) {
            uintptr_t funcStart = FindFunctionStart(ref, m_scriptingLuaBase);
            if (funcStart) {
                p_lua_tolstring = (fn_lua_tolstring)funcStart;
                OutputDebugStringA(("[ResourceCreator] lua_tolstring encontrado em: 0x" + 
                    std::to_string(funcStart - m_scriptingLuaBase)).c_str());
            }
        }
    }
    
    // --- lua_pushcclosure ---
    // lua_pushcclosure referencia "upvalue" em erro
    // Ou melhor, referencia "value expected" 
    // Na verdade, a melhor string e o padrao especifico da funcao
    
    // --- lua_setglobal / lua_getglobal ---
    // Estas funcoes usam luaH_getstr e luaV_finishset
    // Dificil de encontrar por string
    
    // ============================================================
    // ABORDAGEM ALTERNATIVA MAIS CONFIAVEL:
    // Usar GetLuaLibs() para obter os luaopen_* e chamar eles
    // Depois usar a tabela registrada para obter funcoes
    // ============================================================
    
    // Se nao conseguimos todas as funcoes essenciais por scan,
    // tentamos criar um estado e usar GetLuaLibs para abrir as libs
    // Depois executamos codigo via os proprios mecanismos internos
    
    bool hasEssentialFunctions = p_luaL_loadbufferx && p_lua_tolstring;
    
    if (!hasEssentialFunctions) {
        OutputDebugStringA("[ResourceCreator] Scan de strings nao encontrou todas funcoes essenciais");
        OutputDebugStringA("[ResourceCreator] Tentando abordagem via Lua C API padrao...");
        
        // Tentar GetProcAddress para funcoes Lua padrao (caso alguma build exporte)
        if (hLuaDll) {
            if (!p_luaL_newstate) p_luaL_newstate = (fn_luaL_newstate)GetProcAddress(hLuaDll, "luaL_newstate");
            if (!p_luaL_openlibs) p_luaL_openlibs = (fn_luaL_openlibs)GetProcAddress(hLuaDll, "luaL_openlibs");
            if (!p_luaL_loadstring) p_luaL_loadstring = (fn_luaL_loadstring)GetProcAddress(hLuaDll, "luaL_loadstring");
            if (!p_luaL_loadbufferx) p_luaL_loadbufferx = (fn_luaL_loadbufferx)GetProcAddress(hLuaDll, "luaL_loadbufferx");
            if (!p_lua_pcallk) p_lua_pcallk = (fn_lua_pcallk)GetProcAddress(hLuaDll, "lua_pcallk");
            if (!p_lua_tolstring) p_lua_tolstring = (fn_lua_tolstring)GetProcAddress(hLuaDll, "lua_tolstring");
            if (!p_lua_pushcclosure) p_lua_pushcclosure = (fn_lua_pushcclosure)GetProcAddress(hLuaDll, "lua_pushcclosure");
            if (!p_lua_setglobal) p_lua_setglobal = (fn_lua_setglobal)GetProcAddress(hLuaDll, "lua_setglobal");
            if (!p_lua_getglobal) p_lua_getglobal = (fn_lua_getglobal)GetProcAddress(hLuaDll, "lua_getglobal");
            if (!p_lua_gettop) p_lua_gettop = (fn_lua_gettop)GetProcAddress(hLuaDll, "lua_gettop");
            if (!p_lua_settop) p_lua_settop = (fn_lua_settop)GetProcAddress(hLuaDll, "lua_settop");
            if (!p_lua_pushstring) p_lua_pushstring = (fn_lua_pushstring)GetProcAddress(hLuaDll, "lua_pushstring");
            if (!p_lua_close) p_lua_close = (fn_lua_close)GetProcAddress(hLuaDll, "lua_close");
        }
        
        // Tambem tentar na lua54.dll se existir
        HMODULE hLua54 = GetModuleHandleA("lua54.dll");
        if (!hLua54) hLua54 = GetModuleHandleA("lua5.4.dll");
        if (hLua54) {
            OutputDebugStringA("[ResourceCreator] Encontrou lua54.dll separada!");
            if (!p_luaL_newstate) p_luaL_newstate = (fn_luaL_newstate)GetProcAddress(hLua54, "luaL_newstate");
            if (!p_luaL_openlibs) p_luaL_openlibs = (fn_luaL_openlibs)GetProcAddress(hLua54, "luaL_openlibs");
            if (!p_luaL_loadstring) p_luaL_loadstring = (fn_luaL_loadstring)GetProcAddress(hLua54, "luaL_loadstring");
            if (!p_luaL_loadbufferx) p_luaL_loadbufferx = (fn_luaL_loadbufferx)GetProcAddress(hLua54, "luaL_loadbufferx");
            if (!p_lua_pcallk) p_lua_pcallk = (fn_lua_pcallk)GetProcAddress(hLua54, "lua_pcallk");
            if (!p_lua_tolstring) p_lua_tolstring = (fn_lua_tolstring)GetProcAddress(hLua54, "lua_tolstring");
            if (!p_lua_pushcclosure) p_lua_pushcclosure = (fn_lua_pushcclosure)GetProcAddress(hLua54, "lua_pushcclosure");
            if (!p_lua_setglobal) p_lua_setglobal = (fn_lua_setglobal)GetProcAddress(hLua54, "lua_setglobal");
            if (!p_lua_getglobal) p_lua_getglobal = (fn_lua_getglobal)GetProcAddress(hLua54, "lua_getglobal");
            if (!p_lua_gettop) p_lua_gettop = (fn_lua_gettop)GetProcAddress(hLua54, "lua_gettop");
            if (!p_lua_settop) p_lua_settop = (fn_lua_settop)GetProcAddress(hLua54, "lua_settop");
            if (!p_lua_pushstring) p_lua_pushstring = (fn_lua_pushstring)GetProcAddress(hLua54, "lua_pushstring");
            if (!p_lua_close) p_lua_close = (fn_lua_close)GetProcAddress(hLua54, "lua_close");
        }
    }
    
    // ============================================================
    // Status final - reportar quais funcoes foram encontradas
    // ============================================================
    
    int foundCount = 0;
    int totalNeeded = 0;
    
    auto checkFunc = [&](const char* name, void* ptr) {
        totalNeeded++;
        if (ptr) {
            foundCount++;
            OutputDebugStringA((std::string("[ResourceCreator] ") + name + " = OK").c_str());
        } else {
            OutputDebugStringA((std::string("[ResourceCreator] ") + name + " = NAO ENCONTRADO").c_str());
        }
    };
    
    // Funcoes essenciais para execucao direta
    checkFunc("lua_rpmalloc_state", (void*)p_lua_rpmalloc_state);
    checkFunc("luaL_loadbufferx", (void*)p_luaL_loadbufferx);
    checkFunc("luaL_loadstring", (void*)p_luaL_loadstring);
    checkFunc("lua_pcallk", (void*)p_lua_pcallk);
    checkFunc("lua_tolstring", (void*)p_lua_tolstring);
    checkFunc("lua_pushcclosure", (void*)p_lua_pushcclosure);
    checkFunc("lua_setglobal", (void*)p_lua_setglobal);
    checkFunc("lua_gettop", (void*)p_lua_gettop);
    checkFunc("lua_settop", (void*)p_lua_settop);
    checkFunc("GetLuaLibs", (void*)p_GetLuaLibs);
    checkFunc("GetCitizenLibs", (void*)p_GetCitizenLibs);
    
    // Funcoes extras
    checkFunc("GetCurrent", (void*)p_GetCurrent);
    checkFunc("luaL_newstate", (void*)p_luaL_newstate);
    checkFunc("luaL_openlibs", (void*)p_luaL_openlibs);
    
    m_status = "Funcoes: " + std::to_string(foundCount) + "/" + std::to_string(totalNeeded);
    
    // Verificar se temos o minimo para funcionar
    bool canDirectLua = (p_luaL_newstate || p_lua_rpmalloc_state) &&
                        (p_luaL_loadstring || p_luaL_loadbufferx) &&
                        p_lua_pcallk;
                        
    bool canRuntimeConnect = (p_GetCurrent != nullptr);
    
    if (canDirectLua) {
        m_status = "Modo direto disponivel! (" + std::to_string(foundCount) + " funcoes)";
        return true;
    }
    
    if (canRuntimeConnect) {
        m_status = "Modo Runtime.Connect disponivel (server only)";
        return true;
    }
    
    // Se nem modo direto nem Runtime.Connect, tentar mesmo assim
    // ja que lua_rpmalloc_state + GetLuaLibs pode funcionar
    if (p_lua_rpmalloc_state && p_GetLuaLibs) {
        m_status = "Modo rpmalloc+libs disponivel (experimental)";
        return true;
    }
    
    m_status = "AVISO: Funcoes Lua limitadas - apenas Runtime.Connect";
    return p_GetCurrent != nullptr;
}

// ============================================================
// Create Lua State
// ============================================================

bool ResourceCreator::CreateLuaState() {
    m_status = "Criando lua_State para resource '" + m_resourceName + "'...";

    // Method 1: Use luaL_newstate if available
    if (p_luaL_newstate) {
        m_luaState = p_luaL_newstate();
        if (m_luaState) {
            if (p_luaL_openlibs) {
                p_luaL_openlibs(m_luaState);
            }
            m_status = "lua_State criado (luaL_newstate)!";
            return true;
        }
    }

    // Method 2: Use FiveM's lua_rpmalloc_state
    if (p_lua_rpmalloc_state) {
        void* userData = nullptr;
        m_luaState = p_lua_rpmalloc_state(userData);
        if (m_luaState) {
            // Abrir libs usando GetLuaLibs se disponivel
            if (p_GetLuaLibs && p_luaL_openlibs == nullptr) {
                // GetLuaLibs retorna um array de luaL_Reg = {name, func}
                // Cada entrada e um luaopen_* function
                luaL_Reg* libs = p_GetLuaLibs();
                if (libs) {
                    OutputDebugStringA("[ResourceCreator] Abrindo libs via GetLuaLibs...");
                    // As funcoes luaopen_* precisam de luaL_requiref que nao temos
                    // Mas podemos chamar cada uma diretamente com o state
                    for (int i = 0; libs[i].name != nullptr; i++) {
                        if (libs[i].func) {
                            libs[i].func(m_luaState);
                            OutputDebugStringA(("[ResourceCreator] Lib: " + std::string(libs[i].name)).c_str());
                        }
                    }
                }
            } else if (p_luaL_openlibs) {
                p_luaL_openlibs(m_luaState);
            }
            
            // Abrir citizen libs tambem
            if (p_GetCitizenLibs) {
                luaL_Reg* citizenLibs = p_GetCitizenLibs();
                if (citizenLibs) {
                    for (int i = 0; citizenLibs[i].name != nullptr; i++) {
                        if (citizenLibs[i].func) {
                            citizenLibs[i].func(m_luaState);
                            OutputDebugStringA(("[ResourceCreator] CitizenLib: " + std::string(citizenLibs[i].name)).c_str());
                        }
                    }
                }
            }
            
            m_status = "lua_State criado (rpmalloc_state)!";
            return true;
        }
    }

    m_status = "ERRO: Nao foi possivel criar lua_State";
    return false;
}

// ============================================================
// Custom print function - shows "script:likinho" 
// ============================================================

static ResourceCreator* g_creator = nullptr;

static int custom_print(lua_State* L) {
    if (!g_creator) return 0;
    
    auto& creator = *g_creator;
    
    int nargs = 0;
    if (creator.p_lua_gettop)
        nargs = creator.p_lua_gettop(L);

    std::string output;
    for (int i = 1; i <= nargs; i++) {
        if (i > 1) output += "\t";
        
        size_t len = 0;
        const char* str = nullptr;
        if (creator.p_lua_tolstring)
            str = creator.p_lua_tolstring(L, i, &len);
        
        if (str) {
            output += std::string(str, len);
        } else {
            output += "nil";
        }
    }

    // Format como FiveM: "script:likinho: <message>"
    std::string formatted = "script:" + creator.GetResourceName() + ": " + output + "\n";
    
    OutputDebugStringA(formatted.c_str());
    printf("%s", formatted.c_str());
    
    return 0;
}

void ResourceCreator::RegisterCustomFunctions() {
    if (!m_luaState) return;
    
    g_creator = this;
    
    // Registrar print customizado
    if (p_lua_pushcclosure && p_lua_setglobal) {
        p_lua_pushcclosure(m_luaState, custom_print, 0);
        p_lua_setglobal(m_luaState, "print");
    }
}

// ============================================================
// Initialize
// ============================================================

bool ResourceCreator::Initialize() {
    if (m_initialized) return true;

    m_status = "Inicializando ResourceCreator...";

    // Step 1: Find DLLs
    if (!ResolveDLLs()) return false;

    // Step 2: Resolve Lua functions
    if (!ResolveLuaFunctions()) return false;

    // Step 3: Tentar criar lua_State se temos funcoes diretas
    bool directLuaAvailable = (p_luaL_newstate || p_lua_rpmalloc_state) && 
                               (p_luaL_loadstring || p_luaL_loadbufferx) &&
                               p_lua_pcallk;

    if (directLuaAvailable) {
        if (!CreateLuaState()) return false;
        RegisterCustomFunctions();
        m_status = "Resource '" + m_resourceName + "' pronta! (modo direto)";
    } else if (p_GetCurrent) {
        // Modo Runtime.Connect - funciona em server
        m_status = "Resource '" + m_resourceName + "' pronta! (modo runtime)";
    } else if (p_lua_rpmalloc_state) {
        // Estado criado mas sem funcoes de execucao
        // Ainda criamos o state para estar pronto
        if (!CreateLuaState()) {
            m_status = "AVISO: State criado mas sem funcoes de execucao";
        } else {
            m_status = "Resource '" + m_resourceName + "' (modo experimental)";
        }
    } else {
        m_status = "ERRO: Nenhum modo de execucao disponivel";
        return false;
    }

    m_initialized = true;
    return true;
}

// ============================================================
// SEH Helper Functions (vtable calls protegidas)
// MSVC nao permite __try em funcoes com destructors de C++
// ============================================================

static void* SafeCallCreateResource(void* vtableFunc, void* mgr, const std::string* name, void* mounter) {
    // CreateResource retorna fwRefContainer<Resource> que NAO eh trivially copyable
    // (tem constructor/destructor de ref counting)
    // Em MSVC x64, retorno nao-trivial usa HIDDEN RETURN POINTER em RCX:
    // RCX = &returnValue (hidden), RDX = this, R8 = &name, R9 = &mounter
    typedef void* (__fastcall* fn_t)(void* hiddenRet, void* thisPtr, const std::string& name, const void* mounter);
    fn_t fn = (fn_t)vtableFunc;
    void* result = nullptr;
    __try {
        fn(&result, mgr, *name, mounter);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
    return result;
}

static bool SafeCallStart(void* vtableFunc, void* resource) {
    // Start() retorna bool = trivially copyable, sem hidden return pointer
    typedef bool (__fastcall* fn_t)(void*);
    fn_t fn = (fn_t)vtableFunc;
    __try {
        return fn(resource);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool SafeCallRemoveResource(void* vtableFunc, void* mgr, void* resource) {
    // RemoveResource(fwRefContainer<Resource>) recebe por valor
    // fwRefContainer nao eh trivially copyable mas como argumento
    // em x64 structs de 8 bytes sao passadas em registrador
    // RemoveResource retorna void, sem hidden return
    typedef void (__fastcall* fn_t)(void*, void*);
    fn_t fn = (fn_t)vtableFunc;
    __try {
        fn(mgr, resource);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool SafeCallMakeCurrent(void* vtableFunc, void* mgr, void* resource) {
    // MakeCurrent(fwRefContainer<Resource>) recebe por valor
    // Assim como RemoveResource, struct nao trivial > 8 bytes ou com dtor
    // eh passada por referncia oculta (ponteiro para copia)
    typedef void (__fastcall* fn_t)(void*, void*);
    fn_t fn = (fn_t)vtableFunc;
    __try {
        fn(mgr, resource);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ============================================================
// Execute Script
// ============================================================

bool ResourceCreator::ExecuteScript(const std::string& script) {
    if (!m_initialized) {
        if (!Initialize()) {
            return false;
        }
    }

    // Gerar novo nome aleatorio a cada execucao
    m_resourceName = GenerateRandomName();

    // ================================================================
    // BYPASS PREFIX - 100% pcall-safe (funciona COM e SEM PL_PROTECT)
    // Cada bloco eh independente: se falhar, nao afeta os outros
    // ================================================================
    std::string bypassPrefix = 
        "do\n"
        "  local function unhook(hooked, depth)\n"
        "    depth = depth or 0\n"
        "    if depth > 5 then return hooked end\n"
        "    if type(hooked) ~= 'function' then return hooked end\n"
        "    local ok, info = pcall(debug.getinfo, hooked, 'u')\n"
        "    if not ok or not info or (info.nups or 0) == 0 then return hooked end\n"
        "    for i = 1, info.nups do\n"
        "      local ok2, name, val = pcall(debug.getupvalue, hooked, i)\n"
        "      if ok2 and type(val) == 'function' then\n"
        "        local ok3, inner = pcall(debug.getinfo, val, 'S')\n"
        "        if ok3 and inner and inner.what == 'C' then\n"
        "          return val\n"
        "        end\n"
        "        local deeper = unhook(val, depth + 1)\n"
        "        if deeper ~= val then return deeper end\n"
        "      end\n"
        "    end\n"
        "    return hooked\n"
        "  end\n"
        "\n"
        "  pcall(function()\n"
        "    local _t = {'CreateThread','RegisterCommand','AddEventHandler',\n"
        "      'RegisterNetEvent','TriggerServerEvent','TriggerEvent',\n"
        "      'TriggerClientEvent','SetTimeout','RegisterNUICallback',\n"
        "      'AddStateBagChangeHandler'}\n"
        "    for _, f in ipairs(_t) do\n"
        "      local fn = rawget(_G, f)\n"
        "      if fn and type(fn) == 'function' then\n"
        "        local o = unhook(fn)\n"
        "        if o and o ~= fn then rawset(_G, f, o) end\n"
        "      end\n"
        "    end\n"
        "  end)\n"
        "\n"
        "  pcall(function()\n"
        "    if Citizen then\n"
        "      for _, k in ipairs({'CreateThread','Wait','SetTimeout','Trace'}) do\n"
        "        if Citizen[k] and type(Citizen[k]) == 'function' then\n"
        "          local o = unhook(Citizen[k])\n"
        "          if o then Citizen[k] = o end\n"
        "        end\n"
        "      end\n"
        "      if Citizen.CreateThread then CreateThread = Citizen.CreateThread end\n"
        "      if Citizen.Wait then Wait = Citizen.Wait end\n"
        "      if Citizen.SetTimeout then SetTimeout = Citizen.SetTimeout end\n"
        "    end\n"
        "  end)\n"
        "\n"
        "  pcall(function()\n"
        "    if Citizen and Citizen.Trace then\n"
        "      local _rt = Citizen.Trace\n"
        "      Citizen.Trace = function(m, ...)\n"
        "        if type(m)=='string' then\n"
        "          local l=m:lower()\n"
        "          if l:find('pl_protect') or l:find('invalid pl') or l:find('script error') or l:find('stack traceback') then return end\n"
        "        end\n"
        "        return _rt(m, ...)\n"
        "      end\n"
        "    end\n"
        "  end)\n"
        "\n"
        "  pcall(function()\n"
        "    local _rp = print\n"
        "    print = function(...)\n"
        "      for _, v in ipairs({...}) do\n"
        "        if type(v)=='string' then\n"
        "          local l=v:lower()\n"
        "          if l:find('pl_protect') or l:find('invalid pl') or l:find('script error') then return end\n"
        "        end\n"
        "      end\n"
        "      return _rp(...)\n"
        "    end\n"
        "  end)\n"
        "end\n"
        "\n"
        "-- ====== SCRIPT DO USUARIO ======\n";

    // ================================================================
    // METHOD 1: STEALTH - Direct lua_State + Resource Rename
    // Injeta direto no lua_State de uma resource existente
    // ================================================================
    if (m_luaState && p_GetCurrent && (p_luaL_loadbufferx || p_luaL_loadstring) && p_lua_pcallk) {
        m_status = "Executando via STEALTH...";
        OutputDebugStringA("[ResourceCreator] METHOD 1: STEALTH - Direct lua_State");
        
        {
            auto rawMgr = p_GetCurrent(true);
            if (rawMgr) {
                auto mgr = (fx::ResourceManagerImpl*)((uint64_t*)rawMgr + 2);
                auto resources = mgr->getAllResources();
                
                if (!resources.empty()) {
                    // Pegar primeira resource disponivel
                    fx::fwRefContainer<fx::Resource> r = resources[0];
                    
                    // Tentar achar spawnmanager (mais estavel)
                    for (auto& res : resources) {
                        auto resImpl = res->get_impl();
                        if (resImpl && resImpl->GetName() == "spawnmanager") {
                            r = res;
                            break;
                        }
                    }

                    auto impl = r->get_impl();
                    if (impl) {
                        std::string* realNamePtr = nullptr;
                        std::string originalName;
                        bool canRename = false;

                        const std::string& nameRef = impl->GetName();
                        realNamePtr = const_cast<std::string*>(&nameRef);

                        if (realNamePtr && !realNamePtr->empty() && realNamePtr->size() < 256) {
                            originalName = *realNamePtr;
                            canRename = true;
                        }

                        // Renomear resource
                        if (canRename && realNamePtr) {
                            *realNamePtr = m_resourceName;
                        }

                        std::string wrappedScript = bypassPrefix + script;
                        std::string chunkName = "@" + m_resourceName + "/client.lua";
                        
                        int loadResult = -1;
                        if (p_luaL_loadbufferx) {
                            loadResult = p_luaL_loadbufferx(m_luaState, wrappedScript.c_str(), wrappedScript.size(), chunkName.c_str(), nullptr);
                        } else if (p_luaL_loadstring) {
                            loadResult = p_luaL_loadstring(m_luaState, wrappedScript.c_str());
                        }

                        if (loadResult == 0) {
                            int pcallResult = p_lua_pcallk(m_luaState, 0, 0, 0, 0, nullptr);
                            
                            if (pcallResult != 0) {
                                if (p_lua_tolstring) {
                                    size_t len = 0;
                                    const char* err = p_lua_tolstring(m_luaState, -1, &len);
                                    if (err) {
                                        m_status = std::string("ERRO Runtime: ") + err;
                                        OutputDebugStringA(("[ResourceCreator] STEALTH pcall error: " + std::string(err)).c_str());
                                    }
                                }
                                if (p_lua_settop) p_lua_settop(m_luaState, -2);
                            } else {
                                m_status = "Executado (STEALTH) como '" + m_resourceName + "'!";
                            }
                        } else {
                            if (p_lua_tolstring) {
                                size_t len = 0;
                                const char* err = p_lua_tolstring(m_luaState, -1, &len);
                                if (err) {
                                    m_status = std::string("ERRO Load: ") + err;
                                }
                            }
                            if (p_lua_settop) p_lua_settop(m_luaState, -2);
                        }

                        // Restaurar nome original
                        if (canRename && realNamePtr) {
                            *realNamePtr = originalName;
                        }

                        if (loadResult == 0) return true;
                    }
                }
            }
        }
    }

    // ================================================================
    // METHOD 2: CREATE RESOURCE - Cria resource NOVA via vtable
    // Baseado no open source do FiveM (citizen-resources-core)
    // CreateResource = vtable[9], RemoveResource = vtable[8]
    // ================================================================
    if (p_GetCurrent) {
        m_status = "Criando resource '" + m_resourceName + "'...";
        OutputDebugStringA("[ResourceCreator] METHOD 2: CreateResource via vtable");
        
        {
            auto rawMgr = p_GetCurrent(true);
            if (rawMgr) {
                // rawMgr = ResourceManager* (classe base com vtable)
                // A vtable tem CreateResource no index 9
                // Assinatura: fwRefContainer<Resource> CreateResource(const string& name, const fwRefContainer<ResourceMounter>& mounter)
                
                // Pegar vtable do ResourceManager
                uintptr_t* vtable = *(uintptr_t**)rawMgr;
                
                // CreateResource: vtable[9]
                // Em MSVC x64, retorno por valor de objetos >8 bytes usa hidden return pointer
                // fwRefContainer<Resource> tem 8 bytes (1 ponteiro), pode caber em RAX
                // Mas fwRefContainer pode ser tratado como struct - depende do compilador
                
                // Tentar chamar CreateResource com nullptr como mounter
                // typedef: void* (__fastcall*)(void* thisPtr, const std::string& name, void* mounter)
                // O retorno fwRefContainer<Resource> = 1 ponteiro = cabe em RAX
                
                typedef void* (__fastcall* fn_CreateResource)(void* thisPtr, const std::string& name, const void* mounter);
                typedef void (__fastcall* fn_RemoveResource)(void* thisPtr, void* resource);
                
                // Indices da vtable (baseado no open source):
                // [0] = destructor
                // [1] = AddResource (pode ter 2 slots: deleting + complete destructor)
                // Vamos tentar com offset 1 para destructor
                // Entao: CreateResource pode estar em [9] ou [10] dependendo do destructor
                
                // Vamos usar uma abordagem mais segura:
                // Achar a funcao pelo comportamento ao inves de hardcodar o index
                // Primeiro tentamos index 9, depois 10, 11 como fallback
                
                int createResourceIndex = -1;
                int removeResourceIndex = -1;
                
                // Em MSVC x64 com: virtual destructor (1 slot) + 8 pure virtuals antes de CreateResource + CreateResource
                // destructor = slot 0
                // AddResource = slot 1
                // AddResourceWithError = slot 2
                // GetMounterForUri = slot 3
                // GetResource = slot 4
                // ForAllResources = slot 5
                // ResetResources = slot 6
                // AddMounter = slot 7
                // RemoveResource = slot 8
                // CreateResource = slot 9
                // Tick = slot 10
                // MakeCurrent = slot 11
                createResourceIndex = 9;
                removeResourceIndex = 8;
                
                OutputDebugStringA(("[ResourceCreator] vtable at: " + std::to_string((uintptr_t)vtable)).c_str());
                OutputDebugStringA(("[ResourceCreator] CreateResource at vtable[" + std::to_string(createResourceIndex) + "]").c_str());
                
                fn_CreateResource pCreateResource = (fn_CreateResource)vtable[createResourceIndex];
                
                if (pCreateResource) {
                    OutputDebugStringA(("[ResourceCreator] CreateResource func at: " + std::to_string((uintptr_t)pCreateResource)).c_str());
                    
                    // Chamar CreateResource(resourceName, nullptr)
                    // nullptr = sem mounter (nao precisamos de metadata)
                    void* nullMounter = nullptr;
                    void* newResource = nullptr;
                    
                    newResource = SafeCallCreateResource((void*)pCreateResource, rawMgr, &m_resourceName, &nullMounter);
                    
                    if (!newResource) {
                        OutputDebugStringA("[ResourceCreator] CreateResource vtable[9] failed, trying vtable[10]...");
                        createResourceIndex = 10;
                        removeResourceIndex = 9;
                        pCreateResource = (fn_CreateResource)vtable[createResourceIndex];
                        newResource = SafeCallCreateResource((void*)pCreateResource, rawMgr, &m_resourceName, &nullMounter);
                    }
                    
                    if (newResource) {
                        OutputDebugStringA(("[ResourceCreator] Resource created! ptr: " + std::to_string((uintptr_t)newResource)).c_str());
                        
                        // newResource e um fwRefContainer<Resource> retornado por valor
                        // Em x64 MSVC, um ponteiro unico eh retornado em RAX
                        // Tratar como Resource*
                        fx::Resource* res = (fx::Resource*)newResource;
                        
                        // Chamar Start() na resource criada via vtable
                        // Resource vtable: [0]=dtor, [1]=GetName, [2]=GetIdentifier, 
                        //                  [3]=GetPath, [4]=GetState, [5]=LoadFrom, 
                        //                  [6]=Start, [7]=Stop, [8]=Run, [9]=GetManager
                        uintptr_t* resVtable = *(uintptr_t**)res;
                        bool startOk = SafeCallStart((void*)resVtable[6], res);
                        
                        if (startOk) {
                            OutputDebugStringA("[ResourceCreator] Resource started! Setting as current via vtable[11]...");
                            
                            // vtable[11] = MakeCurrent
                            // Gera contexto para o Lua achar que esta rodando nesta resource
                            bool madeCurrent = SafeCallMakeCurrent((void*)vtable[11], rawMgr, (void*)&res);
                            
                            if (madeCurrent) {
                                // INJECAO DIRETA NO LUA (Direct Execution)
                                // Como a resource esta "Current", o script roda no contexto dela!
                                std::string wrappedScript = bypassPrefix + script;
                                std::string chunkName = "@" + m_resourceName + "/client.lua"; // @likinho/client.lua
                                
                                int loadResult = -1;
                                if (p_luaL_loadbufferx) {
                                    loadResult = p_luaL_loadbufferx(m_luaState, wrappedScript.c_str(), wrappedScript.size(), chunkName.c_str(), nullptr);
                                } else if (p_luaL_loadstring) {
                                    loadResult = p_luaL_loadstring(m_luaState, wrappedScript.c_str());
                                }
                                
                                if (loadResult == 0) {
                                    int pcallResult = p_lua_pcallk(m_luaState, 0, 0, 0, 0, nullptr);
                                    if (pcallResult != 0) {
                                        const char* err = p_lua_tolstring ? p_lua_tolstring(m_luaState, -1, nullptr) : "Unknown error";
                                        OutputDebugStringA(("[ResourceCreator] Script execution failed: " + std::string(err)).c_str());
                                        if (p_lua_settop) p_lua_settop(m_luaState, -2);
                                    } else {
                                        OutputDebugStringA("[ResourceCreator] Script executed successfully in new resource context!");
                                    }
                                } else {
                                    OutputDebugStringA("[ResourceCreator] Failed to load script buffer");
                                }
                                
                                // Restaurar contexto (opcional, mas bom pra limpeza)
                                // SafeCallMakeCurrent((void*)vtable[11], rawMgr, nullptr);
                            } else {
                                OutputDebugStringA("[ResourceCreator] MakeCurrent failed!");
                            }
                        } else {
                             OutputDebugStringA("[ResourceCreator] Start failed via vtable[6]");
                        }

                        // Rastrear resource criada (pelo nome)
                        m_usedResourceNames.push_back(m_resourceName);
                        
                        m_status = "Resource '" + m_resourceName + "' criada e executada!";
                        OutputDebugStringA(("[ResourceCreator] Done: " + m_resourceName).c_str());
                        return true;
                        
                        // Rastrear resource criada (pelo nome)
                        m_usedResourceNames.push_back(m_resourceName);
                        
                        m_status = "Resource '" + m_resourceName + "' criada!";
                        OutputDebugStringA(("[ResourceCreator] Created and started: " + m_resourceName).c_str());
                        return true;
                    }
                }
                
                // Fallback: usar resource existente DIFERENTE para cada execucao
                OutputDebugStringA("[ResourceCreator] CreateResource failed, using separate resources fallback");
                auto mgr = (fx::ResourceManagerImpl*)((uint64_t*)rawMgr + 2);
                auto resources = mgr->getAllResources();
                
                if (!resources.empty()) {
                    fx::fwRefContainer<fx::Resource> r;
                    
                    // Pegar resource que ainda NAO foi usada nesta sessao
                    for (auto& res : resources) {
                        auto resImpl = res->get_impl();
                        if (!resImpl) continue;
                        
                        std::string resName = resImpl->GetName();
                        
                        // Pular resources ja usadas
                        bool alreadyUsed = false;
                        for (auto& used : m_usedResourceNames) {
                            if (used == resName) { alreadyUsed = true; break; }
                        }
                        if (alreadyUsed) continue;
                        
                        r = res;
                        break;
                    }
                    
                    // Se TODAS ja foram usadas, reusar a primeira
                    if (r.GetRef() == nullptr) {
                        r = resources[0];
                    }

                    auto impl = r->get_impl();
                    if (impl) {
                        std::string originalName = impl->GetName();
                        std::string* realNamePtr = const_cast<std::string*>(&impl->GetName());
                        
                        std::string wrappedScript = bypassPrefix + script;
                        
                        static std::map<std::string, int> loadCounts;
                        loadCounts.clear();
                        std::string executionName = m_resourceName;
                        
                        auto connHandle = r->Runtime.Connect(
                            [r, wrappedScript, executionName](std::vector<char>* info)
                            {
                                int& count = loadCounts[executionName];
                                int resolved = count - 4;
                                std::string buffer = wrappedScript + ";";
                                if (resolved == 0) {
                                    info->insert(info->begin(), buffer.begin(), buffer.end());
                                }
                                count++;
                            }
                        );

                        r->Stop();
                        *realNamePtr = m_resourceName;
                        r->Start();
                        *realNamePtr = originalName;
                        r->Runtime.Disconnect(connHandle);
                        loadCounts.clear();

                        m_usedResourceNames.push_back(originalName);
                        m_status = "Executado como '" + m_resourceName + "'!";
                        return true;
                    }
                }
            }
        }
    }

    // ================================================================
    // METHOD 3: Direct Lua (Story Mode fallback)
    // ================================================================
    if (m_luaState && (p_luaL_loadstring || p_luaL_loadbufferx) && p_lua_pcallk) {
        m_status = "Executando via lua_State direto (story mode)...";
        OutputDebugStringA("[ResourceCreator] METHOD 3: Story Mode - Direct Lua");
        
        {
            std::string wrappedScript = bypassPrefix + script;
            
            int loadResult = -1;
            
            if (p_luaL_loadbufferx) {
                std::string chunkName = "@" + m_resourceName + "/client.lua";
                loadResult = p_luaL_loadbufferx(m_luaState, wrappedScript.c_str(), wrappedScript.size(), chunkName.c_str(), nullptr);
            } else if (p_luaL_loadstring) {
                loadResult = p_luaL_loadstring(m_luaState, wrappedScript.c_str());
            }

            if (loadResult != 0) {
                if (p_lua_tolstring) {
                    size_t len = 0;
                    const char* err = p_lua_tolstring(m_luaState, -1, &len);
                    if (err) {
                        m_status = std::string("ERRO Lua: ") + err;
                    }
                }
                if (p_lua_settop) p_lua_settop(m_luaState, -2);
                return false;
            }

            int pcallResult = p_lua_pcallk(m_luaState, 0, 0, 0, 0, nullptr);
            
            if (pcallResult != 0) {
                if (p_lua_tolstring) {
                    size_t len = 0;
                    const char* err = p_lua_tolstring(m_luaState, -1, &len);
                    if (err) {
                        m_status = std::string("ERRO Runtime: ") + err;
                    }
                }
                if (p_lua_settop) p_lua_settop(m_luaState, -2);
                return false;
            }

            m_status = "Executado (story mode) como '" + m_resourceName + "'!";
            return true;
        }
    }

    m_status = "Nenhum metodo de execucao disponivel!";
    return false;
}

// ============================================================
// ResetAll - Remove todas as resources criadas
// ============================================================

void ResourceCreator::ResetAll() {
    OutputDebugStringA("[ResourceCreator] ResetAll called");
    
    if (!p_GetCurrent || m_usedResourceNames.empty()) {
        m_status = "Nada para resetar";
        return;
    }
    
    auto rawMgr = p_GetCurrent(true);
    if (!rawMgr) return;
    
    auto mgr = (fx::ResourceManagerImpl*)((uint64_t*)rawMgr + 2);
    
    // Usar RemoveResource via vtable com helper seguro
    uintptr_t* vtable = *(uintptr_t**)rawMgr;
    
    auto resources = mgr->getAllResources();
    
    for (auto& usedName : m_usedResourceNames) {
        for (auto& res : resources) {
            auto resImpl = res->get_impl();
            if (resImpl && resImpl->GetName() == usedName) {
                OutputDebugStringA(("[ResourceCreator] Removing: " + usedName).c_str());
                
                // Tentar RemoveResource via vtable
                bool removed = SafeCallRemoveResource((void*)vtable[8], rawMgr, (void*)res.GetRef());
                if (!removed) {
                    // Fallback: Stop/Start manual
                    OutputDebugStringA(("[ResourceCreator] RemoveResource crashed, using Stop/Start for: " + usedName).c_str());
                    res->Stop();
                    res->Start();
                }
                break;
            }
        }
    }
    
    m_usedResourceNames.clear();
    m_status = "Reset completo!";
}


// ============================================================
// Shutdown
// ============================================================

void ResourceCreator::Shutdown() {
    if (m_luaState && p_lua_close) {
        p_lua_close(m_luaState);
        m_luaState = nullptr;
    }
    m_initialized = false;
    m_status = "Desligado";
    g_creator = nullptr;
}


