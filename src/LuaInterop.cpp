#include "LuaInterop.h"
#include "Logger.h"

#include <Windows.h>
#include <cstdio>

namespace MapSelectionFix
{
    namespace
    {
        constexpr uintptr_t kRvaLuaCheckStatus = 0x000FF600; // BZR 2.2.301: bool LuaCheckStatus(int,lua_State*,const char*)
        constexpr int LUA_TFUNCTION = 6;

        typedef int(__cdecl* lua_gettop_fn)(void* L);
        typedef void(__cdecl* lua_settop_fn)(void* L, int idx);
        typedef void(__cdecl* lua_getglobal_fn)(void* L, const char* name);
        typedef void(__cdecl* lua_setglobal_fn)(void* L, const char* name);
        typedef void(__cdecl* lua_pushstring_fn)(void* L, const char* s);
        typedef void(__cdecl* lua_pushnumber_fn)(void* L, double n);
        typedef int(__cdecl* lua_pcall_fn)(void* L, int nargs, int nresults, int errfunc);
        typedef int(__cdecl* lua_type_fn)(void* L, int idx);
        typedef const char*(__cdecl* lua_tolstring_fn)(void* L, int idx, size_t* len);

        struct LuaApi
        {
            lua_gettop_fn gettop = nullptr;
            lua_settop_fn settop = nullptr;
            lua_getglobal_fn getglobal = nullptr;
            lua_setglobal_fn setglobal = nullptr;
            lua_pushstring_fn pushstring = nullptr;
            lua_pushnumber_fn pushnumber = nullptr;
            lua_pcall_fn pcall = nullptr;
            lua_type_fn type = nullptr;
            lua_tolstring_fn tostring = nullptr;
            HMODULE module = nullptr;
        };

        LuaApi g_lua_api;
        bool g_initialized = false;
        void* g_lua_state = nullptr;
        char g_state_source[64] = {0};
        bool g_objective_iter_fix_installed = false;

        PVOID g_veh_cookie = nullptr;
        uintptr_t g_hook_address = 0;
        uint8_t g_original_byte = 0;
        bool g_hook_active = false;
        bool g_hook_reload_pending = false;

        void ResolveLuaApi()
        {
            if (g_lua_api.gettop && g_lua_api.settop && g_lua_api.getglobal && g_lua_api.setglobal && g_lua_api.pushstring && g_lua_api.pushnumber && g_lua_api.pcall && g_lua_api.type)
                return;

            const char* kCandidateModules[] = {
                "lua5.1-bzr.dll",
                "lua51.dll",
                "lua5.1.dll",
                "lua.dll",
                nullptr
            };

            HMODULE exe = GetModuleHandleA(nullptr);
            if (exe)
            {
                g_lua_api.gettop = (lua_gettop_fn)GetProcAddress(exe, "lua_gettop");
                g_lua_api.settop = (lua_settop_fn)GetProcAddress(exe, "lua_settop");
                g_lua_api.getglobal = (lua_getglobal_fn)GetProcAddress(exe, "lua_getglobal");
                g_lua_api.setglobal = (lua_setglobal_fn)GetProcAddress(exe, "lua_setglobal");
                g_lua_api.pushstring = (lua_pushstring_fn)GetProcAddress(exe, "lua_pushstring");
                g_lua_api.pushnumber = (lua_pushnumber_fn)GetProcAddress(exe, "lua_pushnumber");
                g_lua_api.pcall = (lua_pcall_fn)GetProcAddress(exe, "lua_pcall");
                g_lua_api.type = (lua_type_fn)GetProcAddress(exe, "lua_type");
                g_lua_api.tostring = (lua_tolstring_fn)GetProcAddress(exe, "lua_tolstring");
                if (g_lua_api.gettop && g_lua_api.settop && g_lua_api.getglobal && g_lua_api.setglobal && g_lua_api.pushstring && g_lua_api.pushnumber && g_lua_api.pcall && g_lua_api.type)
                {
                    g_lua_api.module = exe;
                    Logger::Log("[LuaInterop] Resolved Lua API exports from game executable");
                    return;
                }
            }

            for (int i = 0; kCandidateModules[i] != nullptr; ++i)
            {
                HMODULE mod = GetModuleHandleA(kCandidateModules[i]);
                if (!mod)
                    continue;

                lua_gettop_fn gettop = (lua_gettop_fn)GetProcAddress(mod, "lua_gettop");
                lua_settop_fn settop = (lua_settop_fn)GetProcAddress(mod, "lua_settop");
                lua_getglobal_fn getglobal = (lua_getglobal_fn)GetProcAddress(mod, "lua_getglobal");
                lua_setglobal_fn setglobal = (lua_setglobal_fn)GetProcAddress(mod, "lua_setglobal");
                lua_pushstring_fn pushstring = (lua_pushstring_fn)GetProcAddress(mod, "lua_pushstring");
                lua_pushnumber_fn pushnumber = (lua_pushnumber_fn)GetProcAddress(mod, "lua_pushnumber");
                lua_pcall_fn pcall = (lua_pcall_fn)GetProcAddress(mod, "lua_pcall");
                lua_type_fn type = (lua_type_fn)GetProcAddress(mod, "lua_type");

                if (gettop && settop && getglobal && setglobal && pushstring && pushnumber && pcall && type)
                {
                    g_lua_api.gettop = gettop;
                    g_lua_api.settop = settop;
                    g_lua_api.getglobal = getglobal;
                    g_lua_api.setglobal = setglobal;
                    g_lua_api.pushstring = pushstring;
                    g_lua_api.pushnumber = pushnumber;
                    g_lua_api.pcall = pcall;
                    g_lua_api.type = type;
                    g_lua_api.tostring = (lua_tolstring_fn)GetProcAddress(mod, "lua_tolstring");
                    g_lua_api.module = mod;
                    Logger::LogFormat("[LuaInterop] Resolved Lua API exports from %s", kCandidateModules[i]);
                    return;
                }
            }

            Logger::Log("[LuaInterop] Lua C API exports not found yet (will still capture state for future use)");
        }

        bool InstallHook()
        {
            if (g_hook_active)
                return true;

            uintptr_t base = (uintptr_t)GetModuleHandleA(nullptr);
            if (!base)
                return false;

            g_hook_address = base + kRvaLuaCheckStatus;
            uint8_t* patch_addr = (uint8_t*)g_hook_address;

            DWORD old_protect = 0;
            if (!VirtualProtect(patch_addr, 1, PAGE_EXECUTE_READWRITE, &old_protect))
            {
                Logger::LogFormat("[LuaInterop] Failed to change protection for Lua hook address 0x%p", patch_addr);
                return false;
            }

            g_original_byte = *patch_addr;
            *patch_addr = 0xCC;
            VirtualProtect(patch_addr, 1, old_protect, &old_protect);
            FlushInstructionCache(GetCurrentProcess(), patch_addr, 1);
            g_hook_active = true;

            Logger::LogFormat("[LuaInterop] Hooked LuaCheckStatus at RVA 0x%X (VA 0x%p)", (unsigned)kRvaLuaCheckStatus, patch_addr);
            return true;
        }

        void RemoveHook()
        {
            if (!g_hook_active || !g_hook_address)
                return;

            uint8_t* patch_addr = (uint8_t*)g_hook_address;
            DWORD old_protect = 0;
            if (VirtualProtect(patch_addr, 1, PAGE_EXECUTE_READWRITE, &old_protect))
            {
                *patch_addr = g_original_byte;
                VirtualProtect(patch_addr, 1, old_protect, &old_protect);
                FlushInstructionCache(GetCurrentProcess(), patch_addr, 1);
            }

            g_hook_active = false;
            g_hook_reload_pending = false;
        }

        bool TryCaptureState(void* candidate_state, const char* source)
        {
            if (!candidate_state)
                return false;

            if (g_lua_api.gettop)
            {
                __try
                {
                    (void)g_lua_api.gettop(candidate_state);
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    Logger::LogFormat("[LuaInterop] Rejected invalid lua_State* from %s: 0x%p", source, candidate_state);
                    return false;
                }
            }

            if (g_lua_state == candidate_state)
                return true;

            g_lua_state = candidate_state;
            std::snprintf(g_state_source, sizeof(g_state_source), "%s", source ? source : "unknown");
            Logger::LogFormat("[LuaInterop] Captured lua_State* from %s: 0x%p", g_state_source, g_lua_state);
            return true;
        }

        bool EvalLuaChunk(const char* code)
        {
            if (!g_lua_state || !code)
                return false;

            if (!g_lua_api.gettop || !g_lua_api.settop || !g_lua_api.getglobal || !g_lua_api.pushstring || !g_lua_api.pcall || !g_lua_api.type)
                return false;

            int top = g_lua_api.gettop(g_lua_state);

            // loadstring(code) -> function
            g_lua_api.getglobal(g_lua_state, "loadstring");
            if (g_lua_api.type(g_lua_state, -1) != LUA_TFUNCTION)
            {
                g_lua_api.settop(g_lua_state, top);
                Logger::Log("[LuaInterop] loadstring not available; cannot install ObjectiveObjects fix");
                return false;
            }

            g_lua_api.pushstring(g_lua_state, code);
            int status = g_lua_api.pcall(g_lua_state, 1, 1, 0);
            if (status != 0)
            {
                if (g_lua_api.tostring)
                {
                    size_t len = 0;
                    const char* err = g_lua_api.tostring(g_lua_state, -1, &len);
                    if (err)
                        Logger::LogFormat("[LuaInterop] loadstring failed: %.*s", (int)len, err);
                }
                g_lua_api.settop(g_lua_state, top);
                return false;
            }

            // call compiled chunk
            if (g_lua_api.type(g_lua_state, -1) != LUA_TFUNCTION)
            {
                g_lua_api.settop(g_lua_state, top);
                Logger::Log("[LuaInterop] loadstring result is not callable");
                return false;
            }

            status = g_lua_api.pcall(g_lua_state, 0, 0, 0);
            if (status != 0)
            {
                if (g_lua_api.tostring)
                {
                    size_t len = 0;
                    const char* err = g_lua_api.tostring(g_lua_state, -1, &len);
                    if (err)
                        Logger::LogFormat("[LuaInterop] ObjectiveObjects patch chunk failed: %.*s", (int)len, err);
                }
                g_lua_api.settop(g_lua_state, top);
                return false;
            }

            g_lua_api.settop(g_lua_state, top);
            return true;
        }

        void TryInstallObjectiveObjectsFix()
        {
            if (g_objective_iter_fix_installed || !g_lua_state)
                return;

            static const char* kObjectiveObjectsFixScript =
                "if not _G.__msf_ObjectiveObjectsFix then\n"
                "  local _all = _G.AllObjects\n"
                "  local _getname = _G.GetObjectiveName\n"
                "  local _old = _G.ObjectiveObjects\n"
                "  if type(_all) == 'function' and type(_getname) == 'function' then\n"
                "    _G.ObjectiveObjects = function()\n"
                "      local it = _all()\n"
                "      if type(it) ~= 'function' then\n"
                "        if type(_old) == 'function' then return _old() end\n"
                "        return function() return nil end\n"
                "      end\n"
                "      return function()\n"
                "        while true do\n"
                "          local h = it()\n"
                "          if h == nil then return nil end\n"
                "          local ok, name = pcall(_getname, h)\n"
                "          if ok and name ~= nil then return h end\n"
                "        end\n"
                "      end\n"
                "    end\n"
                "    _G.ObjectiveObjectives = _G.ObjectiveObjects\n"
                "    _G.__msf_ObjectiveObjectsFix = true\n"
                "  end\n"
                "end";

            if (EvalLuaChunk(kObjectiveObjectsFixScript))
            {
                g_objective_iter_fix_installed = true;
                Logger::Log("[LuaInterop] Installed ObjectiveObjects iterator compatibility fix");
            }
        }

        LONG WINAPI Handler(EXCEPTION_POINTERS* exception_info)
        {
            if (!exception_info || !exception_info->ExceptionRecord || !exception_info->ContextRecord)
                return EXCEPTION_CONTINUE_SEARCH;

            DWORD code = exception_info->ExceptionRecord->ExceptionCode;
            if (code == EXCEPTION_BREAKPOINT)
            {
                uintptr_t eip = exception_info->ContextRecord->Eip;
                if (g_hook_active && eip == g_hook_address)
                {
                    uintptr_t esp = exception_info->ContextRecord->Esp;
                    if (esp != 0)
                    {
                        __try
                        {
                            void* state = *(void**)(esp + 8); // second cdecl argument
                            if (TryCaptureState(state, "LuaCheckStatus"))
                                TryInstallObjectiveObjectsFix();
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER)
                        {
                            Logger::Log("[LuaInterop] Failed to read lua_State argument from stack");
                        }
                    }

                    RemoveHook();
                    g_hook_reload_pending = true;
                    exception_info->ContextRecord->EFlags |= 0x100; // trap flag
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            else if (code == EXCEPTION_SINGLE_STEP)
            {
                if (g_hook_reload_pending)
                {
                    g_hook_reload_pending = false;
                    InstallHook();
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }

            return EXCEPTION_CONTINUE_SEARCH;
        }

        bool CallFactory3(const char* factory_name, double a, double b, double c)
        {
            if (!g_lua_state)
            {
                Logger::Log("[LuaInterop] No lua_State captured yet; helper call skipped");
                return false;
            }

            if (!g_lua_api.gettop || !g_lua_api.settop || !g_lua_api.getglobal || !g_lua_api.pushnumber || !g_lua_api.pcall || !g_lua_api.type)
            {
                Logger::Log("[LuaInterop] Lua API unresolved; helper call skipped");
                return false;
            }

            int top = g_lua_api.gettop(g_lua_state);
            g_lua_api.getglobal(g_lua_state, factory_name);
            if (g_lua_api.type(g_lua_state, -1) != LUA_TFUNCTION)
            {
                g_lua_api.settop(g_lua_state, top);
                Logger::LogFormat("[LuaInterop] Lua global '%s' not found or not callable", factory_name);
                return false;
            }

            g_lua_api.pushnumber(g_lua_state, a);
            g_lua_api.pushnumber(g_lua_state, b);
            g_lua_api.pushnumber(g_lua_state, c);

            int status = g_lua_api.pcall(g_lua_state, 3, 1, 0);
            if (status != 0)
            {
                if (g_lua_api.tostring)
                {
                    size_t len = 0;
                    const char* err = g_lua_api.tostring(g_lua_state, -1, &len);
                    if (err)
                        Logger::LogFormat("[LuaInterop] %s call failed: %.*s", factory_name, (int)len, err);
                    else
                        Logger::LogFormat("[LuaInterop] %s call failed with status %d", factory_name, status);
                }
                else
                {
                    Logger::LogFormat("[LuaInterop] %s call failed with status %d", factory_name, status);
                }
                g_lua_api.settop(g_lua_state, top);
                return false;
            }

            // Compatibility wrappers are non-returning helpers for now.
            g_lua_api.settop(g_lua_state, top);
            return true;
        }

        bool CallFactory12(const char* factory_name, const double* values)
        {
            if (!g_lua_state)
            {
                Logger::Log("[LuaInterop] No lua_State captured yet; helper call skipped");
                return false;
            }

            if (!g_lua_api.gettop || !g_lua_api.settop || !g_lua_api.getglobal || !g_lua_api.pushnumber || !g_lua_api.pcall || !g_lua_api.type)
            {
                Logger::Log("[LuaInterop] Lua API unresolved; helper call skipped");
                return false;
            }

            int top = g_lua_api.gettop(g_lua_state);
            g_lua_api.getglobal(g_lua_state, factory_name);
            if (g_lua_api.type(g_lua_state, -1) != LUA_TFUNCTION)
            {
                g_lua_api.settop(g_lua_state, top);
                Logger::LogFormat("[LuaInterop] Lua global '%s' not found or not callable", factory_name);
                return false;
            }

            for (int i = 0; i < 12; ++i)
                g_lua_api.pushnumber(g_lua_state, values[i]);

            int status = g_lua_api.pcall(g_lua_state, 12, 1, 0);
            if (status != 0)
            {
                if (g_lua_api.tostring)
                {
                    size_t len = 0;
                    const char* err = g_lua_api.tostring(g_lua_state, -1, &len);
                    if (err)
                        Logger::LogFormat("[LuaInterop] %s call failed: %.*s", factory_name, (int)len, err);
                    else
                        Logger::LogFormat("[LuaInterop] %s call failed with status %d", factory_name, status);
                }
                else
                {
                    Logger::LogFormat("[LuaInterop] %s call failed with status %d", factory_name, status);
                }
                g_lua_api.settop(g_lua_state, top);
                return false;
            }

            // Compatibility wrappers are non-returning helpers for now.
            g_lua_api.settop(g_lua_state, top);
            return true;
        }
    }

    void LuaInterop::Initialize()
    {
        if (g_initialized)
            return;

        Logger::Log("[LuaInterop] Initializing...");
        ResolveLuaApi();

        g_veh_cookie = AddVectoredExceptionHandler(1, Handler);
        if (!g_veh_cookie)
        {
            Logger::Log("[LuaInterop] Failed to install VEH handler");
            return;
        }

        if (!InstallHook())
            Logger::Log("[LuaInterop] Failed to install LuaCheckStatus hook");

        g_initialized = true;
        Logger::Log("[LuaInterop] Initialized");
    }

    void LuaInterop::Shutdown()
    {
        if (!g_initialized)
            return;

        Logger::Log("[LuaInterop] Shutting down...");
        RemoveHook();

        if (g_veh_cookie)
        {
            RemoveVectoredExceptionHandler(g_veh_cookie);
            g_veh_cookie = nullptr;
        }

        g_lua_state = nullptr;
        g_state_source[0] = '\0';
        g_objective_iter_fix_installed = false;
        g_lua_api = LuaApi{};
        g_initialized = false;
    }

    bool LuaInterop::HasState()
    {
        return g_lua_state != nullptr;
    }

    bool LuaInterop::PushVectorCompat(const BZR::VECTOR_3D& v)
    {
        return CallFactory3("SetVector", v.x, v.y, v.z);
    }

    bool LuaInterop::PushMatrixCompat(const BZR::MAT_3D& m)
    {
        // Stock BZR SetMatrix expects up/right/front/position order.
        const double values[12] = {
            m.up_x, m.up_y, m.up_z,
            m.right_x, m.right_y, m.right_z,
            m.front_x, m.front_y, m.front_z,
            m.posit_x, m.posit_y, m.posit_z
        };
        return CallFactory12("SetMatrix", values);
    }
}
