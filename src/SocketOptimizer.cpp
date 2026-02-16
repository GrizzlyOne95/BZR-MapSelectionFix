#include "SocketOptimizer.h"
#include "Logger.h"
#include <iostream>
#include <cstring>
#include <unordered_set>

namespace MapSelectionFix
{
    /**
     * Implementation of socket buffer optimization
     * 
     * Strategy: Hook socket() and WSASocketW to intercept socket creation,
     * then directly set SO_SNDBUF and SO_RCVBUF to 1MB on all created sockets.
     * 
     * This is more reliable than trying to hook setsockopt since the game
     * may not explicitly call setsockopt, relying on defaults instead.
     */

    // Real function pointers
    typedef SOCKET (WINAPI* socket_fn)(int af, int type, int protocol);
    typedef SOCKET (WINAPI* WSASocketW_fn)(int af, int type, int protocol, LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags);
    typedef int (WINAPI* setsockopt_fn)(SOCKET s, int level, int optname, const char* optval, int optlen);
    typedef int (WINAPI* getsockopt_fn)(SOCKET s, int level, int optname, char* optval, int* optlen);
    typedef int (WINAPI* closesocket_fn)(SOCKET s);
    typedef int (WSAAPI* WSASend_fn)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
    typedef int (WSAAPI* WSARecv_fn)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
    typedef int (WSAAPI* WSASendTo_fn)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const sockaddr* lpTo, int iToLen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
    typedef int (WSAAPI* WSARecvFrom_fn)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);

    socket_fn g_real_socket = nullptr;
    WSASocketW_fn g_real_WSASocketW = nullptr;
    setsockopt_fn g_real_setsockopt = nullptr;
    getsockopt_fn g_real_getsockopt = nullptr;
    closesocket_fn g_real_closesocket = nullptr;
    WSASend_fn g_real_WSASend = nullptr;
    WSARecv_fn g_real_WSARecv = nullptr;
    WSASendTo_fn g_real_WSASendTo = nullptr;
    WSARecvFrom_fn g_real_WSARecvFrom = nullptr;

    // Static function pointer for the hooked setsockopt (for compatibility)
    int (WINAPI* SocketOptimizer::g_real_setsockopt)(
        SOCKET s, int level, int optname, const char* optval, int optlen
    ) = nullptr;

    // Flag to track if we're initialized
    static bool g_socket_optimizer_initialized = false;
    static bool g_socket_lock_initialized = false;
    static CRITICAL_SECTION g_socket_lock;
    static std::unordered_set<SOCKET> g_optimized_sockets;

    // Helper to set socket buffers. Returns true once we attempted to set on this socket.
    bool SetSocketBuffers(SOCKET s)
    {
        if (s == INVALID_SOCKET)
        {
            Logger::Log("[SocketOptimizer] Skipping buffer set: INVALID_SOCKET");
            return false;
        }

        setsockopt_fn set_fn = g_real_setsockopt;
        if (!set_fn)
        {
            HMODULE hWinsock = GetModuleHandleA("ws2_32.dll");
            if (hWinsock)
            {
                set_fn = (setsockopt_fn)GetProcAddress(hWinsock, "setsockopt");
                g_real_setsockopt = set_fn;
            }
        }

        if (!set_fn)
        {
            Logger::LogFormat("[SocketOptimizer] Skipping buffer set for socket 0x%p (setsockopt unavailable)", (void*)(uintptr_t)s);
            return false;
        }

        uint32_t buf_size = 0x100000;  // 1MB
        Logger::LogFormat("[SocketOptimizer] Applying buffer optimization to socket 0x%p", (void*)(uintptr_t)s);
        
        // Set send buffer
        int res = set_fn(s, SOL_SOCKET, SO_SNDBUF, (const char*)&buf_size, sizeof(buf_size));
        if (res == 0)
        {
            Logger::LogFormat("[SocketOptimizer] Set SO_SNDBUF to 0x%X (%u bytes)", buf_size, buf_size);
        }
        else
        {
            Logger::LogFormat("[SocketOptimizer] Failed to set SO_SNDBUF (error: %d)", WSAGetLastError());
        }

        // Set receive buffer
        res = set_fn(s, SOL_SOCKET, SO_RCVBUF, (const char*)&buf_size, sizeof(buf_size));
        if (res == 0)
        {
            Logger::LogFormat("[SocketOptimizer] Set SO_RCVBUF to 0x%X (%u bytes)", buf_size, buf_size);
        }
        else
        {
            Logger::LogFormat("[SocketOptimizer] Failed to set SO_RCVBUF (error: %d)", WSAGetLastError());
        }

        if (g_real_getsockopt)
        {
            int actual = 0;
            int actual_len = sizeof(actual);
            res = g_real_getsockopt(s, SOL_SOCKET, SO_SNDBUF, (char*)&actual, &actual_len);
            if (res == 0)
                Logger::LogFormat("[SocketOptimizer] Readback SO_SNDBUF = 0x%X (%d bytes), len=%d", actual, actual, actual_len);
            else
                Logger::LogFormat("[SocketOptimizer] Readback SO_SNDBUF failed (error: %d)", WSAGetLastError());

            actual = 0;
            actual_len = sizeof(actual);
            res = g_real_getsockopt(s, SOL_SOCKET, SO_RCVBUF, (char*)&actual, &actual_len);
            if (res == 0)
                Logger::LogFormat("[SocketOptimizer] Readback SO_RCVBUF = 0x%X (%d bytes), len=%d", actual, actual, actual_len);
            else
                Logger::LogFormat("[SocketOptimizer] Readback SO_RCVBUF failed (error: %d)", WSAGetLastError());
        }
        else
        {
            Logger::Log("[SocketOptimizer] getsockopt unavailable; skipping readback verification");
        }

        return true;
    }

    // Set buffers exactly once per socket handle.
    void EnsureSocketBuffers(SOCKET s)
    {
        if (s == INVALID_SOCKET)
        {
            Logger::Log("[SocketOptimizer] EnsureSocketBuffers called with INVALID_SOCKET");
            return;
        }

        Logger::LogFormat("[SocketOptimizer] EnsureSocketBuffers for socket 0x%p", (void*)(uintptr_t)s);

        bool already_optimized = false;
        if (g_socket_lock_initialized)
        {
            EnterCriticalSection(&g_socket_lock);
            already_optimized = (g_optimized_sockets.find(s) != g_optimized_sockets.end());
            LeaveCriticalSection(&g_socket_lock);
        }

        if (!already_optimized)
        {
            Logger::LogFormat("[SocketOptimizer] Socket 0x%p not seen before; optimizing now", (void*)(uintptr_t)s);
            bool optimized = SetSocketBuffers(s);
            if (optimized && g_socket_lock_initialized)
            {
                EnterCriticalSection(&g_socket_lock);
                g_optimized_sockets.insert(s);
                LeaveCriticalSection(&g_socket_lock);
                Logger::LogFormat("[SocketOptimizer] Socket 0x%p marked optimized", (void*)(uintptr_t)s);
            }
            else if (!optimized)
            {
                Logger::LogFormat("[SocketOptimizer] Socket 0x%p optimization did not complete; will retry", (void*)(uintptr_t)s);
            }
        }
        else
        {
            Logger::LogFormat("[SocketOptimizer] Socket 0x%p already optimized; skipping", (void*)(uintptr_t)s);
        }
    }

    // Hooked socket() function
    SOCKET WINAPI Hooked_socket(int af, int type, int protocol)
    {
        SOCKET s = g_real_socket(af, type, protocol);
        
        if (s != INVALID_SOCKET)
        {
            Logger::LogFormat("[SocketOptimizer] Socket created (AF=%d, TYPE=%d, PROTO=%d)", af, type, protocol);
            EnsureSocketBuffers(s);
        }
        else
        {
            Logger::LogFormat("[SocketOptimizer] socket() failed with error %d", WSAGetLastError());
        }
        
        return s;
    }

    // Hooked WSASocketW() function
    SOCKET WINAPI Hooked_WSASocketW(int af, int type, int protocol, LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags)
    {
        SOCKET s = g_real_WSASocketW(af, type, protocol, lpProtocolInfo, g, dwFlags);
        
        if (s != INVALID_SOCKET)
        {
            Logger::LogFormat("[SocketOptimizer] WSASocketW created socket (AF=%d, TYPE=%d, PROTO=%d)", af, type, protocol);
            EnsureSocketBuffers(s);
        }
        else
        {
            Logger::LogFormat("[SocketOptimizer] WSASocketW() failed with error %d", WSAGetLastError());
        }
        
        return s;
    }

    int WSAAPI Hooked_WSASend(
        SOCKET s,
        LPWSABUF lpBuffers,
        DWORD dwBufferCount,
        LPDWORD lpNumberOfBytesSent,
        DWORD dwFlags,
        LPWSAOVERLAPPED lpOverlapped,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    )
    {
        EnsureSocketBuffers(s);
        return g_real_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
    }

    int WSAAPI Hooked_WSARecv(
        SOCKET s,
        LPWSABUF lpBuffers,
        DWORD dwBufferCount,
        LPDWORD lpNumberOfBytesRecvd,
        LPDWORD lpFlags,
        LPWSAOVERLAPPED lpOverlapped,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    )
    {
        EnsureSocketBuffers(s);
        return g_real_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
    }

    int WSAAPI Hooked_WSASendTo(
        SOCKET s,
        LPWSABUF lpBuffers,
        DWORD dwBufferCount,
        LPDWORD lpNumberOfBytesSent,
        DWORD dwFlags,
        const sockaddr* lpTo,
        int iToLen,
        LPWSAOVERLAPPED lpOverlapped,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    )
    {
        EnsureSocketBuffers(s);
        return g_real_WSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iToLen, lpOverlapped, lpCompletionRoutine);
    }

    int WSAAPI Hooked_WSARecvFrom(
        SOCKET s,
        LPWSABUF lpBuffers,
        DWORD dwBufferCount,
        LPDWORD lpNumberOfBytesRecvd,
        LPDWORD lpFlags,
        sockaddr* lpFrom,
        LPINT lpFromlen,
        LPWSAOVERLAPPED lpOverlapped,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
    )
    {
        EnsureSocketBuffers(s);
        return g_real_WSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
    }

    int WINAPI Hooked_closesocket(SOCKET s)
    {
        if (g_socket_lock_initialized && s != INVALID_SOCKET)
        {
            EnterCriticalSection(&g_socket_lock);
            size_t erased = g_optimized_sockets.erase(s);
            LeaveCriticalSection(&g_socket_lock);
            if (erased > 0)
                Logger::LogFormat("[SocketOptimizer] Removed socket 0x%p from optimized set on close", (void*)(uintptr_t)s);
        }

        if (!g_real_closesocket)
        {
            Logger::Log("[SocketOptimizer] closesocket hook called but real function is null");
            WSASetLastError(WSAEFAULT);
            return SOCKET_ERROR;
        }

        return g_real_closesocket(s);
    }

    // Compatibility hooked setsockopt (for any code that hooks this directly)
    int WINAPI SocketOptimizer::Hooked_setsockopt(
        SOCKET s,
        int level,
        int optname,
        const char* optval,
        int optlen
    )
    {
        // Check if this is a buffer size operation that we should upgrade
        if (level == SOL_SOCKET && optval && optlen >= sizeof(uint32_t))
        {
            uint32_t original_value = *(uint32_t*)optval;

            if (optname == SO_SNDBUF && original_value == 0x8000)
            {
                Logger::LogFormat("[SocketOptimizer] Intercepted SO_SNDBUF: 0x%X → 0x100000", 0x8000);
                uint32_t optimized_value = 0x100000;
                return g_real_setsockopt(s, level, optname, (const char*)&optimized_value, sizeof(optimized_value));
            }
            else if (optname == SO_RCVBUF && original_value == 0x8000)
            {
                Logger::LogFormat("[SocketOptimizer] Intercepted SO_RCVBUF: 0x%X → 0x100000", 0x8000);
                uint32_t optimized_value = 0x100000;
                return g_real_setsockopt(s, level, optname, (const char*)&optimized_value, sizeof(optimized_value));
            }
        }

        // For all other calls, pass through unchanged
        return g_real_setsockopt(s, level, optname, optval, optlen);
    }

    void SocketOptimizer::Initialize()
    {
        if (g_socket_optimizer_initialized)
            return;

        Logger::Log("[SocketOptimizer] Initializing...");

        // Mark as initialized early to prevent re-entry
        g_socket_optimizer_initialized = true;

        try
        {
            // Get ws2_32.dll and function pointers
            HMODULE hWinsock = GetModuleHandleA("ws2_32.dll");
            if (!hWinsock)
            {
                Logger::Log("[SocketOptimizer] Could not load ws2_32.dll");
                return;
            }

            // Get function addresses
            g_real_socket = (socket_fn)GetProcAddress(hWinsock, "socket");
            g_real_WSASocketW = (WSASocketW_fn)GetProcAddress(hWinsock, "WSASocketW");
            g_real_setsockopt = (setsockopt_fn)GetProcAddress(hWinsock, "setsockopt");
            g_real_getsockopt = (getsockopt_fn)GetProcAddress(hWinsock, "getsockopt");
            g_real_closesocket = (closesocket_fn)GetProcAddress(hWinsock, "closesocket");
            g_real_WSASend = (WSASend_fn)GetProcAddress(hWinsock, "WSASend");
            g_real_WSARecv = (WSARecv_fn)GetProcAddress(hWinsock, "WSARecv");
            g_real_WSASendTo = (WSASendTo_fn)GetProcAddress(hWinsock, "WSASendTo");
            g_real_WSARecvFrom = (WSARecvFrom_fn)GetProcAddress(hWinsock, "WSARecvFrom");

            // Store in class member for compatibility
            SocketOptimizer::g_real_setsockopt = g_real_setsockopt;

            if (!g_real_socket)
            {
                Logger::Log("[SocketOptimizer] Could not find socket() in ws2_32.dll");
                return;
            }

            if (!g_real_setsockopt)
            {
                Logger::Log("[SocketOptimizer] Could not find setsockopt() in ws2_32.dll");
                return;
            }

            Logger::LogFormat("[SocketOptimizer] Got socket() at 0x%p", g_real_socket);
            Logger::LogFormat("[SocketOptimizer] Got setsockopt() at 0x%p", g_real_setsockopt);
            Logger::LogFormat("[SocketOptimizer] Got getsockopt() at 0x%p", g_real_getsockopt);
            Logger::LogFormat("[SocketOptimizer] Got closesocket() at 0x%p", g_real_closesocket);
            Logger::LogFormat("[SocketOptimizer] Got WSASend() at 0x%p", g_real_WSASend);
            Logger::LogFormat("[SocketOptimizer] Got WSARecv() at 0x%p", g_real_WSARecv);

            if (!g_socket_lock_initialized)
            {
                InitializeCriticalSection(&g_socket_lock);
                g_socket_lock_initialized = true;
            }

            // Patch whichever winsock imports the game is currently using.
            if (PatchIAT())
            {
                Logger::Log("[SocketOptimizer] Successfully installed winsock IAT hooks");
                Logger::Log("[SocketOptimizer] Socket buffers will be optimized on first socket use");
            }
            else
            {
                Logger::Log("[SocketOptimizer] No compatible winsock imports were patched - buffers may not be optimized");
            }
        }
        catch (...)
        {
            Logger::Log("[SocketOptimizer] Exception during init");
        }
    }

    bool SocketOptimizer::InstallInlineHook(void* target_func, void* hook_func)
    {
        if (!target_func || !hook_func)
            return false;

        try
        {
            unsigned char* target = (unsigned char*)target_func;

            // Create a 5-byte jump instruction: JMP relative32
            // Format: E9 [relative offset as 4-byte little-endian]
            unsigned char jump_code[5];
            jump_code[0] = 0xE9; // JMP rel32 opcode

            // Calculate relative offset: target_jmp_location + 5 = hook_func + offset
            // So: offset = hook_func - (target + 5)
            intptr_t hook_offset = (intptr_t)hook_func - ((intptr_t)target + 5);

            // Store offset as little-endian 4-byte value
            memcpy(&jump_code[1], &hook_offset, 4);

            // Disable write protection on the memory page
            DWORD old_protect;
            if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old_protect))
            {
                Logger::Log("[SocketOptimizer] Failed to unprotect memory for hooking");
                return false;
            }

            // Write the jump
            memcpy(target, jump_code, 5);

            // Restore protection
            VirtualProtect(target, 5, old_protect, &old_protect);

            // Flush CPU instruction cache
            FlushInstructionCache(GetCurrentProcess(), target, 5);

            Logger::LogFormat("[SocketOptimizer] Installed inline hook at 0x%p", target);
            return true;
        }
        catch (...)
        {
            Logger::Log("[SocketOptimizer] Exception installing hook");
            return false;
        }
    }

    bool SocketOptimizer::PatchIAT()
    {
        try
        {
            HMODULE hGameMod = GetModuleHandleA(NULL);  // Game executable
            if (!hGameMod)
            {
                Logger::Log("[SocketOptimizer] Could not get game module");
                return false;
            }

            Logger::LogFormat("[SocketOptimizer] Game module base: 0x%p", hGameMod);

            // Get PE header
            DWORD_PTR mod_base = (DWORD_PTR)hGameMod;
            PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mod_base;

            if (IsBadReadPtr(pDosHeader, sizeof(IMAGE_DOS_HEADER)))
            {
                Logger::Log("[SocketOptimizer] Invalid DOS header pointer");
                return false;
            }

            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            {
                Logger::LogFormat("[SocketOptimizer] Invalid PE signature (got 0x%X)", pDosHeader->e_magic);
                return false;
            }

            PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(mod_base + pDosHeader->e_lfanew);
            
            if (IsBadReadPtr(pNtHeaders, sizeof(IMAGE_NT_HEADERS)))
            {
                Logger::Log("[SocketOptimizer] Invalid NT header pointer");
                return false;
            }

            if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
            {
                Logger::LogFormat("[SocketOptimizer] Invalid NT signature (got 0x%X)", pNtHeaders->Signature);
                return false;
            }

            // Get Import Directory
            DWORD import_rva = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            DWORD import_size = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

            if (!import_rva || !import_size)
            {
                Logger::Log("[SocketOptimizer] No import directory found");
                return false;
            }

            PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(mod_base + import_rva);
            
            Logger::Log("[SocketOptimizer] Searching for winsock imports in game IAT...");

            // Look for ws2_32.dll
            bool found_ws2 = false;
            int patched_count = 0;
            int dll_count = 0;

            for (; pImportDesc->Name && dll_count < 100; pImportDesc++, dll_count++)
            {
                const char* dll_name = (const char*)(mod_base + pImportDesc->Name);
                
                if (_stricmp(dll_name, "ws2_32.dll") == 0)
                {
                    Logger::Log("[SocketOptimizer] Found ws2_32.dll in IAT");
                    found_ws2 = true;

                    // Use OriginalFirstThunk to read names, FirstThunk to patch
                    DWORD_PTR oft_addr = mod_base + pImportDesc->OriginalFirstThunk;
                    PIMAGE_THUNK_DATA pOftThunk = (PIMAGE_THUNK_DATA)oft_addr;
                    
                    DWORD_PTR iat_addr = mod_base + pImportDesc->FirstThunk;
                    PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)iat_addr;

                    int thunk_count = 0;
                    for (; thunk_count < 500; pOftThunk++, pThunk++, thunk_count++)
                    {
                        if (IsBadReadPtr(pOftThunk, sizeof(IMAGE_THUNK_DATA)))
                            break;

                        if (pOftThunk->u1.AddressOfData == 0)
                        {
                            Logger::LogFormat("[SocketOptimizer] Reached end of IAT after %d entries", thunk_count);
                            break;
                        }

                        if (pOftThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                            continue;

                        DWORD import_by_name_rva = pOftThunk->u1.AddressOfData;
                        DWORD_PTR import_by_name_addr = mod_base + import_by_name_rva;
                        
                        if (IsBadReadPtr((void*)import_by_name_addr, sizeof(IMAGE_IMPORT_BY_NAME) + 16))
                            continue;

                        PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)import_by_name_addr;
                        const char* func_name = (const char*)pImportByName->Name;

                        if (IsBadStringPtrA(func_name, 256))
                            continue;

                        void* hook_target = nullptr;
                        void** real_target = nullptr;

                        if (strcmp(func_name, "WSASocketW") == 0)
                        {
                            hook_target = (void*)Hooked_WSASocketW;
                            real_target = (void**)&g_real_WSASocketW;
                        }
                        else if (strcmp(func_name, "socket") == 0)
                        {
                            hook_target = (void*)Hooked_socket;
                            real_target = (void**)&g_real_socket;
                        }
                        else if (strcmp(func_name, "WSASend") == 0)
                        {
                            hook_target = (void*)Hooked_WSASend;
                            real_target = (void**)&g_real_WSASend;
                        }
                        else if (strcmp(func_name, "WSARecv") == 0)
                        {
                            hook_target = (void*)Hooked_WSARecv;
                            real_target = (void**)&g_real_WSARecv;
                        }
                        else if (strcmp(func_name, "WSASendTo") == 0)
                        {
                            hook_target = (void*)Hooked_WSASendTo;
                            real_target = (void**)&g_real_WSASendTo;
                        }
                        else if (strcmp(func_name, "WSARecvFrom") == 0)
                        {
                            hook_target = (void*)Hooked_WSARecvFrom;
                            real_target = (void**)&g_real_WSARecvFrom;
                        }
                        else if (strcmp(func_name, "closesocket") == 0)
                        {
                            hook_target = (void*)Hooked_closesocket;
                            real_target = (void**)&g_real_closesocket;
                        }

                        if (hook_target != nullptr)
                        {
                            Logger::LogFormat("[SocketOptimizer] Found %s at IAT entry 0x%p", func_name, pThunk);

                            // Patch the IAT to point to our hook.
                            DWORD old_protect;
                            if (VirtualProtect(pThunk, sizeof(pThunk->u1.Function), PAGE_READWRITE, &old_protect))
                            {
                                if (real_target != nullptr && *real_target == nullptr)
                                    *real_target = (void*)(uintptr_t)pThunk->u1.Function;

                                Logger::LogFormat("[SocketOptimizer] Original %s entry: 0x%p", func_name, (void*)(uintptr_t)pThunk->u1.Function);
                                pThunk->u1.Function = (ULONG_PTR)hook_target;
                                VirtualProtect(pThunk, sizeof(pThunk->u1.Function), old_protect, &old_protect);
                                FlushInstructionCache(GetCurrentProcess(), pThunk, sizeof(pThunk->u1.Function));

                                Logger::LogFormat("[SocketOptimizer] Patched %s to: 0x%p", func_name, (void*)(uintptr_t)pThunk->u1.Function);
                                patched_count++;
                            }
                            else
                            {
                                Logger::LogFormat("[SocketOptimizer] Failed to unprotect IAT for %s (error: %d)", func_name, GetLastError());
                            }
                        }
                    }
                }
            }

            if (!found_ws2)
                Logger::Log("[SocketOptimizer] ws2_32.dll not found in game IAT");
            if (patched_count == 0)
                Logger::Log("[SocketOptimizer] No target winsock imports found in ws2_32 import table");
            else
                Logger::LogFormat("[SocketOptimizer] Patched %d winsock IAT entries", patched_count);

            return patched_count > 0;
        }
        catch (...)
        {
            Logger::Log("[SocketOptimizer] Exception patching IAT");
            return false;
        }
    }

    void SocketOptimizer::Shutdown()
    {
        if (g_socket_optimizer_initialized)
        {
            Logger::Log("[SocketOptimizer] Shutting down...");
            if (g_socket_lock_initialized)
            {
                EnterCriticalSection(&g_socket_lock);
                g_optimized_sockets.clear();
                LeaveCriticalSection(&g_socket_lock);
                DeleteCriticalSection(&g_socket_lock);
                g_socket_lock_initialized = false;
            }
            g_socket_optimizer_initialized = false;
            // Pointer cleanup not necessary (DLL is unloading anyway)
        }
    }
}
