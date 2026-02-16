#pragma once

#define WIN32_LEAN_AND_MEAN
#define _WINSOCKAPI_  // Prevent winsock.h from being included
#include <Windows.h>
#include <WinSock2.h>
#include <cstdint>

namespace MapSelectionFix
{
    /**
     * Network Socket Buffer Optimizer
     * 
     * Hooks socket() to increase buffer sizes from 32KB to 1MB on socket creation.
     * This improves network stability in multiplayer by reducing packet loss
     * and improving buffering for high-latency networks.
     * 
     * Strategy: Hook socket() and WSASocketW() imports to intercept socket creation,
     * then immediately set SO_SNDBUF and SO_RCVBUF to 1MB before returning to caller.
     */
    class SocketOptimizer
    {
    public:
        /**
         * Initialize socket optimization
         * Hooks the WSASetSockOpt import from ws2_32.dll
         */
        static void Initialize();

        /**
         * Shutdown socket optimization
         */
        static void Shutdown();

    private:
        /**
         * Install an inline code hook at target_func to jump to hook_func
         * Used for low-level function interception
         */
        static bool InstallInlineHook(void* target_func, void* hook_func);

        /**
         * Patch the game executable's Import Address Table (IAT) to redirect
         * setsockopt calls to our hooked version
         */
        static bool PatchIAT();
        /**
         * Our hooked version of setsockopt
         * Intercepts socket buffer size requests and amplifies them
         */
        static int WINAPI Hooked_setsockopt(
            SOCKET s,
            int level,
            int optname,
            const char* optval,
            int optlen
        );

        /**
         * Pointer to the original/real setsockopt function
         */
        static int (WINAPI* g_real_setsockopt)(
            SOCKET s,
            int level,
            int optname,
            const char* optval,
            int optlen
        );

        // Socket constants
        static constexpr uint32_t ORIGINAL_BUFFER_SIZE = 0x8000;     // 32 KB
        static constexpr uint32_t OPTIMIZED_BUFFER_SIZE = 0x100000;  // 1 MB
    };
}
