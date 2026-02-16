#pragma once

#include <Windows.h>
#include <vector>
#include <memory>

namespace MapSelectionFix
{
    /**
     * Network Tuning Module
     * 
     * Patches socket buffer sizes from 32KB to 1MB to improve network stability
     * in Battlezone 98 Redux multiplayer. This addresses packet loss issues that
     * occur with multiple concurrent players on high-latency networks.
     */
    class NetTune
    {
    public:
        /**
         * Initialize network patches.
         * Called during DLL_PROCESS_ATTACH.
         * Patches SO_SNDBUF and SO_RCVBUF constants in the game executable.
         */
        static void Initialize();

        /**
         * Shutdown network patches.
         * Called during DLL_PROCESS_DETACH.
         * Reverts patches to original buffer sizes.
         */
        static void Shutdown();

        /**
         * Generic pattern finder for cross-version compatibility.
         * Can be used to locate patches if offsets change in future game versions.
         */
        static uintptr_t FindPattern(uintptr_t start, uintptr_t end, const uint8_t* pattern, const char* mask);

        /**
         * Advanced patching for multiple variants.
         * Reserved for future use with version detection.
         */
        static void ApplyPatches(uintptr_t tableAddr, int patternType);
    };
}
