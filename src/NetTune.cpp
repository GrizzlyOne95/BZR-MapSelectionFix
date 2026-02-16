#include "NetTune.h"
#include "BasicPatch.h"
#include <cstring>
#include <iostream>

namespace MapSelectionFix
{
    /**
     * Network Tuning Patches for Battlezone 98 Redux v2.0.188+
     * 
     * These patches increase socket buffer sizes from 32KB to 1MB
     * to improve network stability and reduce packet loss in multiplayer.
     * 
     * Based on reverse engineering of working bzcp.dll implementation.
     */

    // Socket buffer size patches (file offsets in .bind section)
    static constexpr uintptr_t OFFSET_SO_SNDBUF = 0x52D969;  // Send buffer
    static constexpr uintptr_t OFFSET_SO_RCVBUF = 0x52DB5D;  // Receive buffer

    // Buffer sizes
    static constexpr uint32_t ORIGINAL_BUFFER_SIZE = 0x8000;     // 32 KB
    static constexpr uint32_t PATCHED_BUFFER_SIZE = 0x100000;    // 1 MB

    /**
     * Represents a patch location with validation
     */
    struct BufferPatch
    {
        uintptr_t offset;
        const char* name;
        uint8_t original_bytes[5];
        uint8_t patched_bytes[5];
        bool applied = false;

        BufferPatch(uintptr_t off, const char* n)
            : offset(off), name(n)
        {
            // Original: PUSH 0x8000 = 68 00 80 00 00
            original_bytes[0] = 0x68;
            original_bytes[1] = 0x00;
            original_bytes[2] = 0x80;
            original_bytes[3] = 0x00;
            original_bytes[4] = 0x00;

            // Patched: PUSH 0x100000 = 68 00 00 10 00
            patched_bytes[0] = 0x68;
            patched_bytes[1] = 0x00;
            patched_bytes[2] = 0x00;
            patched_bytes[3] = 0x10;
            patched_bytes[4] = 0x00;
        }
    };

    static BufferPatch patches[] = {
        BufferPatch(OFFSET_SO_SNDBUF, "SO_SNDBUF (Send Buffer)"),
        BufferPatch(OFFSET_SO_RCVBUF, "SO_RCVBUF (Receive Buffer)")
    };

    static const int PATCH_COUNT = sizeof(patches) / sizeof(patches[0]);

    void NetTune::Initialize()
    {
        uintptr_t gameBase = reinterpret_cast<uintptr_t>(GetModuleHandle(NULL));
        
        std::cout << "[NetTune] Initializing network tuning patches..." << std::endl;
        std::cout << "[NetTune] Game Base: 0x" << std::hex << gameBase << std::dec << std::endl;

        int successCount = 0;

        for (int i = 0; i < PATCH_COUNT; ++i)
        {
            BufferPatch& patch = patches[i];
            
            // Calculate absolute address
            uintptr_t patchAddr = gameBase + patch.offset;
            uint8_t* pAddr = reinterpret_cast<uint8_t*>(patchAddr);

            std::cout << "[NetTune] Attempting to patch " << patch.name << " at 0x" 
                      << std::hex << patch.offset << std::dec << "..." << std::endl;

            // Verify we're patching the right bytes
            bool matches = std::memcmp(pAddr, patch.original_bytes, 5) == 0;

            if (!matches)
            {
                std::cout << "[NetTune] ERROR: Expected bytes not found at offset 0x" 
                          << std::hex << patch.offset << std::dec << std::endl;
                std::cout << "[NetTune] Found: ";
                for (int j = 0; j < 5; ++j) {
                    std::cout << std::hex << (int)pAddr[j] << " ";
                }
                std::cout << std::dec << std::endl;
                continue;
            }

            // Apply patch with memory protection
            DWORD oldProtect = 0;
            if (!VirtualProtect(pAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                std::cout << "[NetTune] ERROR: VirtualProtect failed for " << patch.name << std::endl;
                continue;
            }

            // Copy patched bytes
            std::memcpy(pAddr, patch.patched_bytes, 5);

            // Restore protection
            DWORD dummy;
            if (!VirtualProtect(pAddr, 5, oldProtect, &dummy))
            {
                std::cout << "[NetTune] WARNING: Failed to restore memory protection" << std::endl;
            }

            patch.applied = true;
            successCount++;

            std::cout << "[NetTune] ✓ Successfully patched " << patch.name << std::endl;
            std::cout << "[NetTune]   Changed: 0x8000 (32 KB) → 0x100000 (1 MB)" << std::endl;
        }

        std::cout << "[NetTune] Initialization complete: " << successCount << "/" << PATCH_COUNT 
                  << " patches applied" << std::endl;

        if (successCount > 0)
        {
            std::cout << "[NetTune] Network stability improvements active" << std::endl;
        }
        else
        {
            std::cout << "[NetTune] WARNING: No patches could be applied" << std::endl;
        }
    }

    void NetTune::Shutdown()
    {
        std::cout << "[NetTune] Shutting down..." << std::endl;

        int revertCount = 0;
        uintptr_t gameBase = reinterpret_cast<uintptr_t>(GetModuleHandle(NULL));

        for (int i = 0; i < PATCH_COUNT; ++i)
        {
            BufferPatch& patch = patches[i];

            if (!patch.applied)
                continue;

            uintptr_t patchAddr = gameBase + patch.offset;
            uint8_t* pAddr = reinterpret_cast<uint8_t*>(patchAddr);

            // Verify current state
            if (std::memcmp(pAddr, patch.patched_bytes, 5) != 0)
            {
                std::cout << "[NetTune] WARNING: " << patch.name << " not in expected patched state" << std::endl;
                continue;
            }

            // Revert with memory protection
            DWORD oldProtect = 0;
            if (!VirtualProtect(pAddr, 5, PAGE_EXECUTE_READWRITE, &oldProtect))
            {
                std::cout << "[NetTune] ERROR: VirtualProtect failed during revert" << std::endl;
                continue;
            }

            std::memcpy(pAddr, patch.original_bytes, 5);

            DWORD dummy;
            VirtualProtect(pAddr, 5, oldProtect, &dummy);

            revertCount++;
            std::cout << "[NetTune] Reverted " << patch.name << std::endl;
        }

        std::cout << "[NetTune] Shutdown complete: " << revertCount << " patches reverted" << std::endl;
    }

    uintptr_t NetTune::FindPattern(uintptr_t start, uintptr_t end, const uint8_t* pattern, const char* mask)
    {
        // Simple pattern matcher for future use
        // This allows for flexible pattern matching if offsets change between versions
        
        size_t patternLen = std::strlen(mask);
        
        for (uintptr_t addr = start; addr < end - patternLen; ++addr)
        {
            uint8_t* p = reinterpret_cast<uint8_t*>(addr);
            bool found = true;

            for (size_t i = 0; i < patternLen; ++i)
            {
                if (mask[i] == 'x' && p[i] != pattern[i])
                {
                    found = false;
                    break;
                }
            }

            if (found)
                return addr;
        }

        return 0;
    }

    void NetTune::ApplyPatches(uintptr_t tableAddr, int patternType)
    {
        // Reserved for future use if we need pattern-based patching
        // across different game versions or DLL versions
        (void)tableAddr;
        (void)patternType;
    }
}
