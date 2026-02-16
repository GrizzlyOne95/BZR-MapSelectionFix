#pragma once

#include <Windows.h>
#include <cstdint>
#include <cstring>

namespace MapSelectionFix
{
    /**
     * Network Buffer Diagnostic Module
     * 
     * Used to troubleshoot why network buffer patching isn't working.
     * Logs memory states and pattern matches to help identify the actual
     * socket buffer initialization code.
     */
    class NetDiagnostics
    {
    public:
        /**
         * Scan for socket buffer patterns in memory
         * Looks for PUSH 0x8000 (32KB) patterns that could be socket buffer sizes
         */
        static void ScanForSocketBufferPatterns();
        
        /**
         * Dump memory around a specific offset
         */
        static void DumpMemoryRegion(uintptr_t address, size_t size, const char* label);
        
        /**
         * Verify if the commonly-known offsets contain what we expect
         */
        static void VerifyKnownOffsets();
        
        /**
         * Find ALL occurrences of "PUSH 0x8000" in the executable
         * to identify different game versions or variants
         */
        static void FindAllBufferConstants();
    };
}
