#include "MapFix.h"
#include <iostream>

namespace MapSelectionFix
{
    void MapFix::Initialize()
    {
        m_handlerCookie = AddVectoredExceptionHandler(1, Handler);
        
        uintptr_t base = GetGameBase();
        
        // Use emplace_back to construct right in the vector as requested
        m_patches.reserve(4);
        m_patches.emplace_back(base + RVA_SET_SELECTED_INDEX);
        m_patches.emplace_back(base + RVA_CLEAR_LIST);
        m_patches.emplace_back(base + RVA_ADD_ENTRY);
        m_patches.emplace_back(base + RVA_UI_REFRESH);

        // Actually apply the patches
        for (auto& patch : m_patches) {
            patch.Reload();
        }
    }

    void MapFix::Shutdown()
    {
        if (m_handlerCookie) {
            RemoveVectoredExceptionHandler(m_handlerCookie);
            m_handlerCookie = nullptr;
        }

        // Vector clear will trigger destructors, which call RestorePatch()
        m_patches.clear();
    }

    LONG WINAPI MapFix::Handler(EXCEPTION_POINTERS* ExceptionInfo)
    {
        if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
        {
            uintptr_t base = GetGameBase();
            uintptr_t eip = ExceptionInfo->ContextRecord->Eip;
            uintptr_t rva = eip - base;

            // Handle known hooks
            if (rva == RVA_SET_SELECTED_INDEX || rva == RVA_CLEAR_LIST || 
                rva == RVA_ADD_ENTRY || rva == RVA_UI_REFRESH)
            {
                if (rva == RVA_SET_SELECTED_INDEX) {
                    // Capture selection logic here
                } else if (rva == RVA_CLEAR_LIST) {
                    m_isRefreshing = true;
                } else if (rva == RVA_ADD_ENTRY) {
                    // Filtering logic here:
                    // If we want to SKIP this function entirely:
                    // 1. Get return address: DWORD retAddr = *(DWORD*)ExceptionInfo->ContextRecord->Esp;
                    // 2. Adjust ESP: ExceptionInfo->ContextRecord->Esp += 4; (plus args if stdcall)
                    // 3. Set EIP: ExceptionInfo->ContextRecord->Eip = retAddr;
                    // 4. return EXCEPTION_CONTINUE_EXECUTION;
                } else if (rva == RVA_UI_REFRESH) {
                    m_isRefreshing = false;
                }

                // To resume, we must:
                // 1. Temporarily restore the original byte
                // 2. Set the trap flag to single-step
                // 3. Re-apply the INT3 in the next exception (SINGLE_STEP)
                for (auto& patch : m_patches) {
                    if (patch.GetAddress() == eip) {
                        patch.Restore();
                        ExceptionInfo->ContextRecord->EFlags |= 0x100; // Set Trap Flag (TF)
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                }
            }
        }
        else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
        {
            // Re-apply all patches that were temporarily restored
            for (auto& patch : m_patches) {
                patch.Reload();
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    bool MapFix::ShouldFilter(const char* mapName)
    {
        // Add filtering logic if needed
        return false;
    }
}
