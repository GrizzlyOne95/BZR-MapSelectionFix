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

            if (rva == RVA_SET_SELECTED_INDEX)
            {
                // Capture the map name/index logic here
                // For now just logging the hit
                ExceptionInfo->ContextRecord->Eip++; // Skip INT3
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else if (rva == RVA_CLEAR_LIST)
            {
                m_isRefreshing = true;
                ExceptionInfo->ContextRecord->Eip++;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else if (rva == RVA_ADD_ENTRY)
            {
                // Filtering logic here
                ExceptionInfo->ContextRecord->Eip++;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            else if (rva == RVA_UI_REFRESH)
            {
                m_isRefreshing = false;
                // Restore selection logic here
                ExceptionInfo->ContextRecord->Eip++;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    bool MapFix::ShouldFilter(const char* mapName)
    {
        // Add filtering logic if needed
        return false;
    }
}
