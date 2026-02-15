#include "MapFix.h"
#include <iostream>

namespace MapSelectionFix
{
    static std::vector<INT3Patch*> m_patches;

    void MapFix::Initialize()
    {
        m_handlerCookie = AddVectoredExceptionHandler(1, Handler);
        
        uintptr_t base = GetGameBase();
        m_patches.push_back(new INT3Patch(base + RVA_SET_SELECTED_INDEX));
        m_patches.push_back(new INT3Patch(base + RVA_CLEAR_LIST));
        m_patches.push_back(new INT3Patch(base + RVA_ADD_ENTRY));
        m_patches.push_back(new INT3Patch(base + RVA_UI_REFRESH));
    }

    void MapFix::Shutdown()
    {
        if (m_handlerCookie) {
            RemoveVectoredExceptionHandler(m_handlerCookie);
            m_handlerCookie = nullptr;
        }
        for (auto patch : m_patches) {
            delete patch;
        }
        m_patches.clear();
    }

    bool MapFix::ShouldFilter(const char* mapName)
    {
        if (!mapName) return false;
        
        // Example filtering logic based on _bzcp.dll (mimicking its behavior)
        // In a real scenario, this would check against known problematic maps
        // or based on selected filter in the UI.
        std::string name = mapName;
        if (name.find("Stock") != std::string::npos) return false;
        if (name.find("Workshop") != std::string::npos) return false;
        
        return false; // Default to no filter for now
    }

    LONG WINAPI MapFix::Handler(EXCEPTION_POINTERS* ExceptionInfo)
    {
        if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
        {
            uintptr_t ip = ExceptionInfo->ContextRecord->Eip;
            uintptr_t base = GetGameBase();

            if (ip == base + RVA_SET_SELECTED_INDEX)
            {
                // Capture current selection index/name
                // EDX usually contains the index or name pointer in BZR
                // m_lastSelectedMap = (char*)ExceptionInfo->ContextRecord->Edx;
            }
            else if (ip == base + RVA_CLEAR_LIST)
            {
                m_isRefreshing = true;
            }
            else if (ip == base + RVA_ADD_ENTRY)
            {
                // Intercept and filter
                const char* name = (const char*)ExceptionInfo->ContextRecord->Eax;
                if (ShouldFilter(name)) {
                    // Skip the addition by jumping over the call
                    // This requires careful adjustment of EIP and stack
                    // ExceptionInfo->ContextRecord->Eip += 5; // Skip call
                    // return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            else if (ip == base + RVA_UI_REFRESH)
            {
                if (m_isRefreshing) {
                    m_isRefreshing = false;
                    // Restore selection
                }
            }

            // Step over INT3
            ExceptionInfo->ContextRecord->Eip++; 
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
}
