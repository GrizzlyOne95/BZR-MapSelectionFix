#include "MapFix.h"
#include "Logger.h"
#include <iostream>

namespace MapSelectionFix
{
    namespace
    {
        constexpr uintptr_t kRvaSetSelectedIndex = 0x752834;
        constexpr uintptr_t kRvaClearList = 0x7a31d9;
        constexpr uintptr_t kRvaAddEntry = 0x7a35c0;
        constexpr uintptr_t kRvaUiRefresh = 0x752a82;

        const char* HookNameFromRva(uintptr_t rva)
        {
            if (rva == kRvaSetSelectedIndex) return "SetSelectedIndex";
            if (rva == kRvaClearList) return "ClearList";
            if (rva == kRvaAddEntry) return "AddEntry";
            if (rva == kRvaUiRefresh) return "UIRefresh";
            return "Unknown";
        }
    }

    void MapFix::Initialize()
    {
        Logger::Log("[MapFix] Initializing map selection hooks...");
        m_handlerCookie = AddVectoredExceptionHandler(1, Handler);
        Logger::LogFormat("[MapFix] VEH handler cookie: 0x%p", m_handlerCookie);
        
        uintptr_t base = GetGameBase();
        Logger::LogFormat("[MapFix] Game base: 0x%p", (void*)base);
        
        // Use emplace_back to construct right in the vector as requested
        m_patches.reserve(4);
        m_patches.emplace_back(base + RVA_SET_SELECTED_INDEX);
        m_patches.emplace_back(base + RVA_CLEAR_LIST);
        m_patches.emplace_back(base + RVA_ADD_ENTRY);
        m_patches.emplace_back(base + RVA_UI_REFRESH);

        // Actually apply the patches
        for (auto& patch : m_patches) {
            patch.Reload();
            uintptr_t rva = patch.GetAddress() - base;
            Logger::LogFormat("[MapFix] Hooked %s at RVA 0x%X (VA 0x%p)", HookNameFromRva(rva), (unsigned)rva, (void*)patch.GetAddress());
        }
        Logger::Log("[MapFix] Initialization complete");
    }

    void MapFix::Shutdown()
    {
        Logger::Log("[MapFix] Shutdown starting...");
        if (m_handlerCookie) {
            RemoveVectoredExceptionHandler(m_handlerCookie);
            Logger::Log("[MapFix] VEH handler removed");
            m_handlerCookie = nullptr;
        }

        // Vector clear will trigger destructors, which call RestorePatch()
        m_patches.clear();
        Logger::Log("[MapFix] Hooks cleared");
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
                Logger::LogFormat("[MapFix] Breakpoint hit at %s (RVA 0x%X)", HookNameFromRva(rva), (unsigned)rva);
                if (rva == RVA_SET_SELECTED_INDEX) {
                    // Capture selection logic
                    m_pListObject = (void*)ExceptionInfo->ContextRecord->Ecx;
                    m_savedIndex = *(int*)(ExceptionInfo->ContextRecord->Esp + 4);
                    
                    // Capture scroll offset (topIndex is at +0x44 in BZR ListBox)
                    if (m_pListObject) {
                        m_savedScrollOffset = *(int*)((uintptr_t)m_pListObject + 0x44);
                    }
                    Logger::LogFormat("[MapFix] Captured selection: list=0x%p index=%d topIndex=%d", m_pListObject, m_savedIndex, m_savedScrollOffset);
                } else if (rva == RVA_CLEAR_LIST) {
                    // Also capture scroll offset here in case it changed without re-selection
                    if (ExceptionInfo->ContextRecord->Ecx) {
                        m_pListObject = (void*)ExceptionInfo->ContextRecord->Ecx;
                        m_savedScrollOffset = *(int*)((uintptr_t)m_pListObject + 0x44);
                    }
                    m_isRefreshing = true;
                    Logger::LogFormat("[MapFix] Refresh start: list=0x%p topIndex=%d", m_pListObject, m_savedScrollOffset);
                } else if (rva == RVA_ADD_ENTRY) {
                    // (Optional) Filtering logic here
                    Logger::Log("[MapFix] AddEntry hit during refresh");
                } else if (rva == RVA_UI_REFRESH) {
                    if (m_isRefreshing && m_pListObject && m_savedIndex != -1) {
                        m_isRefreshing = false;
                        
                        // Restore selection by calling the game's function
                        // We must temporarily restore the patch to avoid recursion
                        typedef void (__thiscall* tSetSelectedIndex)(void*, int);
                        tSetSelectedIndex fn = (tSetSelectedIndex)(base + RVA_SET_SELECTED_INDEX);
                        
                        // Find the patch and temporarily restore it
                        for (auto& patch : m_patches) {
                            if (patch.GetAddress() == (base + RVA_SET_SELECTED_INDEX)) {
                                patch.Restore();
                                fn(m_pListObject, m_savedIndex);
                                patch.Reload();
                                Logger::LogFormat("[MapFix] Restored selection index=%d via SetSelectedIndex", m_savedIndex);
                                break;
                            }
                        }

                        // Restore scroll offset
                        if (m_savedScrollOffset != -1) {
                            *(int*)((uintptr_t)m_pListObject + 0x44) = m_savedScrollOffset;
                            Logger::LogFormat("[MapFix] Restored scroll offset topIndex=%d", m_savedScrollOffset);
                        }
                    } else {
                        Logger::Log("[MapFix] UIRefresh hit without saved state (nothing to restore)");
                    }
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
                        Logger::LogFormat("[MapFix] Single-step armed for %s", HookNameFromRva(rva));
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
