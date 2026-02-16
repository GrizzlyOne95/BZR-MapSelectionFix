#include "MapFix.h"
#include "Logger.h"
#include <iostream>
#include <algorithm>

namespace MapSelectionFix
{
    namespace
    {
        constexpr uintptr_t kRvaSetSelectedIndex = 0x752834;
        constexpr uintptr_t kRvaClearList = 0x7a31d9;
        constexpr uintptr_t kRvaAddEntry = 0x7a35c0;
        constexpr uintptr_t kRvaUiRefresh = 0x752a82;
        constexpr uintptr_t kRvaUiRefreshAlt = 0x752d00;
        constexpr uintptr_t kRvaUiDiscovery1 = 0x7680d6;
        constexpr uintptr_t kRvaUiDiscovery2 = 0x76810e;

        const char* HookNameFromRva(uintptr_t rva)
        {
            if (rva == kRvaSetSelectedIndex) return "SetSelectedIndex";
            if (rva == kRvaClearList) return "ClearList";
            if (rva == kRvaAddEntry) return "AddEntry";
            if (rva == kRvaUiRefresh) return "UIRefresh";
            if (rva == kRvaUiRefreshAlt) return "UIRefreshAlt";
            if (rva == kRvaUiDiscovery1) return "UIDiscovery1";
            if (rva == kRvaUiDiscovery2) return "UIDiscovery2";
            return "Unknown";
        }

        bool SafeReadInt(const void* address, int* out)
        {
            if (!address || !out)
                return false;

            __try
            {
                *out = *(const int*)address;
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        bool SafeWriteInt(void* address, int value)
        {
            if (!address)
                return false;

            __try
            {
                *(int*)address = value;
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }
        }

        bool IsHookAddress(uintptr_t address)
        {
            uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandle(NULL));
            uintptr_t rva = address - base;
            return (rva == kRvaSetSelectedIndex ||
                    rva == kRvaClearList ||
                    rva == kRvaAddEntry ||
                    rva == kRvaUiRefresh ||
                    rva == kRvaUiRefreshAlt ||
                    rva == kRvaUiDiscovery1 ||
                    rva == kRvaUiDiscovery2);
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
        m_patches.reserve(7);
        m_patches.emplace_back(base + RVA_SET_SELECTED_INDEX);
        m_patches.emplace_back(base + RVA_CLEAR_LIST);
        m_patches.emplace_back(base + RVA_ADD_ENTRY);
        m_patches.emplace_back(base + RVA_UI_REFRESH);
        m_patches.emplace_back(base + RVA_UI_REFRESH_ALT);
        m_patches.emplace_back(base + RVA_UI_DISCOVERY_1);
        m_patches.emplace_back(base + RVA_UI_DISCOVERY_2);

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
            uintptr_t trap_eip = ExceptionInfo->ContextRecord->Eip;
            uintptr_t hit_address = trap_eip;

            // INT3 commonly reports EIP at the byte *after* 0xCC.
            // Normalize to the actual trap address if needed.
            if (!IsHookAddress(hit_address) && hit_address > 0)
            {
                uintptr_t candidate = hit_address - 1;
                if (IsHookAddress(candidate))
                    hit_address = candidate;
            }

            uintptr_t rva = hit_address - base;

            // Handle known hooks
            if (rva == RVA_SET_SELECTED_INDEX || rva == RVA_CLEAR_LIST || 
                rva == RVA_ADD_ENTRY || rva == RVA_UI_REFRESH ||
                rva == RVA_UI_REFRESH_ALT || rva == RVA_UI_DISCOVERY_1 ||
                rva == RVA_UI_DISCOVERY_2)
            {
                ExceptionInfo->ContextRecord->Eip = hit_address;
                Logger::LogFormat("[MapFix] Breakpoint hit at %s (RVA 0x%X)", HookNameFromRva(rva), (unsigned)rva);
                if (rva == RVA_SET_SELECTED_INDEX) {
                    // Capture selection logic
                    m_pListObject = (void*)ExceptionInfo->ContextRecord->Ecx;
                    m_savedIndex = *(int*)(ExceptionInfo->ContextRecord->Esp + 4);
                    m_hasSelectionSnapshot = (m_savedIndex >= 0);
                    
                    // Capture scroll offset (topIndex is at +0x44 in BZR ListBox)
                    if (m_pListObject) {
                        int topIndex = -1;
                        if (SafeReadInt((void*)((uintptr_t)m_pListObject + 0x44), &topIndex))
                            m_savedScrollOffset = topIndex;
                    }
                    Logger::LogFormat("[MapFix] Captured selection: list=0x%p index=%d topIndex=%d", m_pListObject, m_savedIndex, m_savedScrollOffset);
                } else if (rva == RVA_CLEAR_LIST) {
                    // Also capture scroll offset here in case it changed without re-selection
                    if (ExceptionInfo->ContextRecord->Ecx) {
                        m_pListObject = (void*)ExceptionInfo->ContextRecord->Ecx;
                        int topIndex = -1;
                        if (SafeReadInt((void*)((uintptr_t)m_pListObject + 0x44), &topIndex))
                            m_savedScrollOffset = topIndex;
                    }
                    m_isRefreshing = true;
                    m_pendingEntryCount = 0;
                    Logger::LogFormat("[MapFix] Refresh start: list=0x%p topIndex=%d", m_pListObject, m_savedScrollOffset);
                } else if (rva == RVA_ADD_ENTRY) {
                    if (m_isRefreshing)
                        ++m_pendingEntryCount;
                    Logger::LogFormat("[MapFix] AddEntry hit during refresh (count=%d)", m_pendingEntryCount);
                } else if (rva == RVA_UI_REFRESH || rva == RVA_UI_REFRESH_ALT) {
                    if (m_isRefreshing && m_pListObject) {
                        m_isRefreshing = false;

                        // Restore selection if we have a valid snapshot.
                        if (m_hasSelectionSnapshot && m_savedIndex >= 0) {
                            const int maxIndex = (m_pendingEntryCount > 0) ? (m_pendingEntryCount - 1) : m_savedIndex;
                            const int restoreIndex = std::clamp(m_savedIndex, 0, maxIndex);

                            typedef void (__thiscall* tSetSelectedIndex)(void*, int);
                            tSetSelectedIndex fn = (tSetSelectedIndex)(base + RVA_SET_SELECTED_INDEX);

                            for (auto& patch : m_patches) {
                                if (patch.GetAddress() == (base + RVA_SET_SELECTED_INDEX)) {
                                    patch.Restore();
                                    fn(m_pListObject, restoreIndex);
                                    patch.Reload();
                                    Logger::LogFormat("[MapFix] Restored selection index=%d (saved=%d, entries=%d)", restoreIndex, m_savedIndex, m_pendingEntryCount);
                                    break;
                                }
                            }
                        } else {
                            Logger::Log("[MapFix] No selection snapshot available during UIRefresh; restoring scroll only");
                        }

                        // Always attempt to restore scroll even when selection snapshot is missing.
                        if (m_savedScrollOffset != -1) {
                            const int restoreTopIndex = (m_savedScrollOffset < 0) ? 0 : m_savedScrollOffset;
                            if (SafeWriteInt((void*)((uintptr_t)m_pListObject + 0x44), restoreTopIndex))
                                Logger::LogFormat("[MapFix] Restored scroll offset topIndex=%d", restoreTopIndex);
                            else
                                Logger::Log("[MapFix] Failed to restore scroll offset safely (pointer invalid)");
                        }
                    } else {
                        Logger::Log("[MapFix] UIRefresh hit without saved state (nothing to restore)");
                    }
                    m_isRefreshing = false;
                    m_pendingEntryCount = 0;
                } else {
                    // Discovery probes for manual-refresh code paths.
                    Logger::LogFormat("[MapFix] Discovery probe hit at %s (RVA 0x%X)", HookNameFromRva(rva), (unsigned)rva);
                }

                // To resume, we must:
                // 1. Temporarily restore the original byte
                // 2. Set the trap flag to single-step
                // 3. Re-apply the INT3 in the next exception (SINGLE_STEP)
                for (auto& patch : m_patches) {
                    if (patch.GetAddress() == hit_address) {
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
