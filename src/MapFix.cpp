#include "MapFix.h"
#include "Logger.h"
#include <iostream>
#include <algorithm>
#include <cctype>

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

        // Additional RVAs observed in the closed-source Community Patch helper DLL.
        // These are discovery probes for manual lobby refresh code paths.
        constexpr uintptr_t kExtraDiscoveryRvas[] = {
            0x79b86d, 0x5d4260, 0x799279, 0x79928c,
            0x7cafa0, 0x7cb412, 0x799116, 0x79916b,
            0x799377, 0x79937e, 0x7c9de0, 0x89e8c8,
            0x7cb500, 0x7cb540, 0x7998ab, 0x7998b4
        };

        bool IsExtraDiscoveryRva(uintptr_t rva)
        {
            for (uintptr_t probe : kExtraDiscoveryRvas)
            {
                if (rva == probe)
                    return true;
            }
            return false;
        }

        bool EqualsIgnoreCase(const std::string& a, const std::string& b)
        {
            if (a.size() != b.size())
                return false;
            for (size_t i = 0; i < a.size(); ++i)
            {
                if (std::tolower((unsigned char)a[i]) != std::tolower((unsigned char)b[i]))
                    return false;
            }
            return true;
        }

        const char* HookNameFromRva(uintptr_t rva)
        {
            if (rva == kRvaSetSelectedIndex) return "SetSelectedIndex";
            if (rva == kRvaClearList) return "ClearList";
            if (rva == kRvaAddEntry) return "AddEntry";
            if (rva == kRvaUiRefresh) return "UIRefresh";
            if (rva == kRvaUiRefreshAlt) return "UIRefreshAlt";
            if (rva == kRvaUiDiscovery1) return "UIDiscovery1";
            if (rva == kRvaUiDiscovery2) return "UIDiscovery2";
            if (IsExtraDiscoveryRva(rva)) return "UIExtraDiscovery";
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

        bool SafeReadCString(const char* address, std::string& out, size_t max_len = 128)
        {
            out.clear();
            if (!address || max_len == 0)
                return false;

            __try
            {
                for (size_t i = 0; i < max_len; ++i)
                {
                    char c = address[i];
                    if (c == '\0')
                    {
                        if (!out.empty())
                            return true;
                        return false;
                    }
                    if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7E)
                        return false;
                    out.push_back(c);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                return false;
            }

            return false;
        }

        bool LooksLikeMapKey(const std::string& s)
        {
            if (s.length() < 3 || s.length() > 64)
                return false;

            bool has_alpha = false;
            for (char c : s)
            {
                if (std::isalpha((unsigned char)c))
                    has_alpha = true;
                if (!(std::isalnum((unsigned char)c) || c == '_' || c == '-' || c == '.'))
                    return false;
            }

            return has_alpha;
        }

        std::string ExtractCandidateMapKeyFromContext(CONTEXT* ctx)
        {
            if (!ctx)
                return {};

            const uintptr_t candidates[] = {
                (uintptr_t)ctx->Eax,
                (uintptr_t)ctx->Ebx,
                (uintptr_t)ctx->Ecx,
                (uintptr_t)ctx->Edx,
                (uintptr_t)ctx->Esi,
                (uintptr_t)ctx->Edi
            };

            for (uintptr_t ptr : candidates)
            {
                std::string s;
                if (SafeReadCString((const char*)ptr, s) && LooksLikeMapKey(s))
                    return s;
            }

            auto TryReadStackPointer = [](uintptr_t address, uintptr_t* out) -> bool
            {
                if (!out)
                    return false;
                __try
                {
                    *out = *(uintptr_t*)address;
                    return true;
                }
                __except (EXCEPTION_EXECUTE_HANDLER)
                {
                    return false;
                }
            };

            uintptr_t esp = ctx->Esp;
            for (int i = 1; i <= 6; ++i)
            {
                uintptr_t ptr = 0;
                if (!TryReadStackPointer(esp + i * 4, &ptr))
                    continue;

                std::string s;
                if (SafeReadCString((const char*)ptr, s) && LooksLikeMapKey(s))
                    return s;
            }

            return {};
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
                    rva == kRvaUiDiscovery2 ||
                    IsExtraDiscoveryRva(rva));
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
        m_patches.reserve(7 + _countof(kExtraDiscoveryRvas));
        m_patches.emplace_back(base + RVA_SET_SELECTED_INDEX);
        m_patches.emplace_back(base + RVA_CLEAR_LIST);
        m_patches.emplace_back(base + RVA_ADD_ENTRY);
        m_patches.emplace_back(base + RVA_UI_REFRESH);
        m_patches.emplace_back(base + RVA_UI_REFRESH_ALT);
        m_patches.emplace_back(base + RVA_UI_DISCOVERY_1);
        m_patches.emplace_back(base + RVA_UI_DISCOVERY_2);
        for (uintptr_t probe : kExtraDiscoveryRvas)
        {
            m_patches.emplace_back(base + probe);
        }

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
                rva == RVA_UI_DISCOVERY_2 || IsExtraDiscoveryRva(rva))
            {
                ExceptionInfo->ContextRecord->Eip = hit_address;
                Logger::LogFormat("[MapFix] Breakpoint hit at %s (RVA 0x%X)", HookNameFromRva(rva), (unsigned)rva);
                if (rva == RVA_SET_SELECTED_INDEX) {
                    // Capture selection logic
                    m_pListObject = (void*)ExceptionInfo->ContextRecord->Ecx;
                    m_savedIndex = *(int*)(ExceptionInfo->ContextRecord->Esp + 4);
                    m_hasSelectionSnapshot = (m_savedIndex >= 0);
                    if (m_savedIndex >= 0 && m_savedIndex < (int)m_liveEntryKeys.size())
                    {
                        m_lastSelectedMap = m_liveEntryKeys[m_savedIndex];
                        Logger::LogFormat("[MapFix] Bound selected index %d to key '%s'", m_savedIndex, m_lastSelectedMap.c_str());
                    }
                    
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
                    m_refreshEntryKeys.clear();
                    Logger::LogFormat("[MapFix] Refresh start: list=0x%p topIndex=%d", m_pListObject, m_savedScrollOffset);
                } else if (rva == RVA_ADD_ENTRY) {
                    if (m_isRefreshing)
                        ++m_pendingEntryCount;

                    std::string key = ExtractCandidateMapKeyFromContext(ExceptionInfo->ContextRecord);
                    
                    if (m_isRefreshing)
                        m_refreshEntryKeys.push_back(key);
                    else if (m_liveEntryKeys.size() < 4096)
                        m_liveEntryKeys.push_back(key);

                    Logger::LogFormat("[MapFix] AddEntry hit during refresh (count=%d)", m_pendingEntryCount);
                } else if (rva == RVA_UI_REFRESH || rva == RVA_UI_REFRESH_ALT) {
                    if (m_isRefreshing && m_pListObject) {
                        m_isRefreshing = false;

                        int restoreIndex = -1;
                        if (!m_lastSelectedMap.empty() && !m_refreshEntryKeys.empty())
                        {
                            for (int i = 0; i < (int)m_refreshEntryKeys.size(); ++i)
                            {
                                if (EqualsIgnoreCase(m_refreshEntryKeys[i], m_lastSelectedMap))
                                {
                                    restoreIndex = i;
                                    Logger::LogFormat("[MapFix] Matched selected key '%s' to new index %d", m_lastSelectedMap.c_str(), restoreIndex);
                                    break;
                                }
                            }
                        }

                        if (restoreIndex == -1 && m_hasSelectionSnapshot && m_savedIndex >= 0)
                        {
                            const int maxIndex = (m_pendingEntryCount > 0) ? (m_pendingEntryCount - 1) : m_savedIndex;
                            restoreIndex = std::clamp(m_savedIndex, 0, maxIndex);
                        }

                        // Restore selection if we resolved a target index.
                        if (restoreIndex >= 0) {

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

                        if (!m_refreshEntryKeys.empty())
                        {
                            m_liveEntryKeys = m_refreshEntryKeys;
                            if (m_liveEntryKeys.size() > 4096)
                                m_liveEntryKeys.resize(4096);
                        }
                    } else {
                        Logger::Log("[MapFix] UIRefresh hit without saved state (nothing to restore)");
                    }
                    m_isRefreshing = false;
                    m_pendingEntryCount = 0;
                    m_refreshEntryKeys.clear();
                } else {
                    // Discovery probes for manual-refresh code paths.
                    Logger::LogFormat("[MapFix] Discovery probe hit at %s (RVA 0x%X)", HookNameFromRva(rva), (unsigned)rva);
                    if (ExceptionInfo->ContextRecord->Ecx)
                    {
                        int topIndex = -1;
                        if (SafeReadInt((void*)((uintptr_t)ExceptionInfo->ContextRecord->Ecx + 0x44), &topIndex))
                        {
                            Logger::LogFormat("[MapFix] Discovery ECX=0x%p topIndex=%d EAX=0x%p EDX=0x%p",
                                (void*)ExceptionInfo->ContextRecord->Ecx,
                                topIndex,
                                (void*)ExceptionInfo->ContextRecord->Eax,
                                (void*)ExceptionInfo->ContextRecord->Edx);
                        }
                    }
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
            ExceptionInfo->ContextRecord->EFlags &= ~0x100; // Clear Trap Flag (TF)
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
