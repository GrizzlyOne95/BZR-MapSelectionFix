#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <map>

#include "BasicPatch.h"

namespace MapSelectionFix
{
    class INT3Patch : public ExtraUtilities::BasicPatch
    {
    public:
        INT3Patch(uintptr_t address) : BasicPatch(address, 1, ExtraUtilities::BasicPatch::Status::INACTIVE) {}
        
    protected:
        void DoPatch() override
        {
            uint8_t* p_address = reinterpret_cast<uint8_t*>(m_address);
            VirtualProtect(p_address, 1, PAGE_EXECUTE_READWRITE, &m_oldProtect);
            *p_address = 0xCC; // INT3
            VirtualProtect(p_address, 1, m_oldProtect, &dummyProtect);
            m_status = Status::ACTIVE;
        }
    };

    class MapFix
    {
    public:
        static void Initialize();
        static void Shutdown();

    private:
        static LONG WINAPI Handler(EXCEPTION_POINTERS* ExceptionInfo);
        
        static inline PVOID m_handlerCookie = nullptr;
        
        // RVAs for the hooks
        static constexpr uintptr_t RVA_SET_SELECTED_INDEX = 0x752834;
        static constexpr uintptr_t RVA_CLEAR_LIST         = 0x7a31d9;
        static constexpr uintptr_t RVA_ADD_ENTRY          = 0x7a35c0;
        static constexpr uintptr_t RVA_UI_REFRESH         = 0x752a82;

        static bool ShouldFilter(const char* mapName);
        
        static inline std::string m_lastSelectedMap;
        static inline std::vector<INT3Patch> m_patches;
        static inline bool m_isRefreshing = false;
        static inline void* m_pListObject = nullptr;
        static inline int m_savedIndex = -1;
        static inline int m_savedScrollOffset = -1;
        
        // Helper to get game base
        static uintptr_t GetGameBase() {
            static uintptr_t base = reinterpret_cast<uintptr_t>(GetModuleHandle(NULL));
            return base;
        }
    };
}
