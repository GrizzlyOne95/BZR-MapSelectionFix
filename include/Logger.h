#pragma once

#include <fstream>
#include <sstream>
#include <Windows.h>

namespace MapSelectionFix
{
    /**
     * Simple file logger for DLL diagnostics
     * Writes to MapSelectionFix_Log.txt in the game directory
     */
    class Logger
    {
    public:
        static void Initialize()
        {
            // Get game directory
            char game_dir[MAX_PATH];
            GetCurrentDirectoryA(MAX_PATH, game_dir);

            // Build log file path
            sprintf_s(log_path, sizeof(log_path), "%s\\MapSelectionFix_Log.txt", game_dir);

            // Open file for appending
            std::ofstream log(log_path, std::ios::app);
            if (log.is_open())
            {
                log << "\n=== Log Session Started ===\n";
                log.close();
            }
        }

        static void Log(const char* message)
        {
            std::ofstream log(log_path, std::ios::app);
            if (log.is_open())
            {
                // Add timestamp
                SYSTEMTIME st;
                GetLocalTime(&st);
                
                char timestamp[64];
                sprintf_s(timestamp, sizeof(timestamp), "[%02d:%02d:%02d.%03d]",
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

                log << timestamp << " " << message << "\n";
                log.flush();
                log.close();
            }

            // Also output to console if available
            OutputDebugStringA(message);
            OutputDebugStringA("\n");
        }

        static void LogFormat(const char* format, ...)
        {
            char buffer[1024];
            va_list args;
            va_start(args, format);
            vsprintf_s(buffer, sizeof(buffer), format, args);
            va_end(args);
            Log(buffer);
        }

    private:
        static char log_path[MAX_PATH];
    };
}
