@echo off
set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"

if not exist "%VCVARS%" (
    echo Error: vcvarsall.bat not found at "%VCVARS%"
    exit /b 1
)

call "%VCVARS%" x86

cl /LD /Fe:winmm.dll /Iinclude /Isrc src\dllmain.cpp src\MapFix.cpp src\LuaInterop.cpp src\NetTune.cpp src\SocketOptimizer.cpp src\Logger.cpp User32.lib Psapi.lib Ws2_32.lib /std:c++20 /O2 /MD /EHsc

if %ERRORLEVEL% NEQ 0 (
    echo Build failed!
    exit /b %ERRORLEVEL%
)

echo Build successful: winmm.dll
