import re

with open('system_winmm_exports.txt', 'r') as f:
    content = f.read()

# Pattern to find exports: ordinal hint RVA name
pattern = re.compile(r'^\s+(\d+)\s+[0-9A-F]+\s+[0-9A-F]+\s+([a-zA-Z0-9_]+)', re.MULTILINE)
matches = pattern.findall(content)

exports = []
for ordinal, name in matches:
    if name != '[NONAME]':
        exports.append((name, ordinal))

noname_pattern = re.compile(r'^\s+(\d+)\s+[0-9A-F]+\s+\[NONAME\]', re.MULTILINE)
noname_matches = noname_pattern.findall(content)

header = """#include <Windows.h>
#include "MapFix.h"

// Forwarding all winmm.dll exports to the system version.
// Using System32 path because for 32-bit processes it's automatically 
// redirected to SysWOW64 on 64-bit Windows.
"""

pragmas = []
for name, ordinal in exports:
    pragmas.append(f'#pragma comment(linker, "/export:{name}=C:\\\\Windows\\\\System32\\\\winmm.{name},@{ordinal}")')

for ordinal in noname_matches:
    pragmas.append(f'#pragma comment(linker, "/export:REAL_{ordinal}=C:\\\\Windows\\\\System32\\\\winmm.#{ordinal},@{ordinal},NONAME")')

footer = """
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        MapSelectionFix::MapFix::Initialize();
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        MapSelectionFix::MapFix::Shutdown();
    }
    return TRUE;
}
"""

with open('src/dllmain.cpp', 'w') as f:
    f.write(header)
    for p in pragmas:
        f.write(p + '\n')
    f.write(footer)

print(f"Generated src/dllmain.cpp with {len(pragmas)} exports.")
