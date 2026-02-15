# BZR Map Selection Fix

A standalone `winmm.dll` proxy for Battlezone 98 Redux (v2.0.188+) that implements the "Map Selection Preservation Fix". This project provides an open-source alternative to the legacy fixes, ensuring selected maps in the Shell UI remain stable during lobby refreshes.

## 🔍 Technical Deep Dive

### 1. Winmm Forwarding Proxy
To achieve seamless injection without disrupting the game or its dependencies (Steam, RivaTuner, etc.), the DLL implements a **Full Forwarding Proxy**.

- **Implementation**: Instead of manual `GetProcAddress` wrappers, we use MSVC Linker pragmas for transparent redirection.
- **Export Count**: 193 functions (matching the standard Windows 10/11 `winmm.dll` exports).
- **Redirection Target**: `C:\Windows\System32\winmm.dll` (which is redirected to `SysWOW64` automatically for 32-bit processes).
- **Syntax**: 
  ```cpp
  #pragma comment(linker, "/export:PlaySoundA=C:\\Windows\\System32\\winmm.PlaySoundA,@12")
  ```
- **Ordinal Support**: Includes the critical anonymous export **Ordinal 2** (`#2`), often used by system modules for internal messaging.

### 2. Hooking Mechanism (VEH + INT3)
The project uses a **Vectored Exception Handler (VEH)** combined with **INT3 (0xCC)** breakpoints. This approach is preferred over IAT or Inline hooking (Detours) because:
1. It has zero impact on the code's control flow visibility.
2. It avoids issues with "hotpatching" or page protection on highly sensitive engine code.
3. The footprint is a single byte (`0xCC`) per hook.

#### Handler Logic:
When an `EXCEPTION_BREAKPOINT` is triggered:
1. The handler checks the `EIP` against a list of registered RVAs.
2. If a match is found, it executes the custom logic (e.g., capturing a registers or state).
3. It increments `EIP` to "skip" the original instruction's first byte (which we replaced with `0xCC`) and returns `EXCEPTION_CONTINUE_EXECUTION`.

### 3. Target Game RVAs (v2.0.188)
The following RVAs in `battlezone98redux.exe` are the primary targets for the fix:

| RVA | Name | Description |
|---|---|---|
| `0x752834` | `SetSelectedMapIndex` | Triggered when a map is selected in the UI. We use this to capture the current selection. |
| `0x7a31d9` | `ClearList` | Triggered when the lobby or map list is being wiped for a refresh. |
| `0x7a35c0` | `AddEntry` | The internal call that adds a map to the UI list. Intercepted for filtering. |
| `0x752a82` | `UIRefresh` | Callback triggered when the UI repopulation is complete. Used to restore the captured selection. |

## 🛠️ Build & Architecture

- **Language**: C++20
- **Compiler**: MSVC (Visual Studio 2022)
- **Architecture**: x86 (32-bit)
- **Runtime**: `/MD` (Multi-threaded DLL)

### Project Structure:
- `src/dllmain.cpp`: Generated file containing all 193 forwarding pragmas and `DllMain`.
- `src/MapFix.cpp`: Core VEH handler and state-preservation logic.
- `include/`: Minimal subset of the `ExtraUtilities` infrastructure (BasicPatch, Scanner).
- `gen_proxy.py`: A utility script that parses the system `winmm.dll` and generates the `dllmain.cpp` pragmas.

## 📂 Installation
1. Compile using `build.bat`.
2. Place the resulting `winmm.dll` in the game's root directory.
3. The fix will automatically initialize when the game loads.
