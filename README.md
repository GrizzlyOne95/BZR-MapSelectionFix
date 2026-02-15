# BZR Map Selection Fix

A standalone `winmm.dll` proxy for Battlezone 98 Redux that implements the "Map Selection Preservation Fix". This fix ensures that selected maps in the Shell UI (Multiplayer/Instant Action) are not lost or reset during lobby refreshes or workshop updates.

## 🔍 Findings & Architecture

### 1. Winmm Proxy
The game executable (`battlezone98redux.exe`) and its dependencies (like `steamclient.dll` and RivaTuner) rely on several multimedia functions. To ensure 100% compatibility and avoid "Entry Point Not Found" errors, this proxy implements a **Full Forwarding** mechanism:
- **193 Exports**: Every function in the system `winmm.dll` is exported.
- **Transparent Forwarding**: Calls are forwarded to `C:\Windows\System32\winmm.dll` using `#pragma comment(linker, ...)`.
- **32-bit Architecture**: Built specifically for x86 to match the game's architecture.

### 2. Map Selection Fix
The core logic replicates the fix found in the Battlezone Community Patch (`_bzcp.dll`):
- **Hooking**: Uses a Vectored Exception Handler (VEH) with `INT3` patches to intercept game functions without traditional detour overhead.
- **Key Logic**:
  - Captures the selected map index/name before a list refresh.
  - Intercepts map population to apply filtering.
  - Restores the selection state once the UI refresh is complete.

## 🛠️ Building

The project uses the MSVC compiler (Visual Studio 2022).

1. Open a **Developer Command Prompt for VS 2022**.
2. Run `build.bat`:
   ```cmd
   build.bat
   ```
   This will generate `winmm.dll`.

## 🚀 Installation

1. Copy the generated `winmm.dll` to your Battlezone 98 Redux installation folder (e.g., `C:\Program Files (x86)\Steam\steamapps\common\Battlezone 98 Redux\`).
2. Launch the game via Steam.

## 📂 Project Structure
- `src/`: Source code (`dllmain.cpp`, `MapFix.cpp`).
- `include/`: Header files ported from ExtraUtilities.
- `build.bat`: Build script.
- `gen_proxy.py`: Python script to generate the 193-export `dllmain.cpp`.
