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
The project uses a **Vectored Exception Handler (VEH)** combined with **INT3 (0xCC)** breakpoints. 

#### How it works:
1. **The Trap**: We replace the first byte of target instructions in the game's executable memory with the `0xCC` opcode. This is the x86 instruction for a Hardcoded Breakpoint.
2. **The Exception**: When the CPU hits this byte, it halts execution and triggers a `STATUS_BREAKPOINT` exception.
3. **The Interception**: Since we registered a Vectored Exception Handler via `AddVectoredExceptionHandler(1, Handler)`, Windows gives our DLL the first opportunity to handle this exception.
4. **State Access**: Our `Handler` function receives an `EXCEPTION_POINTERS` structure containing the full CPU `CONTEXT` (all registers: `EAX`, `EBX`, `ECX`, `EDX`, `ESI`, `EDI`, `EBP`, `ESP`, and `EIP`).
5. **Instruction Resumption (Single-Stepping)**: To let the game continue without crashing, we implement a robust two-stage process:
   - **Stage 1 (Breakpoint)**: We temporarily restore the original byte at the current `EIP` and set the **Trap Flag (TF)** in `EFlags`.
   - **Stage 2 (Single Step)**: The CPU executes the original instruction and then immediately triggers a `STATUS_SINGLE_STEP` exception. Our handler intercepts this, re-applies the `0xCC` trap, and continues.
   - This ensures the hook is permanent but the game code executes correctly every time.
6. **Filtering / Skipping**: If we want to skip a function call entirely (as seen in the commented-out `AddEntry` logic), we modify `Context->Eip` to the return address and adjust `Context->Esp` to clean up the stack, effectively "jumping back" before the function even starts.

#### Advantages for C++ Modding:
- **Zero-Footprint**: Unlike standard "Detours" which require a 5-byte `JMP` (often overwriting multiple instructions), `INT3` only needs **1 byte**. This makes it safe to hook even the smallest functions.
- **Stealth**: Many integrity checks look for `JMP` or `CALL` patches. A single `0xCC` is much more subtle and is often ignored as a "debug leftover".
- **Context-Rich**: You get a snapshot of every register at the exact moment of the hook.

#### Coexistence & Safety:
The DLL registers its handler at the front of the **Vectored Exception Chain** (`FirstHandler = 1`). 
- **Ownership**: The handler only returns `CONTINUE_EXECUTION` for exceptions it explicitly owns (matching its RVA list).
- **Transparency**: For any other exception (e.g., engine crashes, division by zero, or other mods' hooks), it returns `CONTINUE_SEARCH`. This allows the exception to pass through to the game's native error handling or other injected debuggers (like Steam/RivaTuner) without interference.

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
