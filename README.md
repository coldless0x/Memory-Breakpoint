# Memory breakpoint engine (INT3 + VEH)

Small Windows library for **same-process software breakpoints** using a **single-byte `INT3` (`0xCC`)** patch and a **vectored exception handler (VEH)**. On each hit, the engine restores the original opcode, advances execution with a **single-step**, then re-arms the breakpoint.

## Requirements

- **Windows x64** (exception context uses `Rip` / `EFlags`).
- **Visual Studio 2022** (v143 toolset) or compatible MSVC, **C++17**.
- Build **x64** only (Debug or Release).

## What this is / is not

| Supported | Not supported |
|-----------|----------------|
| Same address space as the caller | Remote process attach |
| Software `INT3` at a chosen VA | Hardware debug registers (`DR0`–`DR7`) |
| `AddVectoredExceptionHandler` flow | Guard-page or other breakpoint styles |

## Build

Open `memory-breakpoint.sln`, select **x64** and **Debug** or **Release**, then build. The sample executable is emitted as **`breakpoint-engine.exe`** under `x64\<Configuration>\`.

## Usage (minimal)

```cpp
#include "BreakpointEngine.h"

BreakpointEngine::Engine engine;
if (!engine.Initialize(0)) {
    // Use engine.last_error() for GetLastError-style diagnostics.
    return;
}

void* addr = reinterpret_cast<void*>(&MyFunction);
if (BreakpointEngine::Breakpoint* bp = engine.SetBreakpoint(addr)) {
    bp->SetCallback([](const BreakpointEngine::BreakpointContext& ctx) {
        (void)ctx; // threadId, address, registers, hitCount, timestamp
        return true;
    });
    if (!bp->Enable()) { /* VirtualProtect / non-executable VA */ }
}

MyFunction();

engine.Shutdown(); // disables breakpoints, unregisters VEH, frees state
```

`ScopedBreakpoint` registers, enables on construction, and removes the breakpoint on destruction (see `BreakpointEngine.h`).

## API notes

- **`Initialize(0)`** — Only **`process_id == 0`** is accepted (current process). **One active `Engine` per process** installs the VEH; a second `Initialize` fails with `last_error()` set (e.g. `ERROR_ALREADY_INITIALIZED`).
- **`AddressIsExecutable`** — `Enable()` rejects addresses that are not on a committed executable page.
- **`Shutdown`** — Disables all breakpoints before removing the VEH to avoid stray `INT3` hits with no handler.
- **Callbacks** — Do not call `SetBreakpoint`, `RemoveBreakpoint`, or `Shutdown` from inside a breakpoint callback (deadlock / re-entrancy). Do not throw C++ exceptions across the VEH boundary; MSVC builds wrap callback invocation in **SEH** so access violations inside the callback are contained (the handler still treats the breakpoint as handled for execution flow).

## Files

| File | Role |
|------|------|
| `BreakpointEngine.h` / `BreakpointEngine.cpp` | Engine, breakpoint objects, VEH |
| `example.cpp` | Console sample |
| `memory-breakpoint.vcxproj` | MSVC project |

## License

Specify your license in this repository root or here as appropriate for your organization.
