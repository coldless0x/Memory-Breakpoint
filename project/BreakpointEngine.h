#pragma once

#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <vector>

namespace BreakpointEngine {

// -----------------------------------------------------------------------------
// Scope (read before integrating)
// -----------------------------------------------------------------------------
// - x64 only: uses Rip / EFlags in the exception CONTEXT.
// - Same process only: patches virtual addresses in the current address space.
// - Software INT3 (1 byte) at the given address; requires executable committed
//   memory at that byte.
// - One active Engine per process: registers a vectored exception handler (VEH).
// - Do not call Engine::SetBreakpoint / RemoveBreakpoint / Shutdown from inside a
//   breakpoint callback (deadlock / re-entrancy). Callbacks must not throw C++
//   exceptions across the VEH boundary (undefined behaviour); they are shielded
//   from SEH faults only.
// -----------------------------------------------------------------------------

struct BreakpointContext {
    DWORD threadId = 0;
    void* address = nullptr;
    CONTEXT registers{};
    uint64_t hitCount = 0;
    uint64_t timestamp = 0;
};

using BreakpointCallback = std::function<bool(const BreakpointContext&)>;

enum class BreakpointStatus {
    Disabled,
    Enabled,
    Error
};

class Engine;

class Breakpoint {
    friend class Engine;

public:
    Breakpoint(Engine* owner, void* address);
    ~Breakpoint();

    bool Enable();
    bool Disable();
    bool IsEnabled() const noexcept { return m_status == BreakpointStatus::Enabled; }

    void* GetAddress() const noexcept { return m_address; }
    BreakpointStatus GetStatus() const noexcept { return m_status; }
    uint64_t GetHitCount() const noexcept { return m_hitCount; }

    void SetCallback(BreakpointCallback cb) { m_callback = std::move(cb); }

private:
    bool InvokeCallback(const BreakpointContext& ctx);
    bool PatchInt3() noexcept;
    bool RestoreOriginal() noexcept;

    Engine* m_owner = nullptr;
    void* m_address = nullptr;
    BreakpointStatus m_status = BreakpointStatus::Disabled;
    uint64_t m_hitCount = 0;

    uint8_t m_originalByte = 0;
    DWORD m_originalProtect = 0;
    bool m_haveOriginalProtect = false;

    BreakpointCallback m_callback;
};

class Engine {
public:
    Engine();
    ~Engine();

    /// Returns false if `process_id != 0`, another Engine already owns the VEH,
    /// or AddVectoredExceptionHandler fails. On failure, call `last_error()` for GetLastError.
    bool Initialize(DWORD process_id = 0);
    void Shutdown();

    /// nullptr if `address` is null. Address must be instrumentable before Enable().
    Breakpoint* SetBreakpoint(void* address);
    bool RemoveBreakpoint(void* address);
    Breakpoint* GetBreakpoint(void* address);

    bool EnableBreakpoint(void* address);
    bool DisableBreakpoint(void* address);

    void SetGlobalCallback(BreakpointCallback cb) { m_global_callback = std::move(cb); }
    void SetLog(std::function<void(const char* line)> log) { m_log = std::move(log); }

    bool IsInitialized() const noexcept { return m_veh_handle != nullptr; }
    DWORD last_error() const noexcept { return m_last_error; }

    /// True if the committed page at `p` is executable (current protection).
    static bool AddressIsExecutable(void* p) noexcept;

    struct Stats {
        uint32_t total_breakpoints = 0;
        uint32_t enabled_breakpoints = 0;
        uint64_t total_hits = 0;
    };

    Stats GetStats() const;
    std::vector<Breakpoint*> GetAllBreakpoints() const;

private:
    static LONG CALLBACK StaticVeh(EXCEPTION_POINTERS* info);
    LONG HandleVeh(EXCEPTION_POINTERS* info);

    bool RegisterVeh();
    void UnregisterVeh();
    void DisableAllBreakpointsNoDelete();
    void LogLine(const char* msg) const;

    static std::atomic<Engine*> s_instance;

    std::unordered_map<void*, Breakpoint*> m_breakpoints;
    BreakpointCallback m_global_callback;
    std::function<void(const char*)> m_log;

    void* m_veh_handle = nullptr;
    mutable CRITICAL_SECTION m_cs{};
    DWORD m_last_error = 0;
};

class ScopedBreakpoint {
public:
    ScopedBreakpoint(Engine& engine, void* address) : m_engine(engine), m_address(address) {
        if (Breakpoint* b = engine.SetBreakpoint(address))
            (void)b->Enable();
    }

    ~ScopedBreakpoint() {
        if (m_address) m_engine.RemoveBreakpoint(m_address);
    }

    ScopedBreakpoint(const ScopedBreakpoint&) = delete;
    ScopedBreakpoint& operator=(const ScopedBreakpoint&) = delete;

private:
    Engine& m_engine;
    void* m_address = nullptr;
};

} // namespace BreakpointEngine
