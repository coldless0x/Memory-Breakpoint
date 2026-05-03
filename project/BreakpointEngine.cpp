#include "BreakpointEngine.h"

namespace BreakpointEngine {

std::atomic<Engine*> Engine::s_instance{nullptr};

namespace {

thread_local Breakpoint* tls_rearm = nullptr;

bool InvokeCallbackSeh(const BreakpointCallback& cb, const BreakpointContext& ctx) noexcept {
    if (!cb) return true;
#if defined(_MSC_VER)
    __try {
        return cb(ctx) ? true : false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
#else
    return cb(ctx) ? true : false;
#endif
}

} // namespace

Breakpoint::Breakpoint(Engine* owner, void* address) : m_owner(owner), m_address(address) {}

Breakpoint::~Breakpoint() {
    Disable();
}

bool Breakpoint::InvokeCallback(const BreakpointContext& ctx) {
    return InvokeCallbackSeh(m_callback, ctx);
}

bool Breakpoint::PatchInt3() noexcept {
    if (!m_haveOriginalProtect) return false;
    DWORD tmp = 0;
    if (!VirtualProtect(m_address, 1, PAGE_EXECUTE_READWRITE, &tmp)) return false;
    *static_cast<uint8_t*>(m_address) = 0xCC;
    if (!VirtualProtect(m_address, 1, m_originalProtect, &tmp)) return false;
    FlushInstructionCache(GetCurrentProcess(), m_address, 1);
    return true;
}

bool Breakpoint::RestoreOriginal() noexcept {
    if (!m_haveOriginalProtect) return false;
    DWORD oldProtect = 0;
    if (!VirtualProtect(m_address, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;
    *static_cast<uint8_t*>(m_address) = m_originalByte;
    if (!VirtualProtect(m_address, 1, m_originalProtect, &oldProtect)) return false;
    FlushInstructionCache(GetCurrentProcess(), m_address, 1);
    return true;
}

bool Breakpoint::Enable() {
    if (m_status == BreakpointStatus::Enabled) return true;
    if (!m_address || !m_owner || !m_owner->IsInitialized()) return false;
    if (!Engine::AddressIsExecutable(m_address)) return false;

    DWORD oldProtect = 0;
    if (!VirtualProtect(m_address, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;
    m_originalByte = *static_cast<uint8_t*>(m_address);
    m_originalProtect = oldProtect;
    m_haveOriginalProtect = true;
    *static_cast<uint8_t*>(m_address) = 0xCC;
    DWORD tmp = 0;
    if (!VirtualProtect(m_address, 1, oldProtect, &tmp)) {
        *static_cast<uint8_t*>(m_address) = m_originalByte;
        (void)VirtualProtect(m_address, 1, oldProtect, &tmp);
        FlushInstructionCache(GetCurrentProcess(), m_address, 1);
        m_haveOriginalProtect = false;
        return false;
    }
    FlushInstructionCache(GetCurrentProcess(), m_address, 1);

    m_status = BreakpointStatus::Enabled;
    return true;
}

bool Breakpoint::Disable() {
    if (m_status == BreakpointStatus::Disabled) return true;
    if (!m_address) return false;
    if (!m_haveOriginalProtect) {
        m_status = BreakpointStatus::Disabled;
        return true;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(m_address, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;
    *static_cast<uint8_t*>(m_address) = m_originalByte;
    if (!VirtualProtect(m_address, 1, m_originalProtect, &oldProtect)) return false;
    FlushInstructionCache(GetCurrentProcess(), m_address, 1);

    m_status = BreakpointStatus::Disabled;
    return true;
}

void Engine::LogLine(const char* msg) const {
    if (m_log) m_log(msg);
}

Engine::Engine() {
    InitializeCriticalSection(&m_cs);
}

Engine::~Engine() {
    Shutdown();
    DeleteCriticalSection(&m_cs);
}

bool Engine::AddressIsExecutable(void* p) noexcept {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
    if (!(mbi.State & MEM_COMMIT)) return false;
    const DWORD xp =
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (mbi.Protect & xp) != 0;
}

bool Engine::Initialize(DWORD process_id) {
    m_last_error = 0;
    if (process_id != 0) {
        m_last_error = ERROR_INVALID_PARAMETER;
        return false;
    }

    Engine* expected = nullptr;
    if (!s_instance.compare_exchange_strong(expected, this, std::memory_order_acq_rel)) {
        m_last_error = ERROR_ALREADY_INITIALIZED;
        return false;
    }

    if (!RegisterVeh()) {
        m_last_error = GetLastError();
        s_instance.store(nullptr, std::memory_order_release);
        return false;
    }

    return true;
}

void Engine::DisableAllBreakpointsNoDelete() {
    EnterCriticalSection(&m_cs);
    for (auto& p : m_breakpoints) {
        if (p.second) (void)p.second->Disable();
    }
    LeaveCriticalSection(&m_cs);
}

void Engine::Shutdown() {
    DisableAllBreakpointsNoDelete();
    UnregisterVeh();

    if (s_instance.load(std::memory_order_acquire) == this)
        s_instance.store(nullptr, std::memory_order_release);

    EnterCriticalSection(&m_cs);
    for (auto& p : m_breakpoints) delete p.second;
    m_breakpoints.clear();
    LeaveCriticalSection(&m_cs);
}

bool Engine::RegisterVeh() {
    m_veh_handle = AddVectoredExceptionHandler(1, StaticVeh);
    return m_veh_handle != nullptr;
}

void Engine::UnregisterVeh() {
    if (m_veh_handle) {
        RemoveVectoredExceptionHandler(m_veh_handle);
        m_veh_handle = nullptr;
    }
}

LONG CALLBACK Engine::StaticVeh(EXCEPTION_POINTERS* info) {
    Engine* e = s_instance.load(std::memory_order_acquire);
    return e ? e->HandleVeh(info) : EXCEPTION_CONTINUE_SEARCH;
}

LONG Engine::HandleVeh(EXCEPTION_POINTERS* info) {
    EXCEPTION_RECORD* er = info->ExceptionRecord;
    PCONTEXT c = info->ContextRecord;
    if (!er || !c) return EXCEPTION_CONTINUE_SEARCH;

    const DWORD code = er->ExceptionCode;

    if (code == EXCEPTION_SINGLE_STEP) {
        if (!tls_rearm) return EXCEPTION_CONTINUE_SEARCH;
        Breakpoint* b = tls_rearm;
        tls_rearm = nullptr;
        c->ContextFlags = CONTEXT_FULL;
        c->EFlags &= ~0x100ULL;
        if (b->IsEnabled() && !b->PatchInt3()) b->m_status = BreakpointStatus::Error;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code != EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;

    void* int3_addr = nullptr;
    Breakpoint* bp = nullptr;
    void* const candidates[2] = {er->ExceptionAddress,
                                  reinterpret_cast<void*>(static_cast<uintptr_t>(c->Rip) - 1u)};

    EnterCriticalSection(&m_cs);
    for (void* addr : candidates) {
        if (!addr) continue;
        auto it = m_breakpoints.find(addr);
        if (it != m_breakpoints.end()) {
            bp = it->second;
            int3_addr = addr;
            break;
        }
    }
    LeaveCriticalSection(&m_cs);

    if (!bp || !bp->IsEnabled() || !int3_addr) return EXCEPTION_CONTINUE_SEARCH;

    if (!bp->RestoreOriginal()) {
        bp->m_status = BreakpointStatus::Error;
        return EXCEPTION_CONTINUE_SEARCH;
    }
    FlushInstructionCache(GetCurrentProcess(), int3_addr, 1);

    c->ContextFlags = CONTEXT_FULL;
    c->Rip = reinterpret_cast<DWORD64>(int3_addr);
    c->EFlags |= 0x100ULL;
    tls_rearm = bp;

    ++bp->m_hitCount;

    BreakpointContext ctx{};
    ctx.threadId = GetCurrentThreadId();
    ctx.address = int3_addr;
    ctx.hitCount = bp->GetHitCount();
    ctx.timestamp = GetTickCount64();
    ctx.registers.ContextFlags = CONTEXT_FULL;
    ctx.registers = *c;

    (void)InvokeCallbackSeh(bp->m_callback, ctx);
    (void)InvokeCallbackSeh(m_global_callback, ctx);

    return EXCEPTION_CONTINUE_EXECUTION;
}

Breakpoint* Engine::SetBreakpoint(void* address) {
    if (!address) return nullptr;

    EnterCriticalSection(&m_cs);
    auto it = m_breakpoints.find(address);
    if (it != m_breakpoints.end()) {
        Breakpoint* existing = it->second;
        LeaveCriticalSection(&m_cs);
        return existing;
    }
    auto* bp = new Breakpoint(this, address);
    m_breakpoints[address] = bp;
    LeaveCriticalSection(&m_cs);
    return bp;
}

bool Engine::RemoveBreakpoint(void* address) {
    EnterCriticalSection(&m_cs);
    auto it = m_breakpoints.find(address);
    if (it == m_breakpoints.end()) {
        LeaveCriticalSection(&m_cs);
        return false;
    }
    Breakpoint* bp = it->second;
    m_breakpoints.erase(it);
    LeaveCriticalSection(&m_cs);

    delete bp;
    return true;
}

Breakpoint* Engine::GetBreakpoint(void* address) {
    EnterCriticalSection(&m_cs);
    auto it = m_breakpoints.find(address);
    Breakpoint* bp = (it != m_breakpoints.end()) ? it->second : nullptr;
    LeaveCriticalSection(&m_cs);
    return bp;
}

bool Engine::EnableBreakpoint(void* address) {
    Breakpoint* bp = GetBreakpoint(address);
    return bp && bp->Enable();
}

bool Engine::DisableBreakpoint(void* address) {
    Breakpoint* bp = GetBreakpoint(address);
    return bp && bp->Disable();
}

Engine::Stats Engine::GetStats() const {
    Stats s{};
    EnterCriticalSection(&m_cs);
    s.total_breakpoints = static_cast<uint32_t>(m_breakpoints.size());
    for (const auto& p : m_breakpoints) {
        if (p.second->IsEnabled()) ++s.enabled_breakpoints;
        s.total_hits += p.second->GetHitCount();
    }
    LeaveCriticalSection(&m_cs);
    return s;
}

std::vector<Breakpoint*> Engine::GetAllBreakpoints() const {
    std::vector<Breakpoint*> out;
    EnterCriticalSection(&m_cs);
    out.reserve(m_breakpoints.size());
    for (const auto& p : m_breakpoints) out.push_back(p.second);
    LeaveCriticalSection(&m_cs);
    return out;
}

} // namespace BreakpointEngine
