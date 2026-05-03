#include "BreakpointEngine.h"

#include <cstdio>
#include <cstdlib>

using namespace BreakpointEngine;

static void pause_exit(int code) {
    printf("\nPress Enter to close... ");
    fflush(stdout);
    (void)getchar();
    exit(code);
}

static void TargetFunction() {
    printf("Target function executed.\n");
}

static void AnotherFunction() {
    printf("Another function executed.\n");
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    printf("INT3 + VEH (same process, x64). Build x64 Release or Debug.\n\n");

    Engine engine;
    if (!engine.Initialize(0)) {
        printf("Initialize failed (last_error=%lu). Only one Engine per process; VEH must register.\n",
               static_cast<unsigned long>(engine.last_error()));
        pause_exit(1);
    }

    void* const targetAddr = reinterpret_cast<void*>(&TargetFunction);
    void* const anotherAddr = reinterpret_cast<void*>(&AnotherFunction);

    printf("Breakpoints at %p and %p\n\n", targetAddr, anotherAddr);

    const auto callback = [](const BreakpointContext& ctx) {
        printf("Hit @ %p  thread=%lu  count=%llu  Rip=%016llx\n", ctx.address, ctx.threadId, ctx.hitCount,
               static_cast<unsigned long long>(ctx.registers.Rip));
        return true;
    };

    if (Breakpoint* bp1 = engine.SetBreakpoint(targetAddr)) {
        bp1->SetCallback(callback);
        if (!bp1->Enable()) {
            printf("Enable failed on target (VirtualProtect? run as normal user, x64 only).\n");
            pause_exit(1);
        }
    }

    if (Breakpoint* bp2 = engine.SetBreakpoint(anotherAddr)) {
        bp2->SetCallback(callback);
        if (!bp2->Enable()) {
            printf("Enable failed on another.\n");
            pause_exit(1);
        }
    }

    printf("Calling functions (each hit removes INT3, single-steps, re-arms)...\n\n");
    TargetFunction();
    AnotherFunction();
    TargetFunction();

    const auto stats = engine.GetStats();
    printf("\nStats: total=%u enabled=%u hits=%llu\n", stats.total_breakpoints, stats.enabled_breakpoints,
           stats.total_hits);

    printf("\nDisabling...\n");
    engine.DisableBreakpoint(targetAddr);
    engine.DisableBreakpoint(anotherAddr);

    printf("Calls after disable (no hits expected):\n");
    TargetFunction();

    engine.Shutdown();
    printf("Done.\n");
    pause_exit(0);
}
