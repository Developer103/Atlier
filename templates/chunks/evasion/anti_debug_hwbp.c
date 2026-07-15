// chunk: evasion/anti_debug_hwbp
// depends: (none)
// provides: check_debugger
// headers: windows.h
// risk: low
// note: Detects hardware breakpoints by reading DR0-DR3 debug registers via GetThreadContext. Non-zero debug registers mean a debugger set hardware breakpoints. Also checks DR7 local enable bits to catch active breakpoints even when addresses are zero.

#ifndef CHUNK_ANTI_DEBUG_HWBP
#define CHUNK_ANTI_DEBUG_HWBP

#include <windows.h>

static int check_debugger(void) {
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(GetCurrentThread(), &ctx))
        return 0;

    // DR0-DR3 hold hardware breakpoint addresses — nonzero = breakpoint set
    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
        return 1;

    // DR7 debug control register — bits 0,2,4,6 are local enable flags
    // If any are set, a hardware breakpoint is enabled
    if (ctx.Dr7 & 0x55)
        return 1;

    return 0;
}

#endif
