// chunk: evasion/guard_pages
// depends: (none)
// provides: guard_page_init
// headers: windows.h
// risk: none
// note: PAGE_GUARD exception-based control flow — sets guard pages on code sections
//       and uses a vectored exception handler to manage execution. Each memory access
//       triggers an exception, and the handler decides whether to allow execution.
//       This breaks linear debugger stepping and confuses automated analysis.

#ifndef CHUNK_GUARD_PAGES
#define CHUNK_GUARD_PAGES

#include <windows.h>

static PVOID _guard_veh_handle = NULL;
static BYTE *_guard_region = NULL;
static DWORD _guard_region_size = 0;
static volatile int _guard_active = 0;

static LONG CALLBACK _guard_handler(PEXCEPTION_POINTERS info) {
    if (!_guard_active) return EXCEPTION_CONTINUE_SEARCH;

    if (info->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        /* Allow the access — the guard page flag is automatically removed.
           Set the single-step flag so we get a single-step exception after
           the instruction executes, then we re-set the guard. */
        info->ContextRecord->EFlags |= 0x100; /* TF (trap flag) */
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (info->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
        /* Re-apply guard page after the instruction completed */
        PVOID fault_addr = (PVOID)info->ContextRecord->Rip;
        if (fault_addr >= (PVOID)_guard_region &&
            fault_addr < (PVOID)(_guard_region + _guard_region_size)) {
            DWORD old;
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(fault_addr, &mbi, sizeof(mbi))) {
                VirtualProtect(mbi.BaseAddress, mbi.RegionSize,
                             mbi.Protect | PAGE_GUARD, &old);
            }
        }
        info->ContextRecord->EFlags &= ~0x100;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

static void guard_page_init(void) {
    _guard_veh_handle = AddVectoredExceptionHandler(1, _guard_handler);
}

#endif
