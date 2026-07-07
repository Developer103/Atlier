// chunk: collectors/scheduled_tasks_recon
// depends: core/emit_buffer, core/run_cmd
// provides: collect_scheduled_tasks
// note: LOLBin — enumerate scheduled tasks for persistence recon

#ifndef CHUNK_SCHTASKS_RECON
#define CHUNK_SCHTASKS_RECON

static void collect_scheduled_tasks(void) {
    emitf("=== SCHEDULED TASKS ===\r\n");
    char buf[16384] = {0};
    DWORD buf_len = 0;
    run_cmd("cmd /c schtasks /query /fo csv /nh /v 2>nul | findstr /i /v \"disabled\"",
            buf, sizeof(buf), &buf_len);
    if (buf_len > 0)
        emitf("%.*s", (int)buf_len, buf);
    else
        emitf("(no tasks or access denied)\r\n");
    emitf("\r\n");
}

#endif
