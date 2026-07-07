// chunk: commands/cmd_filewrite
// depends: (none)
// provides: cmd_filewrite
// note: write file via CreateFile/WriteFile — zero child processes

#ifndef CHUNK_CMD_FILEWRITE
#define CHUNK_CMD_FILEWRITE

static int cmd_filewrite(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    DWORD cap = *out_len;
    if (args_len == 0 || !args) {
        *out_len = 0;
        return 1;
    }

    const char *nl = memchr(args, '\n', args_len);
    if (!nl) {
        int n = snprintf(out, cap, "Error: format is PATH\\nCONTENT\r\n");
        *out_len = (DWORD)n;
        return 1;
    }

    char path[MAX_PATH] = {0};
    DWORD plen = (DWORD)(nl - args);
    if (plen >= MAX_PATH) plen = MAX_PATH - 1;
    memcpy(path, args, plen);
    while (plen > 0 && (path[plen - 1] == '\r' || path[plen - 1] == '\n'))
        path[--plen] = '\0';

    const char *content = nl + 1;
    DWORD content_len = args_len - (DWORD)(content - args);

    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        int n = snprintf(out, cap, "Error: cannot create %s\r\n", path);
        *out_len = (DWORD)n;
        return 1;
    }

    DWORD written = 0;
    WriteFile(hFile, content, content_len, &written, NULL);
    CloseHandle(hFile);

    int n = snprintf(out, cap, "OK: wrote %lu bytes to %s\r\n", written, path);
    *out_len = (DWORD)n;
    return 0;
}

#endif
