// chunk: commands/cmd_fileread
// depends: (none)
// provides: cmd_fileread
// note: read file contents via CreateFile/ReadFile — zero child processes

#ifndef CHUNK_CMD_FILEREAD
#define CHUNK_CMD_FILEREAD

#define CMD_FILEREAD_MAX (512 * 1024)

static int cmd_fileread(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    DWORD cap = *out_len;
    if (args_len == 0 || !args) {
        *out_len = 0;
        return 1;
    }

    char path[MAX_PATH] = {0};
    DWORD cplen = (args_len < MAX_PATH - 1) ? args_len : MAX_PATH - 1;
    memcpy(path, args, cplen);
    while (cplen > 0 && (path[cplen - 1] == '\r' || path[cplen - 1] == '\n'))
        path[--cplen] = '\0';

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        int n = snprintf(out, cap, "Error: cannot open %s\r\n", path);
        *out_len = (DWORD)n;
        return 1;
    }

    DWORD file_sz = GetFileSize(hFile, NULL);
    DWORD to_read = file_sz;
    if (to_read > CMD_FILEREAD_MAX) to_read = CMD_FILEREAD_MAX;
    if (to_read > cap) to_read = cap;

    DWORD rd = 0;
    ReadFile(hFile, out, to_read, &rd, NULL);
    CloseHandle(hFile);

    *out_len = rd;
    return 0;
}

#endif
