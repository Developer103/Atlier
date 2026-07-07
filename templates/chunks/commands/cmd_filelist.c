// chunk: commands/cmd_filelist
// depends: (none)
// provides: cmd_filelist
// note: directory listing via FindFirstFile/FindNextFile — zero child processes

#ifndef CHUNK_CMD_FILELIST
#define CHUNK_CMD_FILELIST

static int cmd_filelist(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    DWORD cap = *out_len;
    int pos = 0;

    char pattern[MAX_PATH];
    if (args_len == 0 || !args) {
        strncpy(pattern, "C:\\Users\\*", sizeof(pattern) - 1);
    } else {
        char dir[MAX_PATH] = {0};
        DWORD cplen = (args_len < MAX_PATH - 3) ? args_len : MAX_PATH - 3;
        memcpy(dir, args, cplen);
        dir[cplen] = '\0';
        while (cplen > 0 && (dir[cplen - 1] == '\r' || dir[cplen - 1] == '\n'))
            dir[--cplen] = '\0';
        if (dir[cplen - 1] == '\\')
            snprintf(pattern, sizeof(pattern), "%s*", dir);
        else
            snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    }

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        pos += snprintf(out + pos, cap - pos, "Error: cannot list %s\r\n", pattern);
        *out_len = (DWORD)pos;
        return 1;
    }

    do {
        if ((DWORD)pos >= cap - 512) break;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            pos += snprintf(out + pos, cap - pos, "d %s\r\n", fd.cFileName);
        } else {
            ULARGE_INTEGER sz;
            sz.LowPart = fd.nFileSizeLow;
            sz.HighPart = fd.nFileSizeHigh;
            pos += snprintf(out + pos, cap - pos, "f %s (%llu bytes)\r\n",
                            fd.cFileName, sz.QuadPart);
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    *out_len = (DWORD)pos;
    return 0;
}

#endif
