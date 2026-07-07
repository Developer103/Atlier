// chunk: collectors/recent_files
// depends: core/emit_buffer
// provides: collect_recent_files
// note: enumerate Recent folder items — KERNEL32/msvcrt only

#ifndef CHUNK_RECENT_FILES
#define CHUNK_RECENT_FILES

static void collect_recent_files(void) {
    emitf("=== RECENT FILES ===\r\n");

    char recent[MAX_PATH] = {0};
    char *profile = getenv("USERPROFILE");
    if (!profile) { emitf("(no USERPROFILE)\r\n\r\n"); return; }
    snprintf(recent, MAX_PATH, "%s\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\", profile);

    char search[MAX_PATH];
    snprintf(search, MAX_PATH, "%s*.lnk", recent);

    WIN32_FIND_DATAA fd;
    HANDLE hf = FindFirstFileA(search, &fd);
    if (hf == INVALID_HANDLE_VALUE) { emitf("(empty)\r\n\r\n"); return; }

    int count = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        SYSTEMTIME st;
        FileTimeToSystemTime(&fd.ftLastWriteTime, &st);
        char name[256];
        strncpy(name, fd.cFileName, sizeof(name) - 1);
        char *dot = strstr(name, ".lnk");
        if (dot) *dot = '\0';
        emitf("  %04d-%02d-%02d %02d:%02d  %s\r\n",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, name);
        if (++count >= 50) break;
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);
    emitf("Total: %d recent items\r\n\r\n", count);
}

#endif
