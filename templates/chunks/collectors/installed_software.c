// chunk: collectors/installed_software
// depends: core/emit_buffer
// provides: collect_installed_software

#ifndef CHUNK_INSTALLED_SOFTWARE
#define CHUNK_INSTALLED_SOFTWARE

static void enum_installed_from_key(HKEY root, const char *subkey) {
    HKEY hk;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS)
        return;
    char name[256];
    DWORD idx = 0, name_sz;
    while (1) {
        name_sz = sizeof(name);
        if (RegEnumKeyExA(hk, idx++, name, &name_sz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        HKEY sub;
        if (RegOpenKeyExA(hk, name, 0, KEY_READ, &sub) == ERROR_SUCCESS) {
            char display[256] = {0}, version[64] = {0};
            DWORD dsz = sizeof(display), vsz = sizeof(version);
            RegQueryValueExA(sub, "DisplayName", NULL, NULL, (BYTE *)display, &dsz);
            RegQueryValueExA(sub, "DisplayVersion", NULL, NULL, (BYTE *)version, &vsz);
            if (display[0])
                emitf("  %s %s\r\n", display, version);
            RegCloseKey(sub);
        }
    }
    RegCloseKey(hk);
}

static void collect_installed_software(void) {
    emitf("=== INSTALLED SOFTWARE ===\r\n");
    enum_installed_from_key(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    enum_installed_from_key(HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    emitf("\r\n");
}

#endif
