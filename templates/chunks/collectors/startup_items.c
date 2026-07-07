// chunk: collectors/startup_items
// depends: core/emit_buffer
// provides: collect_startup_items
// note: enumerate Run/RunOnce registry keys — uses ADVAPI32 (Reg* APIs)

#ifndef CHUNK_STARTUP_ITEMS
#define CHUNK_STARTUP_ITEMS

static void dump_run_key(const char *label, HKEY root, const char *subkey) {
    HKEY hk;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) != ERROR_SUCCESS) return;
    char name[256], data[1024];
    DWORD idx = 0, nsz, dsz, dtype;
    emitf("  [%s]\r\n", label);
    while (1) {
        nsz = sizeof(name); dsz = sizeof(data);
        if (RegEnumValueA(hk, idx++, name, &nsz, NULL, &dtype, (BYTE *)data, &dsz) != ERROR_SUCCESS)
            break;
        if (dtype == REG_SZ || dtype == REG_EXPAND_SZ)
            emitf("    %s = %s\r\n", name, data);
    }
    RegCloseKey(hk);
}

static void collect_startup_items(void) {
    emitf("=== STARTUP ITEMS ===\r\n");
    dump_run_key("HKCU\\Run", HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    dump_run_key("HKCU\\RunOnce", HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    dump_run_key("HKLM\\Run", HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
    dump_run_key("HKLM\\RunOnce", HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    emitf("\r\n");
}

#endif
