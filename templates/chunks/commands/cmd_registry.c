// chunk: commands/cmd_registry
// depends: (none)
// provides: cmd_registry
// libs: advapi32
// note: registry read via RegOpenKeyEx/RegEnumValue — zero child processes

#ifndef CHUNK_CMD_REGISTRY
#define CHUNK_CMD_REGISTRY

static HKEY reg_parse_root(const char *path, const char **subkey) {
    if (strncmp(path, "HKLM\\", 5) == 0) { *subkey = path + 5; return HKEY_LOCAL_MACHINE; }
    if (strncmp(path, "HKCU\\", 5) == 0) { *subkey = path + 5; return HKEY_CURRENT_USER; }
    if (strncmp(path, "HKCR\\", 5) == 0) { *subkey = path + 5; return HKEY_CLASSES_ROOT; }
    if (strncmp(path, "HKU\\", 4) == 0) { *subkey = path + 4; return HKEY_USERS; }
    if (strncmp(path, "HKEY_LOCAL_MACHINE\\", 18) == 0) { *subkey = path + 18; return HKEY_LOCAL_MACHINE; }
    if (strncmp(path, "HKEY_CURRENT_USER\\", 18) == 0) { *subkey = path + 18; return HKEY_CURRENT_USER; }
    *subkey = path;
    return HKEY_LOCAL_MACHINE;
}

static int cmd_registry(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    DWORD cap = *out_len;
    int pos = 0;

    if (args_len == 0 || !args) {
        pos = snprintf(out, cap, "Error: provide registry path\r\n");
        *out_len = (DWORD)pos;
        return 1;
    }

    char path[512] = {0};
    DWORD cplen = (args_len < sizeof(path) - 1) ? args_len : sizeof(path) - 1;
    memcpy(path, args, cplen);
    while (cplen > 0 && (path[cplen - 1] == '\r' || path[cplen - 1] == '\n'))
        path[--cplen] = '\0';

    const char *subkey = NULL;
    HKEY root = reg_parse_root(path, &subkey);

    HKEY hKey;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        pos = snprintf(out, cap, "Error: cannot open %s\r\n", path);
        *out_len = (DWORD)pos;
        return 1;
    }

    char name[256];
    BYTE data[1024];
    for (DWORD i = 0; i < 256; i++) {
        DWORD name_len = sizeof(name);
        DWORD data_len = sizeof(data);
        DWORD type = 0;
        LONG rc = RegEnumValueA(hKey, i, name, &name_len, NULL, &type, data, &data_len);
        if (rc != ERROR_SUCCESS) break;
        if ((DWORD)pos >= cap - 1280) break;

        switch (type) {
            case REG_SZ:
            case REG_EXPAND_SZ:
                pos += snprintf(out + pos, cap - pos, "%s = \"%s\"\r\n", name, (char *)data);
                break;
            case REG_DWORD:
                if (data_len >= 4)
                    pos += snprintf(out + pos, cap - pos, "%s = 0x%08lX\r\n",
                                    name, *(DWORD *)data);
                break;
            default:
                pos += snprintf(out + pos, cap - pos, "%s = (type %lu, %lu bytes)\r\n",
                                name, type, data_len);
                break;
        }
    }

    RegCloseKey(hKey);
    *out_len = (DWORD)pos;
    return 0;
}

#endif
