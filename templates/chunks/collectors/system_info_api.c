// chunk: collectors/system_info_api
// depends: core/emit_buffer
// provides: collect_system_info
// note: all KERNEL32/msvcrt APIs — no cmd.exe, no iphlpapi, no LOLBins

#ifndef CHUNK_SYSTEM_INFO_API
#define CHUNK_SYSTEM_INFO_API

static void collect_system_info(void) {
    emitf("=== SYSTEM INFO ===\r\n");

    char hostname[256] = {0};
    DWORD hlen = sizeof(hostname);
    if (GetComputerNameA(hostname, &hlen))
        emitf("Hostname: %s\r\n", hostname);

    char *user = getenv("USERNAME");
    if (user) emitf("Username: %s\r\n", user);

    OSVERSIONINFOA ov;
    ZeroMemory(&ov, sizeof(ov));
    ov.dwOSVersionInfoSize = sizeof(ov);
    GetVersionExA(&ov);
    emitf("OS: Windows %lu.%lu Build %lu\r\n",
          ov.dwMajorVersion, ov.dwMinorVersion, ov.dwBuildNumber);

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

    emitf("\r\n");
}

#endif
