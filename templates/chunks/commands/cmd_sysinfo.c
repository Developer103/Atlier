// chunk: commands/cmd_sysinfo
// depends: (none)
// provides: cmd_sysinfo
// note: system info via Win32 API — zero child processes

#ifndef CHUNK_CMD_SYSINFO
#define CHUNK_CMD_SYSINFO

static int cmd_sysinfo(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    (void)args; (void)args_len;
    DWORD cap = *out_len;
    int pos = 0;

    char hostname[256] = {0};
    DWORD hlen = sizeof(hostname);
    if (GetComputerNameA(hostname, &hlen))
        pos += snprintf(out + pos, cap - pos, "Hostname: %s\r\n", hostname);

    char *user = getenv("USERNAME");
    if (user) pos += snprintf(out + pos, cap - pos, "Username: %s\r\n", user);

    OSVERSIONINFOA ov;
    ZeroMemory(&ov, sizeof(ov));
    ov.dwOSVersionInfoSize = sizeof(ov);
    GetVersionExA(&ov);
    pos += snprintf(out + pos, cap - pos, "OS: Windows %lu.%lu Build %lu\r\n",
                    ov.dwMajorVersion, ov.dwMinorVersion, ov.dwBuildNumber);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    pos += snprintf(out + pos, cap - pos, "Arch: %s  CPUs: %lu\r\n",
                    si.wProcessorArchitecture == 9 ? "x64" :
                    si.wProcessorArchitecture == 12 ? "ARM64" : "x86",
                    si.dwNumberOfProcessors);

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms))
        pos += snprintf(out + pos, cap - pos, "RAM: %llu MB\r\n",
                        ms.ullTotalPhys / (1024 * 1024));

    char windir[MAX_PATH] = {0};
    GetWindowsDirectoryA(windir, MAX_PATH);
    pos += snprintf(out + pos, cap - pos, "WinDir: %s\r\n", windir);

    *out_len = (DWORD)pos;
    return 0;
}

#endif
