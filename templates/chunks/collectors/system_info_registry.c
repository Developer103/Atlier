// chunk: collectors/system_info_registry
// depends: core/emit_buffer
// provides: collect_system_info
// headers: (none)
// libs: advapi32

#ifndef CHUNK_SYSTEM_INFO_REGISTRY
#define CHUNK_SYSTEM_INFO_REGISTRY

static void _reg_read_str(HKEY root, const char *subkey, const char *name,
                          char *buf, DWORD bufsz) {
    HKEY hk;
    buf[0] = '\0';
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        DWORD type = 0, cb = bufsz - 1;
        if (RegQueryValueExA(hk, name, NULL, &type, (BYTE *)buf, &cb) == ERROR_SUCCESS) {
            if (type == REG_SZ || type == REG_EXPAND_SZ)
                buf[cb] = '\0';
            else
                buf[0] = '\0';
        }
        RegCloseKey(hk);
    }
}

static void collect_system_info(void) {
    emitf("=== SYSTEM INFO ===\r\n");

    char val[512];

    _reg_read_str(HKEY_LOCAL_MACHINE,
                  "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName",
                  "ComputerName", val, sizeof(val));
    if (val[0]) emitf("Hostname: %s\r\n", val);

    char user[256] = {0};
    DWORD ulen = sizeof(user);
    if (GetUserNameA(user, &ulen))
        emitf("Username: %s\r\n", user);

    _reg_read_str(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                  "ProductName", val, sizeof(val));
    char build[64] = {0}, display[64] = {0};
    _reg_read_str(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                  "CurrentBuild", build, sizeof(build));
    _reg_read_str(HKEY_LOCAL_MACHINE,
                  "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                  "DisplayVersion", display, sizeof(display));
    emitf("OS: %s Build %s (%s)\r\n",
          val[0] ? val : "Windows", build[0] ? build : "?",
          display[0] ? display : "?");

    _reg_read_str(HKEY_LOCAL_MACHINE,
                  "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
                  "PROCESSOR_ARCHITECTURE", val, sizeof(val));
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    emitf("Arch: %s  CPUs: %lu\r\n",
          val[0] ? val : "unknown", si.dwNumberOfProcessors);

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms))
        emitf("RAM: %llu MB\r\n", ms.ullTotalPhys / (1024 * 1024));

    _reg_read_str(HKEY_LOCAL_MACHINE,
                  "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                  "Domain", val, sizeof(val));
    if (val[0]) emitf("Domain: %s\r\n", val);

    _reg_read_str(HKEY_LOCAL_MACHINE,
                  "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                  "Hostname", val, sizeof(val));
    if (val[0]) emitf("TCP Hostname: %s\r\n", val);

    emitf("\r\n");
}

#endif
