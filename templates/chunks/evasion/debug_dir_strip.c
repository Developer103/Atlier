// chunk: evasion/debug_dir_strip
// depends: (none)
// provides: strip_debug_dir
// headers: windows.h
// risk: none
// note: Strips the debug directory from the PE header in memory. Debug directories
//       contain PDB paths, build GUIDs, and compiler info that aid attribution
//       and signature matching. Zeroing them removes this fingerprint.

#ifndef CHUNK_DEBUG_DIR_STRIP
#define CHUNK_DEBUG_DIR_STRIP

#include <windows.h>

static void strip_debug_dir(void) {
    HMODULE base = GetModuleHandleA(NULL);
    if (!base) return;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *pe = (IMAGE_NT_HEADERS *)((BYTE *)base + dos->e_lfanew);

    DWORD dbg_rva = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
    DWORD dbg_size = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

    if (!dbg_rva || !dbg_size) return;

    /* Zero the debug data directory entry in the PE header */
    DWORD old;
    VirtualProtect(&pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG],
                   sizeof(IMAGE_DATA_DIRECTORY), PAGE_READWRITE, &old);
    pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
    pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
    VirtualProtect(&pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG],
                   sizeof(IMAGE_DATA_DIRECTORY), old, &old);

    /* Zero the actual debug directory entries */
    BYTE *dbg_data = (BYTE *)base + dbg_rva;
    VirtualProtect(dbg_data, dbg_size, PAGE_READWRITE, &old);
    memset(dbg_data, 0, dbg_size);
    VirtualProtect(dbg_data, dbg_size, old, &old);
}

#endif
