// chunk: evasion/anti_debug_int3
// depends: (none)
// provides: anti_debug_check
// headers: windows.h
// risk: low
// note: INT3 breakpoint scanning — computes CRC32 checksum of own .text section, detects software breakpoints (0xCC patches)

#ifndef CHUNK_ANTI_DEBUG_INT3
#define CHUNK_ANTI_DEBUG_INT3

#include <windows.h>

static DWORD g_text_crc = 0;
static BYTE *g_text_start = NULL;
static DWORD g_text_size = 0;

static DWORD ad_crc32(const BYTE *data, DWORD len) {
    DWORD crc = 0xFFFFFFFF;
    for (DWORD i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
    }
    return ~crc;
}

static void ad_init_text_crc(void) {
    if (g_text_start) return;

    HMODULE mod = GetModuleHandleA(NULL);
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            g_text_start = base + sec[i].VirtualAddress;
            g_text_size = sec[i].Misc.VirtualSize;
            g_text_crc = ad_crc32(g_text_start, g_text_size);
            return;
        }
    }
}

static int anti_debug_check(void) {
    if (!g_text_start)
        ad_init_text_crc();

    if (!g_text_start || g_text_size == 0)
        return 0;

    DWORD current_crc = ad_crc32(g_text_start, g_text_size);
    if (current_crc != g_text_crc)
        return 1;

    return 0;
}

#endif
