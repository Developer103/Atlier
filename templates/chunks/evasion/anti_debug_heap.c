// chunk: evasion/anti_debug_heap
// depends: (none)
// provides: anti_debug_check
// headers: windows.h
// risk: low
// note: Heap flags check — in a debugger, ProcessHeap.Flags != HEAP_GROWABLE and ForceFlags != 0. Reads PEB directly.

#ifndef CHUNK_ANTI_DEBUG_HEAP
#define CHUNK_ANTI_DEBUG_HEAP

#include <windows.h>

static int anti_debug_check(void) {
    // Read PEB directly via TEB
#ifdef _WIN64
    // TEB.ProcessEnvironmentBlock at offset 0x60 in GS segment
    BYTE *peb = (BYTE *)__readgsqword(0x60);
    // PEB.ProcessHeap at offset 0x30 (x64)
    BYTE *heap = *(BYTE **)(peb + 0x30);
    // HEAP.Flags at offset 0x70 (x64, Windows 10+)
    DWORD flags = *(DWORD *)(heap + 0x70);
    // HEAP.ForceFlags at offset 0x74 (x64, Windows 10+)
    DWORD force_flags = *(DWORD *)(heap + 0x74);
#else
    BYTE *peb = (BYTE *)__readfsdword(0x30);
    BYTE *heap = *(BYTE **)(peb + 0x18);
    // HEAP.Flags at offset 0x40 (x86, Windows 10+)
    DWORD flags = *(DWORD *)(heap + 0x40);
    // HEAP.ForceFlags at offset 0x44 (x86, Windows 10+)
    DWORD force_flags = *(DWORD *)(heap + 0x44);
#endif

    // HEAP_GROWABLE = 0x2 — normal without debugger
    // With debugger, additional flags are set (HEAP_TAIL_CHECKING_ENABLED, etc.)
    if (flags != 0x2)
        return 1;

    // ForceFlags should be 0 without debugger
    if (force_flags != 0)
        return 1;

    // Also check NtGlobalFlag in PEB (offset 0xBC on x64, 0x68 on x86)
#ifdef _WIN64
    DWORD nt_global_flag = *(DWORD *)(peb + 0xBC);
#else
    DWORD nt_global_flag = *(DWORD *)(peb + 0x68);
#endif
    // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    if (nt_global_flag & 0x70)
        return 1;

    return 0;
}

#endif
