# Reverse Engineering EDR Products: A Bypass Discovery Methodology

A systematic guide to analyzing EDR internals, identifying detection gaps, and discovering
new bypass techniques. Covers static analysis of kernel drivers and usermode DLLs, dynamic
analysis with debuggers and tracers, gap analysis methodology, and the open-source tool
ecosystem for EDR research.

---

## Table of Contents

1. [Static Analysis of EDR Kernel Drivers](#1-static-analysis-of-edr-kernel-drivers)
2. [Static Analysis of EDR Usermode DLLs](#2-static-analysis-of-edr-usermode-dlls)
3. [Dynamic Analysis Techniques](#3-dynamic-analysis-techniques)
4. [Finding New Bypass Vectors](#4-finding-new-bypass-vectors)
5. [Open Source Tools for EDR Analysis](#5-open-source-tools-for-edr-analysis)
6. [Setting Up an EDR Research Lab](#6-setting-up-an-edr-research-lab)
7. [Case Studies: Published EDR Reversing Research](#7-case-studies-published-edr-reversing-research)

---

## 1. Static Analysis of EDR Kernel Drivers

EDR products install one or more kernel drivers (`.sys` files) that register callbacks,
minifilter operations, and ETW consumers. Reversing these drivers reveals exactly what
the EDR monitors — and more importantly, what it does NOT monitor.

### 1.1 Tools and Setup

**Ghidra** (free, NSA): Best for batch analysis and scripting. The `WindowsDriverAnalyzer`
plugin auto-identifies DriverEntry, IRP dispatch tables, and IOCTL handlers. Use the
Ghidra headless analyzer for scripted batch processing of multiple EDR driver versions.

**IDA Pro** (commercial): Superior type reconstruction and FLIRT signatures for Windows
kernel APIs. The `WDK` type library (`ntddk.h`, `wdm.h`, `fltkernel.h`) is essential —
import it before analysis. IDA's pseudocode is generally cleaner for kernel code.

**Binary Ninja** (commercial): Good intermediate option. The `binja-msdn` plugin
auto-annotates Windows API calls with parameter names.

**Essential type libraries to import:**
```
ntddk.h          — kernel-mode base types and routines
wdm.h            — Windows Driver Model types
fltkernel.h      — Minifilter framework types (FLT_REGISTRATION, etc.)
ntifs.h          — NT filesystem and security types
wsk.h            — Winsock Kernel (network filtering)
```

### 1.2 Finding Kernel Callback Registrations

Every EDR driver registers callbacks in its `DriverEntry` or an initialization routine
called from `DriverEntry`. Search for these function imports:

#### Process Callbacks

```
PsSetCreateProcessNotifyRoutine          — Legacy, basic process create/exit
PsSetCreateProcessNotifyRoutineEx        — Extended, includes PS_CREATE_NOTIFY_INFO
PsSetCreateProcessNotifyRoutineEx2       — Win10+, richest info (PSCREATETHREADNOTIFYTYPE)
```

In the disassembly, the callback function pointer is the first argument. Rename it
immediately — this is the function the EDR calls for every process creation. Its
`PS_CREATE_NOTIFY_INFO` parameter reveals what data the EDR inspects:

- `FileOpenNameAvailable` — does the EDR check the image file path?
- `ImageFileName` — the full NT path
- `CommandLine` — does the EDR log command-line arguments?
- `CreationStatus` — can the EDR block process creation (by setting STATUS_ACCESS_DENIED)?

**Key question**: Does the EDR set `CreationStatus` to block suspicious processes, or does
it only log and alert? If it only logs, there's a detection-to-response latency window.

#### Thread Callbacks

```
PsSetCreateThreadNotifyRoutine           — Legacy thread create/exit
PsSetCreateThreadNotifyRoutineEx         — Extended, includes thread start address
```

The extended variant receives `PS_CREATE_THREAD_NOTIFY_INFO` with the thread's start
address. EDRs use this to detect remote thread injection — a thread starting at an
address outside any loaded module is suspicious. But they also generate false positives
on legitimate JIT engines (CLR, V8, LuaJIT).

**Bypass implication**: If you can make your injected thread's start address point inside
a legitimate module (e.g., `ntdll!RtlUserThreadStart`), the start address check passes.
This is the basis of threadless injection techniques.

#### Image Load Callbacks

```
PsSetLoadImageNotifyRoutine              — Called for every DLL/EXE load
PsSetLoadImageNotifyRoutineEx            — Extended version (Windows 10+)
```

The callback receives `PIMAGE_INFO` with the image base address, size, and full path.
EDRs use this to:
- Detect DLL sideloading (unexpected DLL in application directory)
- Monitor for known malicious DLL names/hashes
- Inject their own hooking DLL (the image load callback for their own DLL is how they know when to install hooks)

**Bypass implication**: Manual mapping (loading a DLL without calling `LdrLoadDll`) does
NOT trigger this callback because the kernel's image loader is bypassed entirely.

#### Object Callbacks

```
ObRegisterCallbacks                      — Monitor/block handle operations
```

This is one of the most powerful EDR mechanisms. It registers pre- and post-operation
callbacks for process and thread handle operations. The `OB_OPERATION_REGISTRATION`
structure specifies:

- `ObjectType`: `PsProcessType` or `PsThreadType`
- `Operations`: `OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE`
- `PreOperation`: Called BEFORE the handle is granted
- `PostOperation`: Called AFTER

In the `PreOperation` callback, the EDR can strip handle access rights. For example,
when a process opens a handle to `lsass.exe` with `PROCESS_VM_READ`, the EDR can remove
that access right, causing credential dumping to fail silently.

**To find what the EDR protects**: Reverse the PreOperation callback and look for PID/
process name comparisons. You'll find the protected process list (typically lsass.exe,
csrss.exe, the EDR's own processes).

**Bypass implication**: ObRegisterCallbacks only fires for `NtOpenProcess`/`NtDuplicateObject`.
If you already have a handle (inherited, or obtained before the EDR loaded), the callback
doesn't apply. Also, kernel-mode code can call `PsLookupProcessByProcessId` + `KeStackAttachProcess`
to access another process's memory without needing a handle at all.

#### Registry Callbacks

```
CmRegisterCallbackEx                     — Monitor/block registry operations
```

EDRs use this to detect persistence mechanisms (Run keys, services, scheduled tasks
written via registry) and tampering with EDR's own registry configuration. The callback
receives `REG_NOTIFY_CLASS` indicating the operation type (create key, set value, delete
key, etc.) and the full key path.

**Finding the EDR's self-protection**: Search the callback for string comparisons against
the EDR's own service name, registry key paths, and configuration values. This reveals
what registry modifications the EDR blocks — and what it doesn't check.

### 1.3 Reversing Minifilter Pre/Post-Operation Callbacks

EDR minifilter drivers register via `FltRegisterFilter` with a `FLT_REGISTRATION`
structure. This structure contains an array of `FLT_OPERATION_REGISTRATION` entries,
each specifying an IRP major function code and pre/post callbacks:

```c
typedef struct _FLT_OPERATION_REGISTRATION {
    UCHAR                            MajorFunction;    // IRP_MJ_CREATE, IRP_MJ_WRITE, etc.
    FLT_OPERATION_REGISTRATION_FLAGS Flags;
    PFLT_PRE_OPERATION_CALLBACK      PreOperation;     // Called before I/O completes
    PFLT_POST_OPERATION_CALLBACK     PostOperation;    // Called after I/O completes
    PVOID                            Reserved1;
} FLT_OPERATION_REGISTRATION;
```

**Critical IRP codes EDRs monitor:**

| IRP Code | Purpose | EDR Use |
|----------|---------|---------|
| `IRP_MJ_CREATE` | File open/create | Detect access to sensitive files (SAM, ntds.dit, shadow copies) |
| `IRP_MJ_WRITE` | File write | Detect dropper activity, detect writes to startup folders |
| `IRP_MJ_SET_INFORMATION` | Rename/delete | Detect file deletion (cleanup behavior), detect rename-based evasion |
| `IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION` | Memory-mapped file | Detect process hollowing (section mapping of PE files) |
| `IRP_MJ_NETWORK_QUERY_OPEN` | Fast network open | Network file access monitoring |

**To find the EDR's file monitoring scope**: Reverse each PreOperation callback. Look
for path comparisons — the EDR checks if the target path matches sensitive locations.
Common protected paths:
- `\Windows\System32\config\SAM` — credential database
- `\Windows\NTDS\ntds.dit` — Active Directory database
- `\Windows\System32\lsass.exe` — credential process
- Shadow copy paths (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy*`)

**Bypass implication**: If the EDR only checks specific paths, accessing the same data
through alternative paths (e.g., using NtCreateFile with `\??\C:\` vs `\DosDevices\C:\`,
or accessing via volume GUID path instead of drive letter) may bypass the check.

### 1.4 Analyzing IOCTL Dispatchers

The EDR's usermode agent communicates with its kernel driver through DeviceIoControl
calls (IOCTLs). The driver's IRP_MJ_DEVICE_CONTROL handler dispatches based on
IOCTL control codes.

**Finding the dispatch table**: In IDA/Ghidra, find the `DriverEntry` → `IoCreateDevice`
→ `IRP_MJ_DEVICE_CONTROL` handler chain. The handler typically has a large switch/case
on `IoStackLocation->Parameters.DeviceIoControl.IoControlCode`.

**Common IOCTL patterns:**

```
IOCTL_GET_EVENTS       — Usermode agent polls for kernel events
IOCTL_SET_CONFIG       — Agent sends configuration updates
IOCTL_BLOCK_PROCESS    — Agent tells driver to block a specific PID
IOCTL_SCAN_RESULT      — Agent sends back scan verdict for a file
IOCTL_HEARTBEAT        — Agent health check
```

**Why this matters**: Some EDRs make blocking decisions in usermode, not kernel. The
kernel driver collects telemetry and buffers events; the usermode agent processes them
and sends back a verdict. If you kill/crash the usermode agent, pending events may be
lost, and no blocking occurs until the agent restarts.

**Vulnerability hunting**: IOCTL handlers are a rich source of kernel vulnerabilities.
Input validation bugs (buffer overflows, integer overflows, type confusion) in IOCTL
handlers can give you kernel code execution — which means full EDR bypass. Check:
- Is `InputBufferLength` validated before accessing `InputBuffer`?
- Are pointer parameters probed with `ProbeForRead`/`ProbeForWrite`?
- Are IOCTL methods `METHOD_BUFFERED` (safer) or `METHOD_NEITHER` (raw pointers)?

### 1.5 Finding ETW Provider Registrations

Kernel ETW providers are registered with `EtwRegister` or `IoRegisterCallbackForPowerSetting`.
The provider GUID identifies what events the driver produces.

**Important EDR-relevant kernel providers:**

| Provider GUID | Name | Data |
|---------------|------|------|
| `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}` | Microsoft-Windows-Kernel-Process | Process/thread/image events |
| `{EDD08927-9CC4-4E65-B970-C2560FB5C289}` | Microsoft-Windows-Kernel-File | File create/delete/rename |
| `{F4AED7C7-A898-4627-B053-44A7CAA12FCD}` | Microsoft-Windows-Threat-Intelligence | Sensitive API calls (NtAllocateVirtualMemory with RWX, process injection APIs) |
| `{A68CA8B7-004F-D7B6-A698-04740DE7F73E}` | Microsoft-Windows-Kernel-Network | Network connections |
| `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}` | Microsoft-Windows-DNS-Client | DNS resolution |

**ETW-TI (Threat Intelligence)** is the most important provider for EDRs. It's a
kernel-mode-only provider that requires a PPL (Protected Process Light) consumer.
Only processes signed with the `WinTcb` or `Antimalware` signer can consume ETW-TI
events. This is why EDR agents run as PPL.

ETW-TI provides events for:
- `NtAllocateVirtualMemory` with `PAGE_EXECUTE_*` permissions
- `NtProtectVirtualMemory` adding execute permissions
- `NtMapViewOfSection` with execute permissions
- `NtWriteVirtualMemory` into remote processes
- `NtQueueApcThread` (APC injection)
- `NtSetContextThread` (thread context manipulation)
- `SetThreadContext` (debug register manipulation)

**Bypass implication**: ETW-TI operates at the syscall level. If you use indirect
syscalls to call `NtAllocateVirtualMemory`, the ETW-TI event still fires because
the kernel generates it. Usermode ETW patching does NOT affect ETW-TI. You need
kernel-level access (BYOVD, callback removal) to disable ETW-TI.

---

## 2. Static Analysis of EDR Usermode DLLs

### 2.1 Identifying the Hooking Engine

Most EDRs inject a DLL into every process. This DLL hooks ntdll.dll functions (and
sometimes kernel32/kernelbase) to intercept API calls before they reach the kernel.

**Finding the EDR DLL**: Look in `C:\Program Files\<EDR Vendor>\` for DLLs with names like:
- CrowdStrike: `CsFalconDll64.dll`
- SentinelOne: `SentinelAgentDll.dll` / `InProcessClient64.dll`
- Elastic: No injected DLL (uses kernel callbacks + ETW only)
- Defender: `MpClient.dll` (for AMSI), but MDE relies on kernel telemetry
- Carbon Black: `cbk.dll` / `cbsensor.dll`

**How the DLL gets loaded**: Multiple mechanisms:
1. **AppInit_DLLs**: Registry key that loads a DLL into every process. Easy to bypass (set `LoadAppInit_DLLs` to 0 before starting your process).
2. **Image File Execution Options (IFEO)**: Debugger attachment mechanism. Can be detected.
3. **CIG (Code Integrity Guard)**: Process-level enforcement that only allows Microsoft-signed DLLs. EDRs with CIG-enabled processes can't be hooked by other EDRs, but their own DLL is typically added to the allowed list.
4. **Kernel APC injection**: The kernel driver queues a usermode APC to `LdrLoadDll` in the target process during process initialization. This is the most common method and hardest to block from usermode.

### 2.2 Reversing the Hook Installation

The EDR DLL's `DllMain` (or an initializer called from it) walks the ntdll export table
and installs inline hooks (detours) on selected functions.

**Trampoline pattern** (most common):
```asm
; Original function start (before hooking):
4C 8B D1              mov r10, rcx         ; NtAllocateVirtualMemory prologue
B8 18 00 00 00        mov eax, 0x18        ; syscall number
0F 05                 syscall
C3                    ret

; After EDR hooks it:
E9 xx xx xx xx        jmp <edr_hook>       ; 5-byte relative jump to hook function
90                    nop                   ; padding (original was 3 bytes for mov r10,rcx)
90                    nop
0F 05                 syscall              ; leftover bytes
C3                    ret
```

**Finding the hooked functions list**: The hook installer typically iterates an array
of function name strings or hashes. Search for:
- An array of string pointers to ntdll function names ("NtAllocateVirtualMemory", "NtWriteVirtualMemory", etc.)
- A hash computation loop (DJB2, CRC32, or custom) comparing against a hash table
- Calls to `GetProcAddress(ntdll, ...)` in a loop

**Documenting the hook list is critical**: This tells you exactly which API calls the
EDR monitors via usermode hooks. Any ntdll function NOT in this list is unhooked and
can be called freely.

### 2.3 Understanding the Hook Flow

When a hooked function is called, execution flows:

```
Application calls NtAllocateVirtualMemory()
    → JMP to EDR hook function
        → EDR logs: caller address, arguments (ProcessHandle, BaseAddress, Size, Protect)
        → EDR checks: Is Protect == PAGE_EXECUTE_READWRITE? Is ProcessHandle != -1 (remote)?
        → EDR verdict: Allow / Block / Log+Alert
        → If allowed: Call original function via trampoline (saved original bytes)
            → Original syscall executes
            → Return to EDR hook
        → EDR post-processing: Log return value, allocated address
    → Return to application
```

**Reversing the verdict logic**: In the hook function, find the decision point. It's
usually a call to a shared "decision engine" function that takes the API name, arguments,
and caller context, and returns allow/block/alert. This decision engine is the EDR's
brain — reversing it reveals the detection rules.

**Finding the trampoline**: The hook function must call the original API to forward
legitimate calls. Look for an indirect call/jump to a dynamically computed address.
The trampoline is a small code stub in EDR-allocated memory that contains the overwritten
original bytes followed by a jump back to the original function (after the hook).

---

## 3. Dynamic Analysis Techniques

### 3.1 Kernel Debugging with WinDbg

**Setup**: Two VMs — debugger host and target with EDR installed. Connect via network
(KDNET) or named pipe. Enable kernel debugging on the target:

```
bcdedit /debug on
bcdedit /dbgsettings net hostip:<debugger_ip> port:50000 key:<key>
```

**Useful WinDbg commands for EDR analysis:**

```
!drvobj <driver_name> 2            — Show all IRP dispatch routines
!minifilter                        — List all registered minifilters with altitudes
!fltkd.filters                     — Detailed minifilter information
!callback                          — List all kernel callback routines (process, thread, image)
!reg callbacks                     — List CmRegisterCallback registrations
dt nt!_KTHREAD @$thread            — Examine current thread structure
!object \Callback                  — List kernel callback objects
lm m <driver>                      — List loaded EDR driver modules
bp <address>                       — Set breakpoint in EDR driver code
```

**Enumerating ALL registered callbacks:**
```
!callback PsSetCreateProcessNotifyRoutine
!callback PsSetCreateThreadNotifyRoutine
!callback PsSetLoadImageNotifyRoutine
!fltkd.filters                     — Minifilter registrations
!reg callbacks                     — Registry callbacks
!obcallback                        — ObRegisterCallbacks registrations
```

This gives you a complete picture of what the EDR registers at the kernel level.

### 3.2 Using ETW to Monitor the EDR

Ironic but effective: use ETW to trace the EDR's own activity.

**Trace the EDR's kernel driver:**
```powershell
# Start a trace session capturing kernel events from the EDR driver
logman create trace EDRTrace -p "Microsoft-Windows-Kernel-Process" -o edr_trace.etl
logman start EDRTrace
# ... do suspicious activity ...
logman stop EDRTrace
# Parse with Windows Performance Analyzer (WPA) or TraceRpt
tracerpt edr_trace.etl -o edr_report.xml
```

**Trace the EDR's usermode agent:**
```powershell
# Use Process Monitor (ProcMon) to capture all file, registry, network, and
# process activity of the EDR agent process
# Filter: ProcessName contains "CsFalcon" or "SentinelAgent" etc.
```

**Use SilkETW / Sealighter** for real-time ETW monitoring:
```
SilkETW.exe -t user -pn "Microsoft-Windows-Threat-Intelligence" -l verbose
```
Note: ETW-TI requires PPL, so this only works if you run as PPL yourself or patch the
provider's security descriptor.

### 3.3 API Monitor and Frida for Usermode Analysis

**API Monitor**: Configure to hook the EDR DLL itself. Watch:
- What functions the EDR DLL calls internally
- What data it sends to the kernel driver (DeviceIoControl calls)
- What data it sends to the cloud (WinHTTP/WinInet calls)
- What ETW events it generates

**Frida**: Attach to a process with the EDR DLL loaded, then:
```javascript
// List all hooks the EDR installed
var ntdll = Process.getModuleByName("ntdll.dll");
ntdll.enumerateExports().forEach(function(exp) {
    var addr = exp.address;
    var firstByte = Memory.readU8(addr);
    if (firstByte == 0xE9 || firstByte == 0xFF) {
        console.log("HOOKED: " + exp.name + " at " + addr);
    }
});

// Trace a specific hooked function to see what the EDR does
Interceptor.attach(Module.getExportByName("ntdll.dll", "NtAllocateVirtualMemory"), {
    onEnter: function(args) {
        console.log("NtAllocateVirtualMemory called");
        console.log("  ProcessHandle: " + args[0]);
        console.log("  Protect: " + args[4]);
        // Check if we're in the EDR hook or the real function
        var retAddr = this.returnAddress;
        var edrModule = Process.findModuleByName("CsFalconDll64.dll");
        if (edrModule && retAddr >= edrModule.base && retAddr < edrModule.base.add(edrModule.size)) {
            console.log("  → Return goes to EDR hook!");
        }
    }
});
```

### 3.4 Process Monitor for EDR Behavioral Analysis

Run Procmon and filter on the EDR agent process name. Observe:
- **File access patterns**: What files does the EDR scan, and when? (triggers: process start, file write, periodic scan)
- **Registry monitoring**: What registry keys does the EDR watch for changes?
- **Network activity**: How often does the agent phone home? What data does it send?
- **IPC patterns**: Named pipe or ALPC communication between EDR components

**Key insight**: Procmon reveals the EDR's scanning triggers. If the EDR only scans
files when they're written (IRP_MJ_WRITE), then a file that already exists on disk
(pre-staged before EDR was installed, or placed during an EDR update window) may
never be scanned.

---

## 4. Finding New Bypass Vectors

### 4.1 Gap Analysis: What's NOT Hooked

The most reliable way to find bypass opportunities:

1. **Export the full ntdll export table** (all ~2000 exports)
2. **Identify which functions the EDR hooks** (via Frida scan or static analysis)
3. **Diff**: Functions NOT hooked are potential bypass vectors

```python
# Example gap analysis script
import pefile

ntdll = pefile.PE("C:\\Windows\\System32\\ntdll.dll")
all_exports = set()
for exp in ntdll.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name:
        all_exports.add(exp.name.decode())

hooked_functions = set([
    "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx",
    "NtProtectVirtualMemory", "NtMapViewOfSection", "NtOpenProcess",
    # ... add all hooked functions from EDR analysis ...
])

unhooked = all_exports - hooked_functions
nt_unhooked = [f for f in unhooked if f.startswith("Nt") or f.startswith("Zw")]
print(f"Unhooked Nt/Zw functions: {len(nt_unhooked)}")
for f in sorted(nt_unhooked):
    print(f"  {f}")
```

**Common gaps found in real EDRs:**
- `NtCreateSection` + `NtMapViewOfSection` (with non-execute then later protect RWX) — some EDRs only check the initial protection
- `NtSuspendThread` / `NtResumeThread` — used in process hollowing but not always hooked
- `NtQueueApcThread` — some EDRs hook it for remote process injection but not for self-injection
- `RtlCreateUserThread` — alternative to `NtCreateThreadEx`, sometimes unhoooked
- `NtCreateWorkerFactory` — thread pool creation, rarely monitored
- `NtSetInformationProcess` — used for various process manipulation, partially hooked

### 4.2 Timing Analysis

EDR hooks add latency. Measure it:

```c
LARGE_INTEGER freq, start, end;
QueryPerformanceFrequency(&freq);

// Measure hooked call
QueryPerformanceCounter(&start);
for (int i = 0; i < 10000; i++)
    NtAllocateVirtualMemory(GetCurrentProcess(), &base, 0, &sz, MEM_COMMIT, PAGE_READWRITE);
QueryPerformanceCounter(&end);
double hooked_ns = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1e9 / 10000;

// Compare with direct syscall (unhook or indirect)
// ... same measurement with indirect syscall ...
```

**Why this matters**: If the hook adds significant latency (>1us per call), the EDR
may not hook high-frequency APIs. Also, the hook processing itself may have race
conditions — two threads calling the same hooked function simultaneously may confuse
the EDR's internal state tracking.

### 4.3 Fuzzing EDR IOCTL Interfaces

EDR kernel drivers accept IOCTLs from their usermode agent. These IOCTL handlers are
kernel code parsing usermode-supplied data — a prime target for vulnerabilities.

**Approach:**
1. Reverse the IOCTL dispatch table (Section 1.4)
2. Document each IOCTL code, expected input buffer format, and size
3. Send malformed IOCTLs (wrong size, null pointers, extreme values)
4. Monitor with kernel debugger for crashes/BSODs

```c
// IOCTL fuzzer skeleton
HANDLE hDevice = CreateFileA("\\\\.\\<EDR_Device>", GENERIC_READ | GENERIC_WRITE,
                              0, NULL, OPEN_EXISTING, 0, NULL);

for (DWORD ioctl = 0x220000; ioctl < 0x230000; ioctl += 4) {
    char buf[4096];
    memset(buf, 'A', sizeof(buf));
    DWORD out;
    DeviceIoControl(hDevice, ioctl, buf, sizeof(buf), buf, sizeof(buf), &out, NULL);
    // If we survive, the IOCTL was handled without crashing
    // Try again with different buffer sizes: 0, 1, 4, 8, 0x10000, 0xFFFFFFFF
}
```

**Historical results**: Multiple EDR vendors have had IOCTL vulnerabilities that led
to local privilege escalation or arbitrary kernel code execution. CrowdStrike CVE-2023-29362
(local privilege escalation in csagent.sys), SentinelOne CVE-2022-37969 (CLFS driver
abuse via EDR's own driver), etc.

### 4.4 Configuration Analysis

EDRs ship with default configurations that may leave gaps:

**What to check:**
- **Prevention vs Detection mode**: Many EDRs default to "detect only" mode for certain
  threat categories, meaning they alert but don't block
- **Exclusion paths**: Check for default exclusions (some EDRs exclude `C:\Windows\Temp\`,
  `%APPDATA%\`, or specific development tool directories)
- **Cloud dependency**: What features require cloud connectivity? Run the EDR with no
  internet and test again
- **Performance profiles**: "Low impact" mode disables some scanning features
- **Script control**: Is PowerShell/cmd/wscript blocking enabled by default?

**Finding the configuration:**
```
reg query "HKLM\SOFTWARE\<EDR_Vendor>" /s
dir "C:\ProgramData\<EDR_Vendor>\config*" /s
```

### 4.5 Cross-EDR Comparison

A technique detected by EDR-A but not EDR-B reveals a detection gap in EDR-B:

| Technique | CrowdStrike | Defender | SentinelOne | Elastic |
|-----------|-------------|----------|-------------|---------|
| Manual DLL mapping | Detected | Detected | Missed | Missed |
| NtCreateWorkerFactory injection | Missed | Missed | Missed | Missed |
| COM object execution | Partial | Missed | Missed | Missed |
| WMI permanent consumer | Detected | Detected | Partial | Missed |
| Scheduled task via COM | Detected | Partial | Missed | Missed |

Build this matrix empirically by testing each technique against each EDR in your lab.

---

## 5. Open Source Tools for EDR Analysis

### 5.1 EDR Subversion Tools

**EDRSandblast** (GitHub: wavestone-cdt/EDRSandblast)
- Removes kernel callbacks (process, thread, image load, object, registry)
- Unloads minifilter instances
- Uses BYOVD (vulnerable driver) for kernel access
- Supports multiple vulnerable drivers (RTCore64.sys, DBUtil_2_3.sys)
- Status (2025): Core technique still works, but the specific vulnerable drivers
  are increasingly blocked by HVCI/driver blocklist

**EDRSilencer** (GitHub: netero1010/EDRSilencer)
- Blocks EDR network traffic using WFP (Windows Filtering Platform)
- Identifies EDR process network connections and creates WFP filter rules to block them
- Prevents cloud-based detections without killing the EDR process
- Status (2025): Effective, but some EDRs detect WFP filter installation as tampering

**Backstab** (GitHub: Yaxser/Backstab)
- Kills EDR protected processes using a vulnerable process handle from a driver
- Uses the BYOVD technique to open a handle to the EDR process with full access
- Status (2025): Works against non-PPL EDR processes, PPL processes require additional work

**CallbackHell** (GitHub: uf0/CallbackHell)
- Lists and removes kernel callbacks from usermode
- Uses a vulnerable driver to read/write kernel memory
- Can enumerate all PsSetCreateProcessNotifyRoutine callbacks and patch them out

### 5.2 Syscall Tools

**SysWhispers3** (GitHub: klezVirus/SysWhispers3)
- Generates header/asm files for direct and indirect syscalls
- Supports multiple calling conventions and evasion techniques
- Egg-hunter mode: finds SSNs at runtime by scanning ntdll
- Status (2025): The generated code patterns are increasingly signatured;
  custom implementations preferred

**HellsGate** (GitHub: am0nsec/HellsGate)
- Runtime SSN resolution by reading ntdll syscall stubs in memory
- Works even when ntdll is hooked (reads the SSN bytes directly)
- Pattern: `4C 8B D1 B8 xx xx 00 00` — extracts xx xx as SSN

**HalosGate** (GitHub: trickster0/HalosGate)
- Extension of HellsGate that handles hooked ntdll stubs
- If the target function's prologue is overwritten (hooked), it looks at
  neighboring syscall stubs and calculates the SSN by offset
- Neighbor ± 1 = SSN ± 1

**TartarusGate**
- Further extension: if multiple neighbors are hooked, searches wider range
- Walks up and down the syscall stub table until finding an unhooked stub
- Calculates target SSN from the found SSN and offset

### 5.3 PPL Tools

**PPLdump** (GitHub: itm4n/PPLdump)
- Dumps memory of PPL (Protected Process Light) processes
- Exploits the `KnownDlls` directory object to load a custom DLL into a PPL
- Status (2025): Patched in recent Windows versions (PPL now validates DLL origin)

**PPLFault** (GitHub: gabriellandau/PPLFault)
- Exploits TOCTOU in PPL's DLL signature verification
- Races the signature check by swapping the DLL file between check and load
- Uses `NtCreateSection` + `NtMapViewOfSection` timing
- Status (2025): Patched but variant techniques continue to emerge

**PPLmedic** (GitHub: itm4n/PPLmedic)
- Uses a different approach: exploits the ELAM (Early Launch Anti-Malware) driver
  registration to get PPL access
- Status (2025): Partially patched, but ELAM-based techniques evolve

### 5.4 Telemetry Analysis Tools

**TelemetrySourcerer** (GitHub: jthuraisamy/TelemetrySourcerer)
- Lists all ETW providers registered on the system
- Shows which processes consume which ETW providers
- Identifies EDR-specific ETW consumers
- Can disable specific ETW providers at runtime

**SilkETW** (GitHub: mandiant/SilkETW)
- C# ETW tracing framework
- Enables subscribing to any ETW provider and logging events in JSON
- Useful for understanding what telemetry an EDR generates
- Can be used to verify whether your evasion technique successfully blinds ETW

**Sealighter** (GitHub: pathtofile/Sealighter)
- ETW consumer focused on security-relevant providers
- Subscribes to the same providers as Defender/EDRs
- Shows you exactly what the EDR would see for a given action
- Useful for pre-testing: run your payload with Sealighter watching, and see
  what telemetry events fire

---

## 6. Setting Up an EDR Research Lab

### 6.1 VM Architecture

**Minimum setup:**
```
┌─────────────────────────────────────────────┐
│  Host: Linux (KVM/QEMU or VMware Workstation) │
│                                               │
│  ┌─────────────┐  ┌─────────────┐            │
│  │ Windows 11  │  │ Windows 11  │            │
│  │ + EDR-A     │  │ + EDR-B     │            │
│  │ (CrowdStrike│  │ (SentinelOne│            │
│  │  Falcon)    │  │  Agent)     │            │
│  └─────────────┘  └─────────────┘            │
│  ┌─────────────┐  ┌─────────────┐            │
│  │ Windows 11  │  │ Windows 11  │            │
│  │ + EDR-C     │  │ No EDR      │            │
│  │ (Elastic    │  │ (Baseline)  │            │
│  │  Defend)    │  │             │            │
│  └─────────────┘  └─────────────┘            │
└─────────────────────────────────────────────┘
```

**Snapshot strategy**: Take snapshots at key states:
1. `clean_install` — Fresh Windows, no EDR
2. `edr_installed` — EDR installed and running, no test artifacts
3. `pre_test` — Ready for testing (tools deployed, monitoring configured)

**EDR trial licenses:**
- Elastic Defend: Free tier available, full features for 30 days
- CrowdStrike Falcon: Free trial requires business email
- SentinelOne: Partners sometimes offer trial licenses
- Microsoft Defender for Endpoint: Part of M365 E5 trial (30 days)

### 6.2 Baseline with No EDR

Before testing with an EDR, establish a behavioral baseline:
1. Run Procmon, capture all system activity during payload execution
2. Run API Monitor, log all API calls the payload makes
3. Record: process tree, network connections, file writes, registry modifications
4. This baseline shows what the EDR would see

### 6.3 Atomic Red Team for Coverage Testing

Atomic Red Team provides individual test cases mapped to MITRE ATT&CK techniques:

```powershell
# Install
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)

# Run a specific technique
Invoke-AtomicTest T1003.001 -TestNumbers 1    # LSASS credential dumping
Invoke-AtomicTest T1059.001 -TestNumbers 1    # PowerShell execution
Invoke-AtomicTest T1055.012 -TestNumbers 1    # Process hollowing

# Check if EDR alerted
# ... check EDR console ...
```

**Build a coverage matrix**: Run all relevant ATT&CK techniques, record which ones
the EDR detects vs misses. This gives you an empirical detection rate and reveals
the weakest areas to target.

### 6.4 Automated Bypass Testing

Build a CI/CD-style pipeline for bypass testing:

```python
# bypass_tester.py — pseudocode
class BypassTest:
    def __init__(self, name, payload_path, expected_behavior):
        self.name = name
        self.payload = payload_path
        self.expected = expected_behavior

    def run(self, vm):
        # 1. Restore VM snapshot
        vm.restore_snapshot("edr_installed")

        # 2. Deploy payload
        vm.upload(self.payload, "C:\\Users\\test\\Desktop\\payload.exe")
        time.sleep(5)  # Wait for real-time scan

        # 3. Check if file survived
        if not vm.file_exists("C:\\Users\\test\\Desktop\\payload.exe"):
            return Result(self.name, "BLOCKED", "Static detection")

        # 4. Execute
        vm.execute("C:\\Users\\test\\Desktop\\payload.exe")
        time.sleep(30)  # Wait for behavioral analysis

        # 5. Check EDR alerts
        alerts = edr_api.get_alerts(last_minutes=5)
        detections = defender_api.get_detections(last_minutes=5)

        # 6. Check payload outcome
        if self.expected == "c2_beacon":
            c2_connected = c2_server.has_beacon(timeout=60)
            return Result(self.name, c2_connected, alerts, detections)
```

This allows you to rapidly test variants: change one evasion parameter, rebuild,
deploy, measure. Over hundreds of iterations, you build an empirical model of what
the EDR detects and what it misses.

---

## 7. Case Studies: Published EDR Reversing Research

### 7.1 CrowdStrike Falcon Analysis

**Key findings from public research (2023-2025):**

- The Falcon sensor's kernel driver (`csagent.sys`) registers all major kernel callbacks
  plus a minifilter at altitude 328010
- Usermode component `CsFalconService.exe` runs as a service and communicates with the
  cloud endpoint via HTTPS
- The "channel file" incident (July 2024) revealed that Falcon uses dynamically-loaded
  detection content files — a buggy content update caused worldwide BSODs
- Falcon hooks approximately 40-50 ntdll functions in usermode, focusing on
  memory manipulation, process/thread management, and file operations
- Does NOT hook: `NtCreateWorkerFactory`, `NtCreateTimer2`, most `Rtl*` functions

### 7.2 SentinelOne Deep Analysis

**Key findings:**

- Uses a "Static AI" engine (pre-execution ML model) and "Behavioral AI" (runtime)
- The Static AI model is a neural network that classifies PE files before execution —
  susceptible to adversarial examples (adding benign features to malicious PE)
- STAR (SentinelOne Threat-level Analysis Rules) are custom detection rules similar
  to YARA — they can be enumerated by analyzing the agent's rule files
- Agent has both cloud and local detection capabilities, but full behavioral analysis
  requires cloud connectivity
- Known gap (2024): COM-based execution (instantiating COM objects for execution) was
  weakly detected because COM doesn't follow normal process-creation paths

### 7.3 Elastic Defend Architecture

**Key findings:**

- Does NOT inject usermode DLLs — relies entirely on kernel callbacks + ETW
- This makes it immune to ntdll unhooking / direct syscall techniques (those only
  bypass usermode hooks, which Elastic doesn't use)
- Primary detection mechanism: kernel ETW consumers + behavioral rules engine
- `endpoint-rules` repository is partially open-source, revealing detection logic
- Known gap (2024-2025): Call stack analysis uses a allowlist of legitimate return
  addresses. If you can spoof your call stack to match legitimate patterns, behavioral
  detections are bypassed (this is the "call gadget bypass" technique)
- Elastic's memory signature scanning runs periodically (not continuously), creating
  windows where malicious code in memory is not detected

### 7.4 Microsoft Defender for Endpoint (MDE)

**Key findings:**

- `WdFilter.sys` is the kernel minifilter (altitude 328010)
- Cloud-delivered protection adds 10-15 seconds of latency for verdict on unknown files
- AMSI (Antimalware Scan Interface) integration scans script content in PowerShell,
  VBScript, JScript, and .NET assemblies
- ASR (Attack Surface Reduction) rules are configurable — many are disabled by default
  in "Audit" mode rather than "Block"
- SmartScreen integrates with the browser for download reputation checks
- Known gap: Cloud-delivered protection requires internet connectivity. In
  air-gapped environments, detection capability drops significantly (local ML
  model only, no cloud behavioral analysis)

---

## Summary: The Research Loop

The most effective EDR bypass research follows an iterative cycle:

```
1. ANALYZE    — Reverse engineer the EDR to understand what it monitors
2. GAP FIND   — Identify what it does NOT monitor
3. HYPOTHESIZE — "If I do X via unmonitored API Y, the EDR won't detect it"
4. BUILD      — Create a minimal PoC that tests the hypothesis
5. TEST       — Run against the EDR in a lab environment
6. MEASURE    — Record: detected/not, alert type, detection latency
7. ITERATE    — If detected, analyze the detection and find a variant
8. DOCUMENT   — Record the bypass for future use
9. REPEAT     — Move to the next gap
```

This systematic approach, rather than ad hoc technique hunting, is how you
build a comprehensive and evolving library of EDR bypass capabilities.
