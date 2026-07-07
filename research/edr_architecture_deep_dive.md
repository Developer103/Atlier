# EDR Architecture Internals: A Deep Technical Reference

This document provides a comprehensive technical analysis of how modern Endpoint Detection
and Response (EDR) systems operate at every architectural layer on Windows. It covers kernel
callbacks, ETW consumers, usermode hooks, minifilter drivers, network filtering, memory
scanning, telemetry pipelines, protected processes, and behavioral detection engines.

All information reflects the state of EDR technology as of 2024-2026.

---

## Table of Contents

1. [Kernel Callbacks](#1-kernel-callbacks)
2. [ETW Consumers](#2-etw-event-tracing-for-windows-consumers)
3. [Usermode Hooks](#3-usermode-hooks)
4. [Minifilter Drivers](#4-minifilter-drivers)
5. [Network Filtering](#5-network-filtering)
6. [Memory Scanning](#6-memory-scanning)
7. [Telemetry Pipeline](#7-telemetry-pipeline)
8. [Protected Processes (PP/PPL)](#8-protected-processes-ppppl)
9. [Behavioral Detection Engine](#9-behavioral-detection-engine)

---

## 1. Kernel Callbacks

Kernel callbacks are the foundation of EDR telemetry. They are registered by kernel-mode
drivers and invoked by the Windows kernel itself whenever specific system events occur.
Because they execute in kernel context, they cannot be trivially subverted from usermode.
Every major EDR product registers most or all of the callback types described below.

### 1.1 Process Creation Callbacks

Three generations of process notification routines exist, each providing progressively
richer information.

#### PsSetCreateProcessNotifyRoutine (Legacy)

The original process notification API, available since Windows 2000. It registers a
callback with the following signature:

```c
typedef VOID (*PCREATE_PROCESS_NOTIFY_ROUTINE)(
    IN HANDLE  ParentId,
    IN HANDLE  ProcessId,
    IN BOOLEAN Create       // TRUE = creation, FALSE = termination
);
```

This variant provides only the parent PID, child PID, and a boolean indicating creation
or deletion. It cannot block process creation. It remains supported for backward
compatibility but provides insufficient data for modern EDR use.

#### PsSetCreateProcessNotifyRoutineEx

Introduced in Windows Vista SP1. The callback receives a pointer to `PS_CREATE_NOTIFY_INFO`,
which provides substantially more context and critically allows the callback to **block
process creation** by setting `CreationStatus` to a failure NTSTATUS.

```c
typedef VOID (*PCREATE_PROCESS_NOTIFY_ROUTINE_EX)(
    IN OUT PEPROCESS              Process,
    IN     HANDLE                 ProcessId,
    IN OUT PPS_CREATE_NOTIFY_INFO CreateInfo  // NULL on process exit
);
```

The `PS_CREATE_NOTIFY_INFO` structure contains:

```c
typedef struct _PS_CREATE_NOTIFY_INFO {
    SIZE_T              Size;
    union {
        ULONG Flags;
        struct {
            ULONG FileOpenNameAvailable : 1;
            ULONG IsSubsystemProcess   : 1;  // WSL process indicator
            ULONG Reserved             : 30;
        };
    };
    HANDLE              ParentProcessId;
    CLIENT_ID           CreatingThreadId;     // Thread that called CreateProcess
    struct _FILE_OBJECT *FileObject;          // File object of the executable image
    PUNICODE_STRING     ImageFileName;        // NT path of the executable
    PUNICODE_STRING     CommandLine;          // Full command line (may be NULL)
    NTSTATUS            CreationStatus;       // Set to failure code to block
} PS_CREATE_NOTIFY_INFO, *PPS_CREATE_NOTIFY_INFO;
```

Key fields for EDR use:
- `ImageFileName`: The NT-format path to the executable image being launched.
- `CommandLine`: The full command-line string, essential for detecting LOLBin abuse,
  encoded commands, or suspicious arguments.
- `CreatingThreadId`: Identifies the specific thread that initiated process creation,
  enabling attribution even when multiple threads in a parent process create children.
- `FileObject`: A pointer to the file object, allowing the EDR to perform additional
  file-level checks (e.g., reading the PE headers, checking signatures) during the callback.
- `CreationStatus`: The EDR can set this to `STATUS_ACCESS_DENIED` or another failure
  code to **prevent the process from starting**. This is the only callback in this family
  that supports blocking.

An important security requirement: the driver binary must have the
`IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` flag set in its PE header, or registration
will fail with `STATUS_ACCESS_DENIED`.

#### PsSetCreateProcessNotifyRoutineEx2

Added in Windows 10 version 1703 (Creators Update). This extends the Ex variant to also
receive notifications for subsystem processes (primarily WSL/Pico processes).

```c
NTSTATUS PsSetCreateProcessNotifyRoutineEx2(
    PSCREATEPROCESSNOTIFYTYPE NotifyType,      // PsCreateProcessNotifySubsystems
    PVOID                     NotifyInformation, // PCREATE_PROCESS_NOTIFY_ROUTINE_EX
    BOOLEAN                   Remove
);
```

The `PSCREATEPROCESSNOTIFYTYPE` enum currently defines:
- `PsCreateProcessNotifySubsystems` (0) -- Receive notifications for both native
  Windows processes and subsystem (WSL) processes.

When `IsSubsystemProcess` is set in the `PS_CREATE_NOTIFY_INFO.Flags`, the process
is a WSL/Pico process. The callback function signature and data structures are
identical to the Ex variant; Ex2 simply expands the scope of which processes trigger
the notification.

#### Internal Implementation

All process creation callbacks are stored in the kernel array
`nt!PspCreateProcessNotifyRoutine`, which holds up to **64 entries**. Each entry is an
`EX_CALLBACK_ROUTINE_BLOCK` pointer, encoded with the low bits used as flags.

When a process is created, `nt!PspCallProcessNotifyRoutines` iterates the array, decodes
each pointer (via bitwise AND to strip the flag bits), and invokes the callback. The
iteration order follows array index order, not registration order.

The callback executes at **IRQL PASSIVE_LEVEL** in the context of the thread that called
`NtCreateUserProcess`. For creation events, it fires after the first thread has been
created but before it begins executing. For deletion events, it fires after the last
thread has terminated and the address space is about to be torn down.

#### EDR Implications

Process creation callbacks are **mandatory** for any EDR. They provide the foundational
telemetry for process tree construction, parent-child relationship tracking, and
command-line logging. Every commercial EDR registers at least the Ex variant. The ability
to block process creation makes this the first line of defense against known-malicious
executables.

### 1.2 Thread Creation Callbacks

#### PsSetCreateThreadNotifyRoutine

Available since Windows 2000. The callback receives minimal information:

```c
typedef VOID (*PCREATE_THREAD_NOTIFY_ROUTINE)(
    IN HANDLE ProcessId,
    IN HANDLE ThreadId,
    IN BOOLEAN Create       // TRUE = creation, FALSE = termination
);
```

This provides only the PID, TID, and a creation/deletion indicator. The kernel stores
these callbacks in the `nt!PspCreateThreadNotifyRoutine` array, with a maximum of **64
entries**.

#### PsSetCreateThreadNotifyRoutineEx

Added in Windows 10 version 1607. This extends the original with the ability to receive
the thread's start address and, on newer builds, Win32 start address information. It
also allows registration as a "non-system" callback that only fires for the registering
driver's processes.

The `PSCREATETHREADNOTIFYTYPE` enum supports:
- `PsCreateThreadNotifyNonSystem` -- Only receive notifications for threads in
  non-system processes.
- `PsCreateThreadNotifySubsystems` -- Receive notifications for subsystem (WSL) threads.

Thread callbacks fire in the context of the newly created thread, at PASSIVE_LEVEL.

#### EDR Use Cases

Thread creation monitoring is critical for detecting:
- **Remote thread injection**: When a thread is created in a process by a different
  process (e.g., `CreateRemoteThread`), the EDR sees a thread appearing in the target
  process with a start address that may point to injected code.
- **Unusual thread start addresses**: Threads starting at addresses within unbacked
  (non-image) memory regions are suspicious.
- **Cross-process thread operations**: The EDR correlates thread creation events with
  process context to detect injection patterns.

### 1.3 Image Load Callbacks

#### PsSetLoadImageNotifyRoutine

Available since Windows 2000. This callback fires whenever any image (EXE, DLL, or
kernel driver) is mapped into virtual memory.

```c
VOID LoadImageNotifyRoutine(
    IN PUNICODE_STRING FullImageName,  // May be NULL
    IN HANDLE          ProcessId,       // 0 for kernel drivers
    IN PIMAGE_INFO     ImageInfo
);
```

The `IMAGE_INFO` structure:

```c
typedef struct _IMAGE_INFO {
    union {
        ULONG Properties;
        struct {
            ULONG ImageAddressingMode  : 8;  // Always IMAGE_ADDRESSING_MODE_32BIT
            ULONG SystemModeImage      : 1;  // 1 = kernel image, 0 = user image
            ULONG ImageMappedToAllPids : 1;  // Mapped to all processes (KnownDlls)
            ULONG ExtendedInfoPresent  : 1;  // IMAGE_INFO_EX available
            ULONG MachineTypeMismatch  : 1;  // Arch mismatch (WoW64)
            ULONG ImageSignatureLevel  : 4;  // SE_SIGNING_LEVEL_*
            ULONG ImageSignatureType   : 3;  // SE_IMAGE_SIGNATURE_TYPE
            ULONG ImagePartialMap      : 1;  // Only partially mapped
            ULONG Reserved             : 12;
        };
    };
    PVOID  ImageBase;                         // Base address in target process
    ULONG  ImageSelector;                     // Always 0
    SIZE_T ImageSize;                         // Size of the mapped image
    ULONG  ImageSectionNumber;                // Always 0
} IMAGE_INFO, *PIMAGE_INFO;
```

When `ExtendedInfoPresent` is set, the structure is embedded in an `IMAGE_INFO_EX`:

```c
typedef struct _IMAGE_INFO_EX {
    SIZE_T              Size;          // sizeof(IMAGE_INFO_EX)
    IMAGE_INFO          ImageInfo;
    struct _FILE_OBJECT *FileObject;   // File object of the image
} IMAGE_INFO_EX, *PIMAGE_INFO_EX;
```

The maximum number of simultaneously registered image load callbacks is **8** (increased
from the original limit). The callback fires at PASSIVE_LEVEL after the image has been
mapped but before its entry point is called. The `FullImageName` parameter may be NULL
if the kernel cannot determine the image path.

These callbacks are stored in `nt!PspLoadImageNotifyRoutine`.

#### EDR Use Cases

Image load callbacks are essential for:
- **DLL load monitoring**: Tracking every DLL loaded into every process enables detection
  of DLL sideloading, unsigned DLL loading, and suspicious module chains.
- **EDR self-injection**: The EDR uses this callback to detect when its own monitoring
  DLL has been loaded (or failed to load) in a target process.
- **Driver load monitoring**: `ProcessId` is 0 for kernel drivers, enabling detection
  of unsigned or suspicious driver loading.
- **Signature verification**: `ImageSignatureLevel` and `ImageSignatureType` provide
  inline signature status without requiring additional verification calls.

### 1.4 Object Handle Callbacks (ObRegisterCallbacks)

`ObRegisterCallbacks` registers pre-operation and post-operation callbacks for object
handle operations. It was introduced in Windows Vista and is one of the most important
EDR callbacks for detecting credential theft and process tampering.

```c
NTSTATUS ObRegisterCallbacks(
    POB_CALLBACK_REGISTRATION CallbackRegistration,
    PVOID                     *RegistrationHandle
);
```

The registration structure:

```c
typedef struct _OB_CALLBACK_REGISTRATION {
    USHORT                    Version;           // OB_FLT_REGISTRATION_VERSION
    USHORT                    OperationRegistrationCount;
    UNICODE_STRING            Altitude;          // Unique altitude string
    PVOID                     RegistrationContext;
    OB_OPERATION_REGISTRATION *OperationRegistration; // Array of registrations
} OB_CALLBACK_REGISTRATION, *POB_CALLBACK_REGISTRATION;
```

Each `OB_OPERATION_REGISTRATION` specifies:

```c
typedef struct _OB_OPERATION_REGISTRATION {
    POBJECT_TYPE                *ObjectType;     // PsProcessType, PsThreadType, or
                                                 // ExDesktopObjectType
    OB_OPERATION               Operations;       // OB_OPERATION_HANDLE_CREATE and/or
                                                 // OB_OPERATION_HANDLE_DUPLICATE
    POB_PRE_OPERATION_CALLBACK  PreOperation;
    POB_POST_OPERATION_CALLBACK PostOperation;
} OB_OPERATION_REGISTRATION, *POB_OPERATION_REGISTRATION;
```

The pre-operation callback receives `OB_PRE_OPERATION_INFORMATION`:

```c
typedef struct _OB_PRE_OPERATION_INFORMATION {
    OB_OPERATION           Operation;
    union {
        ULONG Flags;
        struct {
            ULONG KernelHandle : 1;  // Handle is a kernel handle
            ULONG Reserved     : 31;
        };
    };
    PVOID                  Object;               // Target EPROCESS/ETHREAD
    POBJECT_TYPE           ObjectType;
    PVOID                  CallContext;
    POB_PRE_OPERATION_PARAMETERS Parameters;     // Desired/original access rights
} OB_PRE_OPERATION_INFORMATION, *POB_PRE_OPERATION_INFORMATION;
```

The `Parameters` union contains either `OB_PRE_CREATE_HANDLE_INFORMATION` or
`OB_PRE_DUPLICATE_HANDLE_INFORMATION`, both of which expose:
- `DesiredAccess`: The access rights being requested.
- `OriginalDesiredAccess`: The access rights before any prior callback modified them.

**Crucially, pre-operation callbacks cannot outright deny a handle request**, but they can
modify the `DesiredAccess` field to strip specific rights. For example, an EDR can remove
`PROCESS_VM_READ` from a handle to lsass.exe, effectively preventing credential dumping
even though the handle is still created.

Callbacks are stored in a doubly-linked `CallbackList` within the `_OBJECT_TYPE` structure
for each supported object type (Process, Thread, Desktop).

#### EDR LSASS Protection

The most important use of ObRegisterCallbacks is protecting lsass.exe. When any process
calls `OpenProcess` targeting lsass.exe with rights like `PROCESS_VM_READ`,
`PROCESS_VM_WRITE`, or `PROCESS_ALL_ACCESS`, the EDR's pre-operation callback fires. The
EDR can:

1. Identify the calling process (via `PsGetCurrentProcess`).
2. Check the target process against a list of protected processes (lsass.exe, the EDR's
   own processes, etc.).
3. Strip dangerous access rights from `DesiredAccess`, leaving only benign rights.
4. Log the attempt for telemetry purposes.

This is why most credential dumping tools fail against EDR-protected systems: they never
obtain a handle with sufficient access rights to read lsass.exe memory.

### 1.5 Registry Callbacks (CmRegisterCallbackEx)

```c
NTSTATUS CmRegisterCallbackEx(
    PEX_CALLBACK_FUNCTION Function,
    PCUNICODE_STRING      Altitude,
    PVOID                 Driver,
    PVOID                 Context,
    PLARGE_INTEGER        Cookie,     // Output: unique ID for unregistration
    PVOID                 Reserved
);
```

The callback function receives a `REG_NOTIFY_CLASS` value indicating the operation type
and a pointer to operation-specific data. There are pre-notification and post-notification
variants for most operations.

Key `REG_NOTIFY_CLASS` values monitored by EDRs:

| Value | Operation | EDR Interest |
|-------|-----------|-------------|
| `RegNtPreCreateKeyEx` | Key creation | Persistence (Run keys, services) |
| `RegNtPreOpenKeyEx` | Key open | Reconnaissance |
| `RegNtPreSetValueKey` | Value write | Configuration tampering, persistence |
| `RegNtPreDeleteKey` | Key deletion | Anti-forensics, defense evasion |
| `RegNtPreDeleteValueKey` | Value deletion | Defense evasion |
| `RegNtPreQueryValueKey` | Value read | Credential access |
| `RegNtPreEnumerateKey` | Key enumeration | Discovery |
| `RegNtPreEnumerateValueKey` | Value enumeration | Discovery |

For write operations (`RegNtPreSetValueKey`), the callback data includes:
- The full registry key path.
- The value name being written.
- The data type and data being written.
- The calling process context.

This enables EDRs to detect persistence mechanisms (e.g., writes to
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`), service creation, scheduled
task registration via registry manipulation, and other abuse of registry-based attack
techniques.

Registry callbacks are stored internally in the Configuration Manager's callback list
and are invoked at **PASSIVE_LEVEL**.

### 1.6 Callback Performance Impact

Each callback type imposes overhead on the corresponding system operation:

| Callback Type | Triggers On | Relative Performance Impact |
|---------------|-------------|---------------------------|
| Process creation | Every `NtCreateUserProcess` | Low (processes created infrequently) |
| Thread creation | Every `NtCreateThreadEx` | Low-Medium (more frequent than processes) |
| Image load | Every DLL/EXE map | Medium (high frequency during process init) |
| Object handle | Every `OpenProcess`/`OpenThread` | Medium-High (very high frequency) |
| Registry | Every registry operation | High (extremely frequent, thousands/sec) |
| Minifilter I/O | Every file I/O operation | High (highest frequency of all) |

Object handle and registry callbacks are the most performance-sensitive because they fire
on the most frequent operations. Poorly implemented callbacks in these categories can
measurably degrade system performance.

### 1.7 Mandatory vs. Optional Callbacks

For a functional EDR, the following are effectively **mandatory**:

- **Process creation** (PsSetCreateProcessNotifyRoutineEx/Ex2): Required for process
  tree visibility, command-line logging, and process blocking.
- **Image load** (PsSetLoadImageNotifyRoutine): Required for DLL injection detection
  and for the EDR to inject its own monitoring DLL.
- **Object handle** (ObRegisterCallbacks): Required for LSASS protection and
  cross-process access monitoring.
- **Minifilter** (FltRegisterFilter): Required for file I/O monitoring and
  malware-on-write detection.

The following are **common but optional** (some EDRs skip them or rely on ETW equivalents):

- **Thread creation**: Useful but duplicative with ETW Kernel-Process events.
- **Registry**: Some EDRs use ETW registry providers instead of kernel callbacks for
  lower overhead.

---

## 2. ETW (Event Tracing for Windows) Consumers

ETW is a high-performance, low-overhead tracing facility built into the Windows kernel.
EDRs consume events from multiple ETW providers, both kernel-mode and user-mode. ETW
provides telemetry that complements kernel callbacks and, in some cases, provides data
that callbacks cannot.

### 2.1 ETW Architecture Overview

ETW operates on a **Provider -> Session -> Consumer** model:

- **Providers** generate events. They are identified by GUIDs and can be kernel-mode
  (implemented in ntoskrnl.exe or kernel drivers) or user-mode (implemented in DLLs or
  EXEs). Windows ships with hundreds of built-in providers.
- **Sessions** (also called trace sessions or loggers) are the transport layer. A session
  subscribes to one or more providers and routes events to consumers. Sessions can be
  real-time (events delivered to a callback) or file-based (events written to an ETL file).
- **Consumers** read events from sessions. An EDR's usermode service typically acts as
  a real-time consumer.

Important session types:
- **Real-time sessions**: Events are delivered to consumer callbacks with minimal latency.
  EDRs use this mode for their primary telemetry.
- **AutoLogger sessions**: Configured via the registry key
  `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\<LoggerName>`. These sessions
  start at boot time, before user-mode services, capturing early-boot activity. Provider
  GUIDs are stored as subkeys under the AutoLogger entry.
- **System logger**: The NT Kernel Logger (`SystemTraceControlGuid`) provides kernel-level
  events for process, thread, disk I/O, network, and other system operations.
- **Private loggers**: Sessions private to a single process; events are not visible to
  other processes.

Each session has a buffer pool. Events are written into per-processor buffers and flushed
to consumers asynchronously. Buffer sizes and flush intervals affect latency and the
risk of event loss under high load.

### 2.2 Microsoft-Windows-Threat-Intelligence (EtwTi)

**Provider GUID**: `{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}`

The Threat Intelligence ETW provider is the single most important ETW source for EDRs.
It is unique in several ways:

1. **Kernel-mode instrumentation**: EtwTi events are generated by instrumentation points
   embedded directly in kernel functions (`nt!MiReadWriteVirtualMemory`,
   `nt!MmProtectVirtualMemory`, etc.). They cannot be suppressed by usermode patching.

2. **PPL requirement**: Only processes running as Protected Process Light (PPL) at the
   `Antimalware` signer level or higher can consume EtwTi events. The consumer must be
   associated with an ELAM (Early Launch Anti-Malware) driver.

3. **Tamper-resistant channel**: EtwTi uses a secure ETW channel designed to resist
   usermode tampering. Unlike standard ETW providers where sessions can be stopped or
   providers disabled by administrators, the TI channel has additional protections.

#### EtwTi Event Tasks

Events are categorized into numbered tasks:

| Task ID | Category | Operations Monitored |
|---------|----------|---------------------|
| 1 | Memory allocation | `NtAllocateVirtualMemory` (local and remote) |
| 2 | Memory protection | `NtProtectVirtualMemory` (RWX transitions) |
| 3 | Map view | `NtMapViewOfSection` (section mapping) |
| 4 | APC queue | `NtQueueApcThread` / `NtQueueApcThreadEx` |
| 5 | Thread context | `NtSetContextThread` (register manipulation) |
| 6 | Virtual memory read | `NtReadVirtualMemory` (e.g., LSASS dumping) |
| 7 | Virtual memory write | `NtWriteVirtualMemory` (process injection) |
| 8 | Thread suspend/resume | `NtSuspendThread` / `NtResumeThread` |
| 9 | Process suspend/resume | `NtSuspendProcess` / `NtResumeProcess` |
| 10 | Driver/device | Driver object and device operations |

Each event carries 64-bit keyword bitmasks that distinguish:
- **Local vs. remote operations**: Whether the operation targets the calling process's
  own memory/threads or another process's.
- **Kernel vs. user initiated**: Whether the operation originated from kernel code or
  usermode code.

For example, a remote memory allocation (allocating memory in another process) carries
keyword `0x4`, immediately flagging it as cross-process activity.

#### EDR Detection Use Cases

- **LSASS credential dumping**: `NtReadVirtualMemory` targeting lsass.exe generates a
  Task 6 event with the target process identified.
- **Process injection**: `NtWriteVirtualMemory` + `NtCreateThreadEx` targeting a remote
  process generates Task 7 + thread creation events.
- **Shellcode execution**: `NtAllocateVirtualMemory` with `PAGE_EXECUTE_READWRITE` in
  a remote process generates Task 1 with RWX flags.
- **Hardware breakpoint abuse**: `NtSetContextThread` generates Task 5 events, enabling
  detection of debug register manipulation used for AMSI/ETW patching.

### 2.3 Microsoft-Windows-Kernel-Process

**Provider GUID**: `{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}`

This provider generates events for process and thread lifecycle operations. While
overlapping with kernel callbacks, it provides additional data and fires through a
different mechanism.

Key events:
- **ProcessStart/ProcessStop**: Process creation and termination with image path, PID,
  parent PID, session ID, and creation flags.
- **ThreadStart/ThreadStop**: Thread creation and termination with TID, start address,
  and stack information.
- **ImageLoad**: Image (DLL/EXE) loading with base address, size, image checksum, and
  file path.

EDRs use this provider as a secondary telemetry source to cross-reference with kernel
callbacks and to fill gaps where callbacks might not provide sufficient context.

### 2.4 Microsoft-Windows-Kernel-File

**Provider GUID**: `{edd08927-9cc4-4e65-b970-c2560fb5c289}`

File operation events including creates, reads, writes, renames, and deletes. This
overlaps with minifilter telemetry but uses the ETW transport mechanism.

Useful for EDRs that want file telemetry without deploying a full minifilter driver, or
as a supplementary source.

### 2.5 Microsoft-Windows-Kernel-Registry

**Provider GUID**: `{70eb4f03-c1de-4f73-a051-33d13d5413bd}`

Registry operation events including creates, opens, sets, deletes, and queries. Similar
in scope to `CmRegisterCallbackEx` but delivered via ETW. Some EDRs prefer this over
registry callbacks due to lower performance overhead.

### 2.6 Microsoft-Windows-Kernel-Network / Kernel-Audit-API-Calls

**Kernel-Network GUID**: `{7dd42a49-5329-4832-8dfd-43d979153a88}`

Network events including TCP/UDP connection establishment, data transfer, and connection
teardown. Provides process-correlated network telemetry.

**Kernel-Audit-API-Calls GUID**: `{e02a841c-75a3-4fa7-afc8-ae09cf9b7f23}`

Audits specific API calls, providing an additional layer of visibility into potentially
suspicious system calls.

### 2.7 Microsoft-Windows-DNS-Client

**Provider GUID**: `{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}`

DNS resolution events including query name, query type, response data, and the process
that initiated the resolution. Critical for detecting DNS-based C2 communication,
DNS tunneling, and correlation of network activity with domain names.

### 2.8 Microsoft-Windows-PowerShell / PowerShell

**Provider GUID**: `{a0c1853b-5c40-4b15-8766-3cf1c58f985a}`

PowerShell telemetry including:
- **Script block logging**: The full text of every PowerShell script block executed,
  including dynamically generated code. This is one of the most valuable sources for
  detecting fileless malware and living-off-the-land techniques.
- **Module logging**: Records which PowerShell modules are loaded.
- **Command history**: Records individual commands executed.

Script block logging captures the deobfuscated content of scripts, meaning that even
if a script uses encoding or obfuscation layers, the final executed code is logged.

### 2.9 Microsoft-Windows-DotNETRuntime

**Provider GUID**: `{e13c0d23-ccbc-4e12-931b-d9cc2eee27e4}`

.NET runtime events including:
- **Assembly load**: Assembly name, whether loaded from disk or from a byte array
  (in-memory). A process like powershell.exe loading an assembly named "SharpHound" or
  "Rubeus" via `Assembly.Load(byte[])` is a clear indicator of in-memory .NET tool
  execution.
- **JIT compilation**: Method names being JIT-compiled, useful for identifying specific
  .NET tool functionality.
- **Exception events**: .NET exceptions that may indicate exploitation attempts.
- **GC events**: Garbage collection activity.

### 2.10 AMSI (Antimalware Scan Interface) ETW Provider

**Provider GUID**: `{2a576b87-09a7-520e-c21a-4942f0271d67}`

AMSI captures content submitted for malware scanning from scripting engines (PowerShell,
VBScript, JScript), Office macros, and other AMSI-integrated applications. The ETW
provider logs:
- The content submitted for scanning.
- The scan result (clean, detected, blocked).
- The application that submitted the scan.

Critically, if a script attempts to patch `amsi.dll` in memory, the ETW trace captures
the bypass attempt itself -- including the script content that attempted the bypass --
even if the bypass subsequently succeeds against AMSI's in-process scanning.

### 2.11 Usermode vs. Kernel-Mode Providers

| Characteristic | Kernel-Mode Providers | Usermode Providers |
|---------------|----------------------|-------------------|
| Implementation | ntoskrnl.exe, kernel drivers | User-mode DLLs, EXEs |
| Tampering risk | Low (requires kernel access) | Higher (process memory patching) |
| Performance | Very low overhead | Low overhead |
| Examples | Kernel-Process, Kernel-File, EtwTi | PowerShell, DotNETRuntime, AMSI |
| Access control | Some require PPL (EtwTi) | Generally accessible |

Kernel-mode providers are considered authoritative because they cannot be tampered with
from usermode. Usermode providers are more susceptible to patching (e.g., `EtwEventWrite`
being hooked or NOPed in the target process), which is why EDRs treat kernel-mode ETW
as more trustworthy.

---

## 3. Usermode Hooks

Usermode hooking is the mechanism by which EDRs intercept API calls within each process.
While less tamper-resistant than kernel callbacks or ETW, hooks provide unique visibility
into the parameters and context of API calls at the point of invocation.

### 3.1 Hook Types

#### Inline Hooks (Detours / Trampolines)

The most common hooking technique used by EDRs. An inline hook modifies the first few
bytes of a target function to redirect execution to the EDR's hook handler.

**Mechanism at the byte level:**

The original function prologue (typically 5+ bytes) is overwritten with a `JMP`
instruction to the EDR's detour function:

```
Original ntdll!NtAllocateVirtualMemory:
    4C 8B D1            mov r10, rcx          ; syscall number into r10
    B8 18 00 00 00      mov eax, 0x18         ; syscall number
    0F 05               syscall
    C3                  ret

After EDR hooking:
    E9 XX XX XX XX      jmp EDR_Hook_NtAllocateVirtualMemory  ; 5-byte relative jump
    90                  nop                    ; padding
    0F 05               syscall                ; (may be partially overwritten)
    C3                  ret
```

The EDR's detour function:
1. Logs the call parameters (base address, size, allocation type, protection flags).
2. Performs policy checks (e.g., is this a cross-process RWX allocation?).
3. Calls the **trampoline** to execute the original instructions and proceed to the
   real syscall.

**Trampoline structure:**

The trampoline preserves the original overwritten bytes and provides a way to call the
original function:

```
EDR Trampoline:
    4C 8B D1            mov r10, rcx          ; Saved original bytes
    B8 18 00 00 00      mov eax, 0x18         ; Saved original bytes
    FF 25 XX XX XX XX   jmp [original_function + 7]  ; Jump past the hook
```

Modern EDRs may use "hot-patching" compatible hooks on functions that begin with a
`MOV EDI, EDI` (2-byte NOP) instruction, allowing a 2-byte short jump to a 5-byte
long jump placed in preceding padding bytes.

#### IAT (Import Address Table) Hooks

IAT hooks modify entries in a PE file's Import Address Table to redirect imported
function calls.

```
Original IAT entry for kernel32!CreateFileW:
    [0x00007FFD12340000]  -> kernel32!CreateFileW

After hooking:
    [0x00007FFD12340000]  -> EDR_Hook_CreateFileW
```

IAT hooks are simpler to implement but only intercept calls made through the IAT. Direct
calls to function addresses (e.g., via `GetProcAddress`) are not intercepted. Most
modern EDRs prefer inline hooks over IAT hooks for this reason.

#### EAT (Export Address Table) Hooks

EAT hooks modify the Export Address Table of a DLL to redirect function resolution.
When any process calls `GetProcAddress` for a hooked function, it receives the address
of the EDR's hook instead of the real function.

EAT hooks are broader in scope than IAT hooks (they affect all future `GetProcAddress`
resolutions) but are less commonly used by EDRs due to complexity and the fact that they
only affect resolution, not direct calls.

### 3.2 EDR DLL Injection Methods

For hooks to work, the EDR must inject its monitoring DLL into every process. Several
methods are used:

#### Kernel-Mode APC Injection

The most common and reliable method. The EDR's kernel driver uses an Asynchronous
Procedure Call (APC) to inject its DLL into new processes:

1. The process creation callback fires in the EDR driver.
2. The driver allocates memory in the new process (via `ZwAllocateVirtualMemory`).
3. The driver writes the DLL path or loader shellcode into the allocated memory.
4. The driver queues a user-mode APC (via `KeInitializeApc` / `KeInsertQueueApc`) to the
   process's initial thread.
5. When the thread begins executing and enters an alertable state, the APC fires and
   loads the EDR DLL.

The timing is critical: the EDR must inject before any malicious code runs, which
typically means the APC must execute before `ntdll!LdrInitializeThunk` completes. Some
EDRs use "Early Bird" APC injection, queuing the APC before the thread's initial
execution begins.

#### AppInit_DLLs Registry Key

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
    AppInit_DLLs = "C:\Program Files\EDR\monitor.dll"
    LoadAppInit_DLLs = 1
```

Every process that loads `user32.dll` (which includes virtually all GUI applications)
also loads DLLs listed in this registry key. This is a legacy method with significant
limitations:
- Does not work for console-only applications that never load `user32.dll`.
- Disabled by default on systems with Secure Boot enabled (Windows 8+).
- Widely known and easy to detect or circumvent.

#### Image File Execution Options (IFEO)

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>
    Debugger = "C:\Program Files\EDR\monitor.exe"
```

IFEO is normally used for debugging but can be used to intercept process launches. The
"debugger" process is launched instead of the original, with the original command line as
arguments. Some EDRs use the `GlobalFlag` and `VerifierDlls` IFEO subkeys to force-load
a verifier DLL into target processes.

#### Code Integrity Guard (CIG) and Its Implications

CIG (`PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON`)
prevents non-Microsoft-signed DLLs from being loaded into a process. When a process
enables CIG:
- The EDR's monitoring DLL cannot be loaded unless it is signed by Microsoft.
- Third-party EDR vendors must either obtain a Microsoft signature or use alternative
  monitoring approaches (e.g., relying entirely on kernel callbacks and ETW).
- Microsoft Defender can inject into CIG-protected processes because its DLLs are
  Microsoft-signed.

CIG enforcement happens at image mapping time: `NtMapViewOfSection` checks the signature
of the section being mapped and refuses mapping if the signature does not meet the CIG
policy.

### 3.3 Commonly Hooked Functions

EDRs typically hook functions in `ntdll.dll` (the lowest usermode layer before the
kernel syscall), and sometimes in `kernel32.dll` or `kernelbase.dll`.

**High-priority ntdll.dll hooks (virtually always hooked):**

| Function | Purpose | Detection Target |
|----------|---------|-----------------|
| `NtAllocateVirtualMemory` | Memory allocation | Shellcode staging, process injection |
| `NtProtectVirtualMemory` | Change memory protection | RWX transitions |
| `NtWriteVirtualMemory` | Write to another process | Process injection |
| `NtCreateThreadEx` | Create thread (local/remote) | Thread injection |
| `NtMapViewOfSection` | Map file/section into memory | Process hollowing, DLL injection |
| `NtOpenProcess` | Open process handle | Cross-process access |
| `NtCreateFile` | File creation/opening | File operations |
| `NtReadVirtualMemory` | Read another process's memory | Credential dumping |

**Medium-priority hooks (commonly hooked):**

| Function | Purpose | Detection Target |
|----------|---------|-----------------|
| `NtQueueApcThread` | Queue APC | APC injection |
| `NtSetContextThread` | Modify thread context | Debug register manipulation |
| `NtSuspendThread` / `NtResumeThread` | Thread manipulation | Process hollowing |
| `NtCreateSection` | Create memory section | Process hollowing |
| `NtUnmapViewOfSection` | Unmap memory | Process hollowing |
| `NtDuplicateObject` | Duplicate handles | Handle manipulation |
| `NtCreateProcess` / `NtCreateProcessEx` | Process creation | Process spawning |
| `NtOpenThread` | Open thread handle | Thread injection |
| `NtWriteFile` | File writing | Payload writing |

### 3.4 The Hook Chain

When an application calls a Windows API, the call flows through multiple layers:

```
Application Code
    |
    v
kernel32.dll!CreateRemoteThread        (high-level API)
    |
    v
kernelbase.dll!CreateRemoteThreadEx    (forwarded implementation)
    |
    v
ntdll.dll!NtCreateThreadEx            (native API wrapper)
    |
    +---> EDR Hook DLL intercept       (inline hook fires here)
    |         |
    |         +--> Log parameters
    |         +--> Policy check
    |         +--> If allowed: call trampoline
    |         |
    v         v
    Trampoline (original bytes + jump back)
    |
    v
    syscall instruction                 (transition to kernel mode)
    |
    v
    nt!NtCreateThreadEx                 (kernel implementation)
```

The EDR hook sees the full parameter set at the point of the native API call, including
the target process handle, thread start address, and creation flags.

### 3.5 Hook Integrity Monitoring

Modern EDRs implement periodic integrity checks to detect hook removal:

1. **Periodic scanning**: The EDR service periodically reads the first bytes of hooked
   functions and compares them against the expected hook bytes. If the hook has been
   removed (e.g., by reloading a clean copy of ntdll.dll from disk), the EDR can
   re-install the hook and raise an alert.

2. **Memory protection**: Some EDRs set the hooked pages as `PAGE_EXECUTE_READ` (removing
   write permission) after installing hooks, causing any attempt to overwrite the hooks
   to trigger an access violation.

3. **Kernel-level verification**: The EDR's kernel driver can verify hook integrity from
   kernel mode, where it is immune to usermode tampering.

4. **Call stack analysis**: Even without hooks, the EDR can analyze call stacks (via ETW
   or kernel callbacks) to detect when syscalls are made directly, bypassing the expected
   call chain through ntdll.dll.

---

## 4. Minifilter Drivers

Minifilter drivers operate within the Filter Manager framework (`fltmgr.sys`) to
intercept file system I/O operations. They are essential for EDRs' on-access scanning,
file activity monitoring, and ransomware protection.

### 4.1 Filter Manager Architecture

The Filter Manager (`fltmgr.sys`) is a kernel-mode driver that acts as an intermediary
between the I/O Manager and file system drivers. It provides a simplified framework
for developing file system filters, replacing the legacy file system filter driver model.

**I/O flow:**

```
Application (CreateFile, WriteFile, etc.)
    |
    v
I/O Manager (constructs IRP)
    |
    v
Filter Manager (fltmgr.sys)
    |
    v
Minifilter Instance (highest altitude)  <-- Pre-operation callback
    |
    v
Minifilter Instance (next altitude)     <-- Pre-operation callback
    |
    v
    ... (more minifilters) ...
    |
    v
File System Driver (NTFS, ReFS, etc.)
    |
    v (operation completes)
    |
    v
Minifilter Instance (lowest altitude)   <-- Post-operation callback
    |
    v
    ... (ascending through altitudes) ...
    |
    v
Minifilter Instance (highest altitude)  <-- Post-operation callback
    |
    v
I/O Manager (returns result to application)
```

Pre-operation callbacks are invoked top-down (highest altitude first), while
post-operation callbacks are invoked bottom-up (lowest altitude first). This means
higher-altitude filters see requests first on the way down and last on the way up.

### 4.2 Altitude Numbers and Registration

Every minifilter must have a unique altitude, a decimal string that determines its
position in the filter stack. Microsoft allocates altitudes to ensure no conflicts.

**Load order groups relevant to EDR/security:**

| Load Order Group | Altitude Range | Purpose |
|-----------------|----------------|---------|
| FSFilter Top | 400000-409999 | Must attach above all others |
| FSFilter Activity Monitor | 360000-389999 | Observe and report file I/O |
| FSFilter Undelete | 340000-349999 | Recover deleted files |
| **FSFilter Anti-Virus** | **320000-329999** | **Detect/disinfect during I/O** |
| FSFilter Replication | 300000-309999 | File replication |
| FSFilter Continuous Backup | 280000-289999 | Backup |
| FSFilter Content Screener | 260000-269999 | Prevent specific file content |
| FSFilter Encryption | 140000-149999 | File encryption |
| FSFilter Security Enhancer | 80000-89999 | Enhanced ACLs |

EDR/antivirus minifilters register in the **FSFilter Anti-Virus** range (320000-329999).
Notable altitude assignments:
- **Microsoft Defender (WdFilter.sys)**: Altitude **328010**
- Third-party EDRs receive altitudes in the same range from Microsoft.

A vendor with an assigned "integer" altitude (e.g., 325000) can create additional
sub-altitudes by appending fractional values (e.g., 325000.3, 325000.7) without
requesting new allocations from Microsoft.

### 4.3 Pre-Operation and Post-Operation Callbacks

Minifilters register callbacks for specific IRP major function codes. Each callback can
return a status that determines how the operation proceeds.

#### Pre-Operation Callback Return Values

```c
typedef enum _FLT_PREOP_CALLBACK_STATUS {
    FLT_PREOP_SUCCESS_WITH_CALLBACK,   // Continue; invoke post-op callback when done
    FLT_PREOP_SUCCESS_NO_CALLBACK,     // Continue; skip post-op callback
    FLT_PREOP_PENDING,                 // Pend the operation (async processing)
    FLT_PREOP_DISALLOW_FASTIO,         // Disallow fast I/O (force IRP path)
    FLT_PREOP_COMPLETE,                // Complete the operation immediately (BLOCK)
    FLT_PREOP_SYNCHRONIZE,             // Synchronize post-op with pre-op thread
    FLT_PREOP_DISALLOW_FSFILTER_IO     // Disallow FS filter I/O
} FLT_PREOP_CALLBACK_STATUS;
```

**`FLT_PREOP_COMPLETE`** is the blocking mechanism: the minifilter sets the IRP's
`IoStatus.Status` to a failure code (e.g., `STATUS_ACCESS_DENIED`) and returns
`FLT_PREOP_COMPLETE`, preventing the operation from reaching the file system.

**`FLT_PREOP_SUCCESS_WITH_CALLBACK`** is the monitoring mechanism: the operation
proceeds to the file system, and the minifilter's post-operation callback is invoked
when it completes, allowing the minifilter to inspect the result.

### 4.4 Key IRP Operations for EDR

#### IRP_MJ_CREATE (File Open)

Fires whenever a file or directory is opened or created. The pre-operation callback
receives the `FLT_CALLBACK_DATA` structure containing:
- The file path being accessed.
- The desired access rights (`FILE_READ_DATA`, `FILE_WRITE_DATA`, `FILE_EXECUTE`, etc.).
- The creation disposition (`FILE_OPEN`, `FILE_CREATE`, `FILE_OVERWRITE`, etc.).
- The calling process context.

EDRs use this callback for:
- **On-access scanning**: Scanning file contents when a file is opened for execution
  or read access.
- **Behavioral monitoring**: Tracking which processes access which files.
- **Ransomware detection**: Monitoring rapid sequential opens of many files.

#### IRP_MJ_WRITE (File Write)

Fires on file write operations. The callback receives:
- The buffer being written (or a pointer to it).
- The offset and length of the write.
- The file object being written to.

EDRs use this for:
- **Malware drop detection**: Scanning content being written to disk for known malware
  signatures.
- **Ransomware detection**: Detecting encryption patterns in write data (high entropy
  writes replacing low-entropy existing content).
- **Script drop detection**: Monitoring writes of script files (.ps1, .vbs, .bat, etc.).

#### IRP_MJ_SET_INFORMATION (File Rename/Delete/Attribute Change)

Fires when file metadata is modified. The `FileInformationClass` field indicates the
type of modification:
- `FileRenameInformation` / `FileRenameInformationEx`: File rename operations.
- `FileDispositionInformation` / `FileDispositionInformationEx`: File deletion.
- `FileBasicInformation`: Timestamp and attribute changes.

EDRs use this for:
- **Anti-forensics detection**: Detecting file timestomping (modification of file
  timestamps to hide evidence).
- **Ransomware detection**: Mass rename operations (e.g., appending `.encrypted` to
  thousands of files).
- **Self-deletion detection**: Malware deleting its own executable after execution.

### 4.5 Communication Ports

Minifilters communicate with their usermode service component through Filter
Communication Ports:

```c
// Kernel side (minifilter driver):
FltCreateCommunicationPort(
    Filter,                    // Filter handle
    &ServerPort,               // Output: server port handle
    &ObjectAttributes,         // Port name (e.g., "\EDRPort")
    ServerPortCookie,          // Context
    ConnectNotifyCallback,     // Called when usermode connects
    DisconnectNotifyCallback,  // Called when usermode disconnects
    MessageNotifyCallback,     // Called when usermode sends a message
    MaxConnections             // Max simultaneous connections
);

// Usermode side (EDR service):
FilterConnectCommunicationPort(
    L"\\EDRPort",              // Port name
    0,                         // Options
    NULL,                      // Context
    0,                         // Context size
    NULL,                      // Security attributes
    &Port                      // Output: port handle
);
```

This bidirectional channel allows:
- The minifilter to send events/alerts to the usermode service.
- The usermode service to send configuration updates, policy changes, and scan requests
  to the minifilter.
- Synchronous scanning: The minifilter can pend an I/O operation, send the file path
  to usermode for scanning, wait for the result, and then allow or block the operation.

### 4.6 Minifilter and Ransomware Protection

Modern EDR minifilters implement multi-layered ransomware detection:

1. **Canary files**: Place decoy files in common directories. Any modification of
   these files immediately triggers an alert.
2. **Entropy analysis**: Monitor write operations for high-entropy data replacing
   low-entropy existing content (a hallmark of encryption).
3. **Rename pattern detection**: Detect mass rename operations with known ransomware
   extensions.
4. **Volume shadow copy monitoring**: Detect deletion of VSS snapshots via
   `IRP_MJ_SET_INFORMATION` or process monitoring.
5. **Rate limiting**: Track the rate of file modifications per process and alert when
   a threshold is exceeded.

---

## 5. Network Filtering

EDRs monitor network activity through the Windows Filtering Platform (WFP) and, in
legacy deployments, NDIS filter drivers.

### 5.1 WFP (Windows Filtering Platform) Architecture

WFP is the successor to NDIS hooking and Winsock SPI hooking. It operates inside the
TCP/IP stack at multiple layers simultaneously, providing access to connection state,
flow context, process identity, and reassembled stream data.

**WFP Components:**

- **Filter Engine**: The central kernel-mode component that evaluates filters against
  network traffic.
- **Layers**: Inspection points within the TCP/IP stack. Each layer represents a
  specific point in the network processing path.
- **Sublayers**: Groupings of filters within a layer. Sublayers are evaluated in order
  of weight. Each sublayer returns an action (permit or block), and the sublayer with
  the highest weight wins.
- **Filters**: Individual rules within a sublayer that match on conditions (IP addresses,
  ports, protocols, application identity) and specify an action.
- **Callouts**: Extensions that provide custom processing logic when a filter matches.
  EDRs register callout drivers to execute their own code for matched traffic.

**WFP Layer Hierarchy:**

```
Application (connect/send/recv)
    |
    v
ALE (Application Layer Enforcement) Layers
    |-- FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6      (outbound connection authorization)
    |-- FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6  (inbound connection authorization)
    |-- FWPM_LAYER_ALE_AUTH_LISTEN_V4/V6       (listen authorization)
    |-- FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4/V6  (flow established notification)
    |-- FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4/V6 (port binding)
    |
    v
Transport Layers
    |-- FWPM_LAYER_OUTBOUND_TRANSPORT_V4/V6    (outbound at transport level)
    |-- FWPM_LAYER_INBOUND_TRANSPORT_V4/V6     (inbound at transport level)
    |
    v
Network Layers
    |-- FWPM_LAYER_OUTBOUND_NETWORK_V4/V6      (outbound at IP level)
    |-- FWPM_LAYER_INBOUND_NETWORK_V4/V6       (inbound at IP level)
    |
    v
Stream Layers
    |-- FWPM_LAYER_STREAM_V4/V6                (TCP stream data)
```

### 5.2 EDR WFP Layer Registration

EDRs typically register at ALE layers because they provide process correlation out of
the box:

**FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6**: Fires once per outbound connection flow. For TCP,
this fires on `connect()`. For UDP, this fires on the first packet sent to a unique
remote address:port tuple. Available metadata includes:
- Source and destination IP addresses and ports.
- Protocol.
- **Process ID and path** of the application making the connection.
- Interface index and sub-interface index.

This is the primary EDR network monitoring layer because it provides complete connection
context with process attribution at low overhead (one event per connection, not per
packet).

**FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6**: The inbound equivalent. Fires when an
inbound connection is accepted.

**FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4/V6**: Fires after a connection is fully
established, providing final connection parameters.

### 5.3 WFP Callout Drivers

EDRs register callout drivers to perform custom processing:

```c
// Register a callout with WFP
FWPS_CALLOUT callout = {
    .calloutKey        = EDR_CALLOUT_GUID,
    .flags             = 0,
    .classifyFn        = EdR_ClassifyFn,        // Called for each matched packet/connection
    .notifyFn          = EdR_NotifyFn,           // Called for filter add/delete
    .flowDeleteFn      = EdR_FlowDeleteFn        // Called when flow context is deleted
};

FwpsCalloutRegister(DeviceObject, &callout, &calloutId);

// Add the callout to WFP management layer
FWPM_CALLOUT mCallout = {
    .calloutKey        = EDR_CALLOUT_GUID,
    .displayData       = { L"EDR Network Monitor", L"Monitors network connections" },
    .applicableLayer   = FWPM_LAYER_ALE_AUTH_CONNECT_V4
};

FwpmCalloutAdd(engineHandle, &mCallout, NULL, NULL);
```

The `classifyFn` is the core processing function. When WFP matches traffic against a
filter associated with this callout, it invokes the classify function with the full
packet/connection metadata. The callout can:
- **Permit**: Allow the traffic to proceed.
- **Block**: Drop the traffic.
- **Continue**: Defer the decision to the next filter/sublayer.
- **Absorb**: Consume the traffic (used for traffic redirection).

Most EDR callouts use a **Terminating** action type, meaning their decision is final
for their sublayer.

### 5.4 NDIS Filter Drivers (Legacy)

NDIS (Network Driver Interface Specification) filter drivers operate at the link layer,
below the TCP/IP stack. They see raw packets before TCP/IP processing.

**Comparison with WFP:**

| Feature | NDIS Filter | WFP |
|---------|-------------|-----|
| Layer | Link layer (L2) | Transport/Network (L3-L4) |
| Process attribution | Must manually track PID | Built-in |
| Connection state | Must reconstruct manually | Built-in |
| Stream reassembly | Manual | Built-in at stream layer |
| Performance | Higher overhead | Lower overhead |
| TLS inspection | Can see encrypted bytes | Cannot see plaintext |

NDIS filters are largely deprecated for EDR use in favor of WFP. They are still used
in some specialized scenarios (e.g., packet capture, protocol analysis, or when access
to raw frames is required).

### 5.5 TLS/SSL Inspection

EDR TLS inspection capabilities are limited on Windows:
- **WFP cannot inspect TLS content**: WFP sees the encrypted stream but cannot decrypt
  it. To inspect TLS content, the EDR would need to perform a man-in-the-middle (MITM)
  interception, which requires installing a root CA certificate and intercepting at the
  Winsock level.
- **Server Name Indication (SNI)**: The TLS Client Hello message contains the SNI
  extension in plaintext. WFP callout drivers (such as WTD.sys in Windows Defender) can
  extract the SNI to determine the destination hostname without decrypting traffic.
- **Encrypted Client Hello (ECH)**: Newer TLS implementations encrypt the SNI, which
  eliminates this visibility.

### 5.6 DNS Query Monitoring

EDRs monitor DNS through multiple channels:
- **ETW Microsoft-Windows-DNS-Client provider**: Captures all DNS resolution events
  with the querying process's identity.
- **WFP UDP port 53 filtering**: Monitoring outbound UDP packets to port 53 at the
  transport layer.
- **Zero Trust DNS (ZTDNS)**: A Windows feature where all DNS queries go through a
  secure resolver, and connections to unresolved addresses are blocked by WFP.

### 5.7 Process-Network Correlation

A core EDR capability is correlating network activity with process context. WFP provides
this natively through the ALE layers, which include the process ID and application path
in the classify metadata (`FWPS_METADATA_FIELD_PROCESS_ID` and
`FWPS_METADATA_FIELD_PROCESS_PATH`).

This eliminates the race conditions and manual socket correlation that were necessary
with NDIS-based approaches, where the PID had to be determined through socket table
lookups that could miss short-lived connections.

---

## 6. Memory Scanning

Memory scanning is one of the most resource-intensive but effective detection mechanisms
in an EDR's arsenal. It detects malicious code that exists only in process memory and
never touches disk.

### 6.1 Scan Triggers

Full continuous memory scanning is too expensive. EDRs use event-driven triggers to
selectively scan:

#### VirtualAlloc/VirtualProtect with Suspicious Protections

When `NtAllocateVirtualMemory` or `NtProtectVirtualMemory` is called with
`PAGE_EXECUTE_READWRITE` (RWX), the EDR flags the memory region for scanning. RWX
memory is suspicious because legitimate applications rarely need simultaneously
writable and executable memory.

EtwTi Task 1 (allocation) and Task 2 (protection change) events provide this telemetry
from the kernel, immune to usermode hook evasion.

#### NtMapViewOfSection Calls

Section mapping (used in process hollowing, DLL injection, and transacted file
operations) triggers scanning of the mapped region, especially if the section is not
backed by a file on disk.

#### Suspicious Thread Creation

Thread creation events where:
- The thread start address is in unbacked (non-image) memory.
- The thread is a remote thread (created by a different process).
- The start address does not correspond to any known module's `.text` section.

These triggers generate immediate memory scans of the target region.

#### ETW-TI Notifications

Task 7 (virtual memory write to remote process) and Task 4 (APC queue) events trigger
scans of the target memory region in the remote process.

#### Periodic Baseline Scanning

Some EDRs perform periodic (e.g., every 5-30 minutes) scans of all processes' memory
for unbacked executable regions, comparing against previous baselines to detect new
injections.

### 6.2 Scan Algorithms

#### YARA Rules

EDRs maintain thousands of YARA rules targeting specific malware signatures, tool
configurations, and behavioral patterns in memory. Examples:
- Metasploit/Meterpreter shellcode signatures.
- Cobalt Strike beacon configuration structures.
- Mimikatz string patterns and data structures.
- Known packer/crypter unpacked payload patterns.

YARA scanning is applied to specific memory regions rather than entire process address
spaces to manage performance.

#### Byte Signatures

Traditional signature-based matching using byte sequences and wildcards. Faster than
YARA but less flexible. Used for known malware families with stable code sections.

#### Machine Learning Models

ML models analyze memory region characteristics:
- **Entropy analysis**: High-entropy regions may indicate encrypted/packed code.
- **Opcode frequency analysis**: Statistical analysis of instruction frequency
  distributions.
- **Structural analysis**: PE header characteristics, section properties, import table
  patterns.
- **Behavioral feature vectors**: Combining memory attributes with process behavior
  for classification.

### 6.3 Memory Region Classification

EDRs classify memory regions by their backing:

**Image-backed (MEM_IMAGE)**: Memory mapped from a PE file on disk (`.text`, `.data`
sections of loaded EXEs/DLLs). These are considered lower risk because the backing file
was presumably scanned when loaded. However, Copy-on-Write (COW) modifications to
image-backed pages indicate tampering and are flagged.

**Private (MEM_PRIVATE)**: Memory allocated dynamically via `VirtualAlloc`. This is
where shellcode and injected code typically reside. Private executable memory is the
highest-risk category.

**Mapped (MEM_MAPPED)**: Memory mapped from a section object. Can be file-backed
(lower risk) or pagefile-backed (higher risk if executable).

EDRs query memory region information using `NtQueryVirtualMemory` with
`MemoryBasicInformation` and `MemoryMappedFilenameInformation` to determine backing
type and file association.

### 6.4 Unbacked Executable Memory Detection

Unbacked executable memory (private commit with execute permissions) is the primary
indicator of in-memory malware. EDRs detect this through:

1. **Working set analysis**: Using `PSAPI_WORKING_SET_EX_INFORMATION` to query page
   attributes including whether a page has been modified (Copy-on-Write detection).
2. **VAD (Virtual Address Descriptor) tree walking**: The kernel driver can walk a
   process's VAD tree to enumerate all memory regions and their protections without
   relying on usermode APIs.
3. **Memory attribute correlation**: Combining memory protection, type, and state with
   thread start addresses and loaded module information to identify suspicious regions.

### 6.5 Performance Considerations

Memory scanning cost hierarchy (relative):

| Operation | Relative Cost | Frequency |
|-----------|--------------|-----------|
| Check memory attributes | 1x | Every suspicious event |
| Scan specific region (YARA) | 10-50x | On trigger |
| Scan full process memory | 100-500x | Rare (periodic or on high-confidence trigger) |
| Scan all processes | 1000x+ | Very rare (scheduled deep scan) |

EDRs budget their scanning based on system load, typically using a separate low-priority
thread pool with CPU and I/O throttling to avoid impacting system performance.

---

## 7. Telemetry Pipeline

The telemetry pipeline is the complete event flow from initial collection through
analysis to cloud backend reporting.

### 7.1 Event Flow Architecture

```
+------------------+    +------------------+    +------------------+
|  Kernel Sources  |    | Usermode Sources  |    |   Cloud Backend  |
|                  |    |                   |    |                  |
| Kernel Callbacks |    | Hook DLL events   |    | ML Models        |
| ETW Providers    |--->| AMSI events       |--->| Threat Intel     |
| Minifilter I/O   |    | Process telemetry |    | Correlation      |
| WFP Network      |    | Memory scan results|   | Storage          |
+------------------+    +------------------+    +------------------+
         |                       |                       ^
         v                       v                       |
    +---------+           +-----------+            +----------+
    | Kernel  |           | Usermode  |            | Secure   |
    | Event   |---------->| EDR       |----------->| Transport|
    | Buffer  |           | Service   |            | (TLS)    |
    +---------+           +-----------+            +----------+
                               |
                               v
                        +-------------+
                        | Local       |
                        | Analysis    |
                        | Engine      |
                        +-------------+
```

### 7.2 Local vs. Cloud Detection Split

EDR detection is split between local and cloud processing:

**Local (agent-side) detection:**
- Signature-based file scanning (immediate, <100ms).
- Known-bad hash lookups against local cache.
- Basic behavioral rules (process tree anomalies, known LOLBin abuse patterns).
- Real-time blocking decisions (must be made locally due to latency requirements).
- Typically handles 70-90% of detections by volume.

**Cloud-side detection:**
- Machine learning models requiring more compute than the endpoint can provide.
- Cross-endpoint correlation (detecting lateral movement across multiple machines).
- Threat intelligence enrichment (matching IOCs against global threat feeds).
- Behavioral analytics over longer time windows (detecting slow-moving threats).
- Typically handles 10-30% of detections but catches more sophisticated threats.

### 7.3 Latency Windows

| Pipeline Stage | Typical Latency | Notes |
|---------------|----------------|-------|
| Kernel callback to usermode service | <1ms | Via communication port or shared memory |
| ETW event to consumer | 1-10ms | Depends on buffer flush interval |
| Local signature scan | 10-100ms | Per file/region |
| Local behavioral rule evaluation | 1-50ms | Depends on rule complexity |
| Usermode to cloud transport | 50-500ms | Network dependent |
| Cloud ML inference | 100-2000ms | Model and load dependent |
| Cloud threat intel lookup | 50-200ms | Cache hit vs. miss |
| End-to-end local detection | <100ms | For immediate blocking decisions |
| End-to-end cloud detection | 1-10s | For cloud-assisted detections |

### 7.4 Event Buffering and Batching

Events are not sent individually to the cloud. Instead, EDR agents employ:

- **Per-CPU kernel buffers**: ETW uses per-processor buffers to minimize lock contention.
  Default buffer sizes are 64KB-1MB per CPU.
- **Usermode event queue**: The EDR service maintains an in-memory queue for events
  pending cloud upload. Queue sizes are typically 10-100MB.
- **Batch compression**: Events are batched (typically 1-10 second windows), compressed
  (gzip or custom formats), and sent as a single HTTPS POST.
- **Priority queues**: High-severity events (blocked malware, credential theft attempts)
  are sent immediately; low-severity events (routine file access, benign process
  creation) are batched with longer intervals.
- **Deduplication**: Repeated identical events (e.g., the same process making the same
  network connection) are deduplicated or counted rather than sent individually.

### 7.5 Offline and Degraded Operation

When cloud connectivity is lost:

- **Store-and-forward**: Events are buffered locally (typically on disk, with a size
  cap of 100MB-1GB). When connectivity is restored, buffered events are uploaded.
- **Degraded detection**: Cloud-only detections are unavailable. The agent falls back
  to local-only detection, which may miss more sophisticated threats.
- **Local cache**: The agent maintains a local cache of IOCs, behavioral rules, and ML
  model weights. These are updated when connectivity is available.
- **Offline persistence**: Critical alerts (blocks, confirmed detections) are persisted
  to disk and uploaded when possible.

### 7.6 Event Volume Management

A single endpoint can generate millions of events per day. EDRs manage this through:

- **Filtering**: Low-value events (e.g., reads to system files, benign scheduled tasks)
  are filtered at the agent before transmission.
- **Sampling**: For extremely high-volume event types (e.g., file reads), the agent may
  sample a percentage rather than reporting all events.
- **Aggregation**: Multiple related events are aggregated into summary records (e.g.,
  "process X made 1000 network connections to Y in the last minute" rather than 1000
  individual events).
- **Adaptive throttling**: When system load is high, the agent reduces telemetry
  collection to stay within its resource budget.

### 7.7 EDR Agent Resource Budgets

EDR agents operate under strict resource constraints to avoid degrading system
performance:

| Resource | Typical Budget | Hard Limit |
|----------|---------------|------------|
| CPU | 1-5% average | 10-15% peak |
| Memory (usermode service) | 100-300MB | 500MB |
| Memory (kernel driver) | 10-50MB | 100MB |
| Disk I/O | 5-20 IOPS average | 100 IOPS peak |
| Network bandwidth | 50-200 KB/s | 1 MB/s |
| Disk storage (event cache) | 100MB-1GB | 2GB |

Exceeding these budgets results in visible user impact (slow performance), which is a
primary reason for EDR agent telemetry reduction and sampling strategies.

---

## 8. Protected Processes (PP/PPL)

Protected Processes and Protected Process Light are security mechanisms that protect
critical system processes and security software from tampering by other processes, even
those running with administrative privileges.

### 8.1 Protected Process (PP) vs. Protected Process Light (PPL)

**Protected Process (PP)**: Introduced in Windows Vista for DRM content protection. PP
processes have the strongest protection -- no other process can inject code, read memory,
or terminate them, regardless of privilege level. Only code signed with a specific
Microsoft DRM certificate can run as PP.

**Protected Process Light (PPL)**: Introduced in Windows 8.1. A more flexible variant
designed for security software and system components. PPL processes have most of the
protections of PP but with a tiered signer system that allows different levels of trust.

Key protections applied to PP/PPL processes:

| Protection | Enforced By |
|-----------|-------------|
| No code injection | Kernel (NtWriteVirtualMemory fails) |
| No DLL injection | Code Integrity (unsigned DLLs rejected) |
| No thread injection | Kernel (NtCreateThreadEx fails) |
| No memory reading | Kernel (NtReadVirtualMemory fails) |
| No process termination | Kernel (NtTerminateProcess fails) |
| No handle access | ObRegisterCallbacks + kernel checks |
| No debugging | Kernel (NtDebugActiveProcess fails) |
| Trusted DLL loading only | Code Integrity verification |

### 8.2 Signer Levels

The PPL system uses a signer hierarchy defined by the `PS_PROTECTED_SIGNER` enumeration:

```c
typedef enum _PS_PROTECTED_SIGNER {
    PsProtectedSignerNone         = 0,  // No protection
    PsProtectedSignerAuthenticode = 1,  // Authenticode-signed
    PsProtectedSignerCodeGen      = 2,  // Code generation
    PsProtectedSignerAntimalware  = 3,  // Anti-malware (EDR)
    PsProtectedSignerLsa          = 4,  // LSA (credential protection)
    PsProtectedSignerWindows      = 5,  // Windows components
    PsProtectedSignerWinTcb       = 6,  // Trusted Computer Base
    PsProtectedSignerWinSystem    = 7,  // Windows System (highest)
    PsProtectedSignerApp          = 8,  // Store application
    PsProtectedSignerMax          = 9
} PS_PROTECTED_SIGNER;
```

The protection information is stored in the `_EPROCESS.Protection` field:

```c
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type   : 3;   // PS_PROTECTED_TYPE (PsProtectedTypeNone=0,
                                //   PsProtectedTypeProtectedLight=1,
                                //   PsProtectedTypeProtected=2)
            UCHAR Audit  : 1;   // Audit mode
            UCHAR Signer : 4;   // PS_PROTECTED_SIGNER value
        };
    };
} PS_PROTECTION, *PPS_PROTECTION;
```

**Access hierarchy**: A PPL process can open a handle to another PPL process only if its
signer level is **greater than or equal to** the target's signer level. This means:

- PPL-WinTcb (6) can access PPL-Antimalware (3), PPL-Lsa (4), PPL-Windows (5).
- PPL-Antimalware (3) **cannot** access PPL-Lsa (4) or PPL-Windows (5).
- No PPL process can access a PP process (PP > PPL in the type hierarchy).

**Notable protected processes:**

| Process | Protection Level | Signer |
|---------|-----------------|--------|
| System | PP-WinSystem | 7 |
| csrss.exe | PPL-WinTcb | 6 |
| wininit.exe | PPL-WinTcb | 6 |
| smss.exe | PPL-WinTcb | 6 |
| services.exe | PPL-Windows | 5 |
| lsass.exe | PPL-Lsa | 4 |
| MsMpEng.exe (Defender) | PPL-Antimalware | 3 |
| EDR service | PPL-Antimalware | 3 |

### 8.3 ELAM (Early Launch Anti-Malware) Drivers

ELAM drivers are the foundation for PPL-Antimalware protection. They serve two purposes:

1. **Boot-time driver evaluation**: The ELAM driver loads very early in the boot process
   (before most other third-party drivers) and evaluates each subsequent boot-start
   driver, classifying it as Known Good, Known Bad, or Unknown. This prevents malicious
   drivers from loading during boot.

2. **PPL certificate registration**: The ELAM driver contains a resource section with
   certificate hashes that identify the EDR's usermode service binaries. During boot,
   the system extracts these hashes and uses them to verify that only properly signed
   binaries can run as PPL-Antimalware.

**ELAM Resource Section Format:**

```c
MicrosoftElamCertificateInfo  MSElamCertInfoID
{
    3,                              // Number of certificate entries
    L"CertHash1\0",                // SHA256 hash of signing certificate
    0x800c,                         // Algorithm (0x800c = SHA256)
    L"EKU1\0",                     // Extended Key Usage OID (optional)
    L"CertHash2\0",
    0x800c,
    L"\0",                          // No EKU
    L"CertHash3\0",
    0x800c,
    L"EKU3a;EKU3b\0",             // Multiple EKUs (max 3, AND logic)
}
```

**ELAM driver requirements:**
- Must be signed with a special WHQL ELAM certificate from Microsoft.
- Must implement boot driver evaluation callbacks.
- Must contain the certificate resource section described above.
- Must pass Microsoft's ELAM test suite.
- The vendor must apply to Microsoft, prove their identity, and sign legal agreements.

### 8.4 Launching as PPL-Antimalware

The EDR's installer configures the service for PPL launch:

```c
// Step 1: Install ELAM driver and register certificates
HANDLE hElamDriver = CreateFile(L"\\path\\to\\elam.sys", ...);
InstallELAMCertificateInfo(hElamDriver);

// Step 2: Configure service as protected
SERVICE_LAUNCH_PROTECTED_INFO info;
info.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT;
ChangeServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, &info);

// Step 3: Start the service
StartService(hService, 0, NULL);
// SCM verifies certificates via Code Integrity before launching as PPL
```

The three `SERVICE_LAUNCH_PROTECTED` values:

| Value | Meaning | Signer Level |
|-------|---------|-------------|
| `SERVICE_LAUNCH_PROTECTED_NONE` (0) | No protection | N/A |
| `SERVICE_LAUNCH_PROTECTED_WINDOWS` (1) | Windows protection | PPL-Windows (5) |
| `SERVICE_LAUNCH_PROTECTED_WINDOWS_LIGHT` (2) | Windows Light | PPL-Windows (5) |
| `SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT` (3) | AM protection | PPL-Antimalware (3) |

### 8.5 What PPL Protects Against

When the EDR service runs as PPL-Antimalware:

**Protected operations (these fail from non-protected processes):**
- `OpenProcess` with `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`,
  `PROCESS_CREATE_THREAD`, `PROCESS_TERMINATE`.
- `CreateRemoteThread` targeting the EDR process.
- `WriteProcessMemory` targeting the EDR process.
- `ReadProcessMemory` targeting the EDR process.
- `VirtualAllocEx` / `VirtualProtectEx` targeting the EDR process.
- Loading unsigned or improperly signed DLLs into the EDR process.
- Attaching a debugger to the EDR process.

**Unprotected operations (these still work):**
- `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` and `PROCESS_SUSPEND_RESUME`
  (limited access is always available).
- Kernel debugger (KD) access -- kernel debuggers can still inspect PPL processes.
- Service Control Manager operations: `sc qc`, `sc start`, `sc interrogate`, `sc sdshow`,
  `sc config start=Auto`.

### 8.6 PPL and Driver Signing

PPL-Antimalware processes enforce Code Integrity on all loaded modules:

- All DLLs loaded into the PPL process must be signed with certificates matching the
  hashes in the ELAM driver's resource section, or be Microsoft-signed Windows DLLs.
- Unsigned DLLs, or DLLs signed with certificates not registered in the ELAM resource
  section, are rejected at load time.
- Script DLLs (`scrobj.dll`, `scrrun.dll`, `jscript.dll`, `jscript9.dll`, `vbscript.dll`)
  are explicitly forbidden in protected processes.

### 8.7 Historical PPL Issues

PPL has been subject to several notable issues over its history:

- **Vulnerable drivers**: Signed drivers with exploitable vulnerabilities have been used
  to modify PPL process memory from kernel mode, where PPL protections do not apply.
  This is the "Bring Your Own Vulnerable Driver" (BYOVD) technique.
- **PPLFault / PPLdump**: Research demonstrating techniques to access PPL processes by
  exploiting specific Windows components or driver vulnerabilities.
- **GodFault**: Combined vulnerable driver exploitation with PPL manipulation.
- **KnownDlls section injection**: The code signing check occurs during section creation,
  not section mapping. If an entry can be placed in KnownDlls, the corresponding DLL
  can be loaded into a PPL process without signature verification.

These issues have led Microsoft to progressively harden PPL and expand the Vulnerable
Driver Blocklist (VDB) to prevent known-exploitable drivers from loading.

---

## 9. Behavioral Detection Engine

The behavioral detection engine is the "brain" of the EDR, correlating raw telemetry
into detection decisions. It operates at multiple analysis levels, from simple rule
matching to complex ML-driven behavioral analysis.

### 9.1 Rule-Based Detection

Rule-based detection uses predefined patterns to identify known attack techniques.

**Rule structure:**

Most EDR behavioral rules follow a pattern of:
- **Source event**: What triggered the rule evaluation (process creation, API call,
  file operation, etc.).
- **Conditions**: Properties that must match (process name, parent process, command-line
  patterns, file paths, registry keys, etc.).
- **Temporal constraints**: Events that must occur within a time window.
- **Scope**: Whether the rule applies to a single process, a process tree, or
  cross-process activity.
- **Action**: Alert severity, blocking decision, and follow-up actions (memory scan,
  data collection, quarantine).

**Example behavioral rules:**

Process tree anomaly detection:
```
RULE: suspicious_powershell_spawn
  WHEN: process_create
  AND parent_process IN (winword.exe, excel.exe, outlook.exe)
  AND child_process == powershell.exe
  AND (commandline CONTAINS "-enc" OR commandline CONTAINS "-nop"
       OR commandline CONTAINS "downloadstring" OR commandline CONTAINS "IEX")
  THEN: ALERT severity=HIGH, action=BLOCK
```

Credential access detection:
```
RULE: lsass_access_suspicious
  WHEN: handle_create
  AND target_process == lsass.exe
  AND desired_access INCLUDES (PROCESS_VM_READ)
  AND source_process NOT IN (whitelist)
  AND source_process.signature != Microsoft
  THEN: ALERT severity=CRITICAL, action=BLOCK
```

**Sigma rules** are an open standard for detection rules. Some EDR vendors (notably
HarfangLab) support Sigma-format rules directly, allowing community-shared detections
to be imported.

**CrowdStrike Custom IOAs** (Indicators of Attack) and **SentinelOne STAR Rules**
(Storyline Active Response) are vendor-specific behavioral rule formats that allow
customers to create custom detections.

### 9.2 ML-Based Behavioral Detection

Machine learning models supplement rule-based detection for patterns that are difficult
to express as rules:

**Pre-execution ML:**
- Static PE analysis: File structure, section characteristics, import table analysis,
  entropy, packer detection.
- Trained on millions of known malware and goodware samples.
- Operates at the minifilter level when files are written or accessed.

**Post-execution ML:**
- Process behavior analysis: API call sequences, memory allocation patterns, network
  behavior, file system activity.
- Anomaly detection: Baseline normal behavior and flag deviations.
- Trained on labeled behavioral telemetry from real attacks and benign activity.

**Local vs. cloud ML:**
- Small, fast models run locally on the endpoint for real-time decisions.
- Larger, more accurate models run in the cloud for deeper analysis.
- Cloud models can be updated without agent updates.

### 9.3 IOC vs. IOA Detection Models

**Indicators of Compromise (IOCs):**

IOCs are artifacts that indicate a breach has occurred. They are reactive -- they identify
known-bad entities after they have been observed in the wild.

| IOC Type | Example | Limitation |
|----------|---------|-----------|
| File hash | SHA256 of malware binary | Trivially changed by recompilation |
| IP address | Known C2 server IP | Changes frequently, shared hosting |
| Domain | Known malware domain | Easily generated (DGA) |
| File path | Known malware drop path | Easily changed |
| Registry key | Known persistence key value | Obfuscatable |
| Mutex name | Known malware mutex | Easily changed |

**Indicators of Attack (IOAs):**

IOAs describe attack behaviors regardless of the specific tools or artifacts used. They
are proactive -- they identify attacks based on what is happening rather than what
specific malware is involved.

| IOA Category | Example | Advantage |
|-------------|---------|-----------|
| Execution pattern | Office app spawning script interpreter | Tool-agnostic |
| Memory behavior | RWX allocation in remote process | Technique-agnostic |
| Discovery pattern | Sequential enumeration of network shares | Intent-based |
| Credential access | Handle to lsass.exe with VM_READ | Method-agnostic |
| Lateral movement | SMB + remote service creation | Behavioral pattern |

Modern EDRs use both models: IOCs for rapid identification of known threats and IOAs for
detection of novel attacks.

### 9.4 MITRE ATT&CK Integration

The MITRE ATT&CK framework provides a common taxonomy for adversary techniques. EDRs
map their detection rules and alerts to ATT&CK technique IDs.

**How ATT&CK mapping works in EDR detection:**

1. **Rule tagging**: Each behavioral rule is tagged with one or more ATT&CK technique
   IDs (e.g., T1055 Process Injection, T1003 OS Credential Dumping).
2. **Alert enrichment**: When a detection fires, the alert includes the ATT&CK technique
   reference, providing analysts with context about the likely attack stage and purpose.
3. **Coverage analysis**: EDR vendors map their total detection capability against the
   ATT&CK matrix to identify coverage gaps.
4. **Detection engineering**: New rules are prioritized based on ATT&CK technique
   prevalence in real-world attacks.

**Example mappings:**

| ATT&CK Technique | ID | EDR Detection Source |
|------------------|-----|---------------------|
| Process Injection | T1055 | EtwTi (memory write + thread create), hooks |
| OS Credential Dumping | T1003 | ObRegisterCallbacks (LSASS handles) |
| Command & Scripting Interpreter | T1059 | PowerShell ETW, AMSI |
| Signed Binary Proxy Execution | T1218 | Process creation (LOLBin detection) |
| Boot/Logon Autostart Execution | T1547 | Registry callbacks, minifilter |
| Masquerading | T1036 | Image load, file metadata analysis |
| Defense Evasion (various) | T1562 | Hook integrity, ETW tampering detection |

### 9.5 Detection Confidence and Alert Prioritization

EDRs assign confidence scores and severity ratings to balance detection sensitivity
against false positive rates:

**Confidence scoring factors:**
- Number of corroborating signals (single IOC = low, IOC + behavioral anomaly = medium,
  IOC + behavioral + memory scan = high).
- Quality of matching (exact hash match = high, fuzzy behavioral match = medium,
  statistical anomaly = low).
- Context: Is the process in a known-suspicious tree? Is the user account high-value?
  Is the machine a server?

**Alert severity tiers:**

| Tier | Criteria | Response |
|------|----------|----------|
| Critical | High-confidence active exploitation (credential theft, ransomware) | Immediate block + alert |
| High | Strong behavioral indicators (process injection, defense evasion) | Alert + optional block |
| Medium | Moderate indicators (suspicious command line, unusual parent-child) | Alert for investigation |
| Low | Weak indicators (uncommon but not malicious behavior) | Log for hunting |
| Informational | Baseline telemetry with no anomaly | Log only (no alert) |

**False positive management:**
- Allowlisting by hash, path, command line, or certificate.
- Per-rule tuning (adjusting conditions or confidence thresholds).
- Customer-specific behavioral baselines (what is "normal" varies by organization).

### 9.6 Process Tree Analysis

Process tree analysis is a core behavioral detection capability. The EDR maintains a
complete process tree for every process on the system, tracking:

- Parent-child relationships.
- Process creation timestamps.
- Command-line arguments at each level.
- User context (SID, token privileges).
- Image signature status.

**Detection patterns:**

- **Unusual parent-child**: `svchost.exe` spawning `cmd.exe`, `services.exe` spawning
  `powershell.exe`, `WmiPrvSE.exe` spawning anything.
- **Deep process chains**: Long chains of script interpreters
  (cmd -> powershell -> cmd -> powershell) suggest staged execution.
- **Orphaned processes**: Processes whose parent has exited may indicate injection or
  persistence mechanisms.
- **Token manipulation**: Child processes running with different user tokens than their
  parent suggest privilege escalation.

### 9.7 Call Stack Analysis

Advanced EDR behavioral engines analyze call stacks to detect anomalous execution flows:

**Normal call stack for NtAllocateVirtualMemory:**
```
ntdll.dll!NtAllocateVirtualMemory
kernelbase.dll!VirtualAlloc
application.exe!.text+0x1234         (code in the application's code section)
kernel32.dll!BaseThreadInitThunk
ntdll.dll!RtlUserThreadStart
```

**Suspicious call stack indicators:**
- Return addresses in unbacked (MEM_PRIVATE) memory regions.
- Syscall instructions executed outside of ntdll.dll (direct syscalls).
- Return addresses in RWX memory.
- Call chain that bypasses expected intermediate DLLs (e.g., no kernelbase.dll frame
  between the application and ntdll.dll).
- Stack frames in memory regions that are not associated with any loaded module.

EDRs obtain call stack information through:
- **ETW events**: Some ETW events include stack trace data when configured with the
  `EVENT_ENABLE_PROPERTY_STACK_TRACE` flag.
- **Thread context inspection**: Reading the thread's context (RSP, RBP) and walking
  the stack frames.
- **EtwTi events**: Include call stack information for monitored operations.

---

## Sources and References

### Kernel Callbacks
- [Microsoft Learn: PsSetCreateProcessNotifyRoutineEx2](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex2)
- [Microsoft Learn: PLOAD_IMAGE_NOTIFY_ROUTINE](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pload_image_notify_routine)
- [SpecterOps: Understanding Telemetry: Kernel Callbacks](https://specterops.io/blog/2023/06/12/understanding-telemetry-kernel-callbacks/)
- [Altered Security: When the Hunter Becomes the Hunted](https://www.alteredsecurity.com/post/when-the-hunter-becomes-the-hunted-using-custom-callbacks-to-disable-edrs)
- [ired.team: Subscribing to Process/Thread/Image Notifications](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/subscribing-to-process-creation-thread-creation-and-image-load-notifications-from-a-kernel-driver)
- [0xflux: Making Improvements to EDR DLL Injection](https://fluxsec.red/improving-edr-dll-injection-kernel-callback)

### ETW and Threat Intelligence
- [0xflux: Leveraging ETW Threat Intelligence for EDR](https://fluxsec.red/event-tracing-for-windows-threat-intelligence-rust-consumer)
- [Praetorian: ETW Threat Intelligence and Hardware Breakpoints](https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/)
- [Meekolab: Introduction into Microsoft Threat Intelligence Drivers](https://research.meekolab.com/introduction-into-microsoft-threat-intelligence-drivers-etw-ti)
- [Trail of Bits: ETW Internals for Security Research](https://blog.trailofbits.com/2023/11/22/etw-internals-for-security-research-and-forensics/)
- [Elastic Security Labs: Kernel ETW is the Best ETW](https://www.elastic.co/security-labs/kernel-etw-best-etw)
- [Jonathan Johnson: Uncovering Windows Events - Threat Intelligence ETW](https://jonny-johnson.medium.com/uncovering-windows-events-b4b9db7eac54)
- [Connor McGarr: Windows Internals - ETW SecurityTrace Flag](https://connormcgarr.github.io/securitytrace-etw-ppl/)

### Usermode Hooks and DLL Injection
- [Red Fox Security: Introduction to EDR Evasion - API Hooking](https://redfoxsecurity.medium.com/introduction-to-edr-evasion-api-hooking-35dc6f4e65d2)
- [DEV Community: Modern EDR Countermeasures - User-Mode Function Hooking](https://dev.to/tiger_smith_9f421b9131db5/modern-edr-countermeasures-fundamentals-and-practical-guide-to-user-mode-function-hooking-3a26)
- [Palo Alto: Deep Dive Into Malicious Direct Syscall Detection](https://www.paloaltonetworks.com/blog/security-operations/a-deep-dive-into-malicious-direct-syscall-detection/)
- [SentinelOne: Deep Hooks - Monitoring Native Execution in WoW64](https://www.sentinelone.com/blog/deep-hooks-monitoring-native-execution-wow64-applications-part-3/)
- [cirosec: Loader Dev - Evading Userspace Hooks](https://cirosec.de/en/news/loader-dev-3-evading-userspace-hooks/)
- [HookChain: A New Perspective for Bypassing EDR Solutions (arXiv)](https://arxiv.org/pdf/2404.16856)

### Minifilter Drivers
- [Microsoft Learn: Load Order Groups and Altitudes for Minifilter Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers)
- [No Starch Press: Filesystem Minifilter Drivers (Evading EDR Ch.6)](https://nostarch.com/download/EvadingEDR_chapter6.pdf)
- [Apriorit: Windows Minifilter Driver Development Tutorial](https://www.apriorit.com/dev-blog/675-driver-windows-minifilter-driver-development-tutorial)
- [hackyboiz: Walking Through Windows Minifilter Drivers](https://hackyboiz.github.io/2025/08/15/banda/Minifilter-Driver/en/)

### Network Filtering (WFP)
- [SCRT Blog: Blinding EDRs - A Deep Dive into WFP Manipulation](https://blog.scrt.ch/2025/08/25/blinding-edrs-a-deep-dive-into-wfp-manipulation/)
- [Microsoft Learn: Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
- [textslashplain: Defensive Technology - Windows Filtering Platform](https://textslashplain.com/2025/03/31/defensive-technology-windows-filtering-platform/)
- [Quarkslab: Guided Tour Inside WinDefender's Network Inspection Driver](https://blog.quarkslab.com/guided-tour-inside-windefenders-network-inspection-driver.html)
- [Jacob Kalat: WFP Wizardry - Abusing WFP for EDR Evasion](https://jacobkalat.com/edr-evasion/2025/02/12/WFP-Wizardry-Abusing-WFP-for-EDR-Evasion.html)

### Memory Scanning
- [deeb.ch: The (Anti-)EDR Compendium](https://blog.deeb.ch/posts/how-edr-works/)
- [Black Lantern Security: Detecting Process Injection](https://blog.blacklanternsecurity.com/p/detecting-process-injection)
- [Black Hills InfoSec: Avoiding Memory Scanners](https://www.blackhillsinfosec.com/avoiding-memory-scanners/)
- [PassTheHashBrowns: Using Frida for Rapid Detection Testing](https://passthehashbrowns.github.io/using-frida-for-rapid-detection-testing)

### Protected Processes (PPL/ELAM)
- [Microsoft Learn: Protecting Anti-Malware Services](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
- [NtDoc: PS_PROTECTED_SIGNER](https://ntdoc.m417z.com/ps_protected_signer)
- [CrowdStrike: Protected Processes Part 3 - Windows PKI Internals](https://www.crowdstrike.com/en-us/blog/protected-processes-part-3-windows-pki-internals-signing-levels-scenarios-signers-root-keys/)
- [Elastic Security Labs: Sandboxing Antimalware Products](https://www.elastic.co/security-labs/sandboxing-antimalware-products)
- [S12 (Medium): Windows PPL Protected Processes Light](https://medium.com/@s12deff/windows-ppl-protected-processes-light-e158332aedca)

### Behavioral Detection
- [HarfangLab: EDR with Behavioral Detection Engine - Sigma Rules](https://harfanglab.io/edr/behavioral-engine-sigma/)
- [Huntress: What is IOA in Cybersecurity](https://www.huntress.com/cybersecurity-101/topic/what-is-ioa-indicator-of-attack)
- [Kaspersky: Mapping EDR to ATT&CKs](https://www.kaspersky.com/enterprise-security/mitre/edr-mapping)
- [Fibratus: What Is an EDR - Kernel-Native Detection](https://fibratus.io/blog/what-is-an-edr-crowdstrike-telemetry)

### General EDR Architecture
- [Evading EDR (Matt Hand, No Starch Press)](https://nostarch.com/evading-edr)
- [EDR Telemetry Project](https://www.edr-telemetry.com/)
- [Wavestone: EDRSandblast](https://github.com/wavestone-cdt/EDRSandblast)
