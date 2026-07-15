# Keylogger Architectural Layers — Exhaustive Research

These are **behavioral-architecture** dimensions that change what an EDR's behavioral engine (especially CrowdStrike Falcon IOA) observes. Not implementation details like string encoding or API hashing — these change the fundamental behavioral chain.

---

## Dimension 1: Capture Method

The single most critical dimension. This is what the EDR is looking for — the mechanism that intercepts keystrokes. Each option produces a fundamentally different behavioral signature.

### 1.1 SetWindowsHookEx (WH_KEYBOARD_LL)
- **Behavioral signature**: Process calls SetWindowsHookEx with idHook=13. EDR sees the hook installation in real-time via kernel callback.
- **Detection risk**: HIGH — Falcon monitors SetWindowsHookEx at kernel level via ObRegisterCallbacks. This is the #1 keylogger indicator.
- **Why it matters**: This is what commodity keyloggers (Agent Tesla, HawkEye, Snake Keylogger) use. Every EDR has rules for it.

### 1.2 GetAsyncKeyState Polling
- **Behavioral signature**: Process enters tight loop calling GetAsyncKeyState for each virtual key (VK_A through VK_Z, etc.). High CPU if naive; low CPU if throttled with Sleep.
- **Detection risk**: LOW-MEDIUM — Legitimate software (games, accessibility tools, AutoHotkey) uses this constantly. EDR sees API calls but the pattern is ubiquitous.
- **Why it matters**: No hook installation event. No cross-process interaction. The process just reads key state from its own thread. The only signal is call frequency.
- **Variant**: Poll only for specific keys (password-entry-relevant keys) to reduce call frequency and look even more legitimate.

### 1.3 Raw Input API (RegisterRawInputDevices + WM_INPUT)
- **Behavioral signature**: Process calls RegisterRawInputDevices with RIDEV_INPUTSINK flag (to receive input even when not foreground). Creates a message-only window.
- **Detection risk**: MEDIUM — Less monitored than SetWindowsHookEx. Legitimate apps (media players, presentation remotes) use this. The RIDEV_INPUTSINK flag is the main indicator.
- **Why it matters**: Receives raw HID packets directly. Can capture input from all keyboards including USB HID devices.

### 1.4 DirectInput (IDirectInput8::CreateDevice)
- **Behavioral signature**: Process loads dinput8.dll, creates a keyboard device, sets cooperative level to DISCL_BACKGROUND|DISCL_NONEXCLUSIVE, polls GetDeviceState.
- **Detection risk**: LOW — This is literally what every DirectX game does. EDR can't distinguish a keylogger from a game without deeper behavioral analysis.
- **Why it matters**: Uses the gaming input stack. EDR teams focus on security APIs, not gaming APIs.

### 1.5 UI Automation Framework
- **Behavioral signature**: Process creates a CUIAutomation COM object, calls AddAutomationEventHandler for UIA_Text_TextChangedEventId or subscribes to TextPattern changes.
- **Detection risk**: LOW — UI Automation is a core Windows accessibility framework. Screen readers (NVDA, JAWS) use it identically. Blocking it breaks accessibility compliance.
- **Why it matters**: Doesn't capture raw keystrokes — captures the *result* of keystrokes (text changes in UI elements). This is architecturally different and much harder to distinguish from legitimate accessibility software.
- **Limitations**: Only captures text in UI Automation-aware applications. Doesn't capture passwords in masked fields (by design). Works great for browser text fields, chat apps, editors.

### 1.6 ETW Keyboard Provider
- **Behavioral signature**: Process opens an ETW trace session, subscribes to the Microsoft-Windows-USB-UCX or HID input providers. Processes ETW events.
- **Detection risk**: LOW-MEDIUM — Monitoring ETW consumers is ironic (you'd be using the telemetry system designed for EDR to capture keystrokes). Legitimate monitoring/diagnostic tools subscribe to ETW.
- **Why it matters**: The process looks like a performance monitoring or diagnostic tool. It's consuming the same telemetry stream that Sysmon/EDR uses.

### 1.7 IME (Input Method Editor) Hijacking
- **Behavioral signature**: Registers a custom IME via ImmInstallIME or registry manipulation (HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layouts). The OS loads the IME DLL automatically for all text input.
- **Detection risk**: LOW — The DLL is loaded by the OS's input processing pipeline. It runs inside legitimate processes (any process that accepts text input). Very common on CJK-locale systems.
- **Why it matters**: The keylogger DLL is loaded by the OS into every process that processes text input. No explicit hook installation. No dedicated process.
- **Variants**: TSF (Text Services Framework) — register as a Text Input Processor (TIP). Windows loads it automatically.

### 1.8 Kernel Keyboard Filter Driver
- **Behavioral signature**: Loads a kernel driver (via sc create or inf installation). Driver attaches to the keyboard device stack via IoAttachDeviceToDeviceStack. Intercepts IRPs (I/O Request Packets) to the keyboard.
- **Detection risk**: HIGH — Any driver load is heavily monitored. DSE (Driver Signature Enforcement) requires signed drivers on 64-bit Windows. Falcon's kernel callbacks see driver loads immediately.
- **Why it matters**: Complete visibility into all keystrokes before any user-mode processing. But the driver load itself is very visible.
- **Variants**: Exploit vulnerable signed driver (BYOVD — Bring Your Own Vulnerable Driver) to load unsigned code into kernel.

### 1.9 SetWinEventHook (Accessibility Events)
- **Behavioral signature**: Process calls SetWinEventHook with EVENT_OBJECT_VALUECHANGE or EVENT_OBJECT_TEXTSELECTIONCHANGED. Receives callbacks when text content changes in any window.
- **Detection risk**: LOW-MEDIUM — This is the older accessibility hook API (pre-UI Automation). Assistive technology and test automation frameworks use it.
- **Why it matters**: Captures text changes, not keystrokes directly. Similar to UI Automation but older API surface.

### 1.10 Window Subclassing / Message Interception
- **Behavioral signature**: Process calls SetWindowLongPtr(GWL_WNDPROC) on a target window to replace its window procedure, or uses SetWindowsHookEx(WH_GETMESSAGE) for message-level hooking.
- **Detection risk**: MEDIUM — WH_GETMESSAGE is less monitored than WH_KEYBOARD_LL but still visible. Window subclassing requires injection into the target process first.
- **Why it matters**: Intercepts WM_KEYDOWN/WM_CHAR messages at the window level. Can be targeted (only subclass the browser window) rather than global.

### 1.11 Clipboard Monitoring
- **Behavioral signature**: Process calls AddClipboardFormatListener or SetClipboardViewer. Receives WM_CLIPBOARDUPDATE notifications.
- **Detection risk**: LOW — Clipboard managers are legitimate software. Password managers, translation tools, and developer tools all monitor clipboard.
- **Why it matters**: Doesn't capture typing — captures copy/paste. Users frequently copy passwords from password managers. Different data type than keystrokes but captures credentials effectively.
- **Variants**: Also hook Ctrl+C detection via GetAsyncKeyState polling for VK_CONTROL + VK_C combination.

### 1.12 Browser Extension / BHO Injection
- **Behavioral signature**: Install a browser extension (Chrome, Edge, Firefox) or Browser Helper Object (legacy IE/Edge). Extension has content scripts that add event listeners to DOM input fields.
- **Detection risk**: LOW from EDR perspective — the "keylogger" runs inside the browser's JavaScript sandbox. EDR sees browser process activity, not a separate suspicious process.
- **Why it matters**: Captures form submissions, not keystrokes. Sees the *value* of input fields when submitted. Runs entirely inside the browser's legitimate process with no suspicious API calls.
- **Limitations**: Only captures browser input. Requires installation as extension (policy push or social engineering).

### 1.13 DLL Injection into Target Process
- **Behavioral signature**: Inject a DLL into a specific process (e.g., a browser or RDP client) using CreateRemoteThread, QueueUserAPC, or NtMapViewOfSection. The DLL hooks the process's input handling internally.
- **Detection risk**: HIGH for injection itself — CreateRemoteThread is heavily monitored. But once injected, the hooking happens inside the target process and is harder to observe.
- **Why it matters**: The keylogger has no standalone process. All activity appears to come from the legitimate target process.
- **Variants**: Use less-monitored injection techniques — thread hijacking, atom bombing, PROPagate technique, extra window bytes injection.

### 1.14 Named Pipe / Mailslot Sniffing
- **Behavioral signature**: Create a named pipe or mailslot that mimics a legitimate input pipeline, or monitor existing RDP/input-related named pipes.
- **Detection risk**: LOW-MEDIUM — Named pipe operations are common Windows IPC. The pipe name and access patterns matter.
- **Why it matters**: In RDP scenarios, keystrokes are transmitted via named pipes between the RDP client and server. Monitoring these captures remote desktop sessions without any keyboard hook.

### 1.15 WMI Event Consumer (Indirect Capture)
- **Behavioral signature**: Register a WMI event subscription for Win32_ProcessStartTrace or ActiveScriptEventConsumer that triggers on specific events. Doesn't capture keystrokes directly but triggers data collection on events like "browser launched" or "specific window opened."
- **Detection risk**: MEDIUM — WMI persistence is monitored by Sysmon Event 19-21. But the WMI subscription doesn't capture keystrokes itself — it triggers a short-lived collector.
- **Why it matters**: Separation of trigger mechanism from capture mechanism. The capture runs briefly and exits. The trigger is a WMI subscription that looks like monitoring.

### 1.16 Magnification API / Screen Capture Based
- **Behavioral signature**: Use MagSetImageScalingCallback or periodic screen capture (BitBlt/PrintWindow) with OCR to extract text from screen.
- **Detection risk**: LOW — Screen magnification and capture are legitimate accessibility and productivity features.
- **Why it matters**: Doesn't interact with the input pipeline at all. Captures the visual output instead. OCR extracts text. Completely different behavioral chain — no keyboard API calls whatsoever.
- **Limitations**: OCR quality, performance overhead, can't capture passwords hidden behind dots.

### 1.17 HPKP/Debug Interface Abuse
- **Behavioral signature**: Use Debug APIs (DebugActiveProcess, WaitForDebugEvent) to attach to the target process and intercept input-related API calls.
- **Detection risk**: HIGH — Debugging another process is very suspicious and monitored.
- **Why it matters**: Gets complete visibility into a process's API calls. But the debugging itself is a strong indicator.

### 1.18 Polling GetKeyboardState
- **Behavioral signature**: Similar to GetAsyncKeyState but uses GetKeyboardState to get the complete keyboard state array (256 keys) in one call.
- **Detection risk**: LOW — Single API call gets all key states. Lower call frequency than per-key GetAsyncKeyState polling.
- **Why it matters**: One call vs 256 calls per poll cycle. Less noisy.

### 1.19 Journal Record Hook (WH_JOURNALRECORD)
- **Behavioral signature**: SetWindowsHookEx with WH_JOURNALRECORD to record all input events system-wide. OS-level input recording facility.
- **Detection risk**: HIGH — This is a system-wide hook that's specifically designed for input recording. EDR knows exactly what this is.
- **Note**: Disabled on modern Windows with UIPI (User Interface Privilege Isolation) unless running as SYSTEM.

---

## Dimension 2: Process Identity

What the EDR sees as the process doing the capturing.

### 2.1 Standalone EXE
- **Behavioral signature**: New unknown process appears. EDR profiles it: origin (how it arrived), reputation (seen before?), behavior (what APIs it calls).
- **Detection risk**: MEDIUM — Unknown binary is itself a signal. Prevalence-based detection flags it.

### 2.2 DLL Loaded by Legitimate Process (DLL Sideloading)
- **Behavioral signature**: A known legitimate signed EXE (e.g., OneDrive.exe, Teams.exe) loads a DLL from a non-standard path. The keylogging behavior appears to come from the legitimate process.
- **Detection risk**: LOW-MEDIUM — The process is trusted/signed. DLL sideloading is a known technique but requires finding a vulnerable loader.
- **Why it matters**: All behavioral analysis is attributed to the legitimate process. EDR must distinguish legitimate DLL loads from malicious ones.

### 2.3 DLL Injected into Running Process
- **Behavioral signature**: An existing process (explorer.exe, svchost.exe) suddenly starts making keyboard-capture API calls. The injection itself is the main detection point.
- **Detection risk**: HIGH for injection, LOW after successful injection — if the injection isn't caught, subsequent behavior is attributed to the host process.

### 2.4 Fileless / In-Memory Only
- **Behavioral signature**: No file on disk. Payload loaded via PowerShell, WMI, or registry into memory. Process might be powershell.exe or wmiprvse.exe.
- **Detection risk**: MEDIUM — Fileless techniques are monitored (AMSI for PowerShell, WMI monitoring). But no file = no static scan.
- **Variants**: Registry-based (payload stored in registry, loaded by a stub). WMI-based (stored in WMI repository).

### 2.5 Windows Service
- **Behavioral signature**: Registered as a Windows service (sc create, registry entry under Services). Runs as SYSTEM or LOCAL SERVICE. Started by services.exe.
- **Detection risk**: MEDIUM — Service registration is logged (Sysmon Event 12/13). But once running, the process lineage (services.exe → keylogger.exe) looks normal.

### 2.6 COM Object (In-Process Server)
- **Behavioral signature**: Registered as COM InprocServer32. Loaded by any process that CoCreateInstance's the CLSID. No dedicated process.
- **Detection risk**: LOW — COM objects are loaded constantly by Windows. The DLL runs inside the calling process. COM registration is logged but COM object loading is ubiquitous.
- **Why it matters**: The keylogger has no process. It's a DLL loaded inside svchost, explorer, or any COM host.

### 2.7 Masquerading as Known Software
- **Behavioral signature**: Binary named and versioned to look like legitimate software (e.g., "RuntimeBroker.exe", "SearchIndexer.exe"). File metadata (version info, description) matches legitimate software.
- **Detection risk**: LOW-MEDIUM — Name-based masquerade is easy. Metadata masquerade helps. But process-path mismatch (real RuntimeBroker.exe is in System32, yours is on Desktop) can be detected.

### 2.8 Script-Based (PowerShell, VBScript, JScript)
- **Behavioral signature**: powershell.exe or wscript.exe runs a script that calls keyboard capture APIs via .NET interop or COM.
- **Detection risk**: HIGH — AMSI inspects script content. PowerShell logging captures the full script. EDR has extensive PowerShell behavioral rules.

### 2.9 .NET Assembly Loaded Reflectively
- **Behavioral signature**: A .NET assembly loaded via Assembly.Load(byte[]) into an existing .NET process. No file on disk.
- **Detection risk**: MEDIUM — .NET Assembly loading is monitored (ETW Microsoft-Windows-DotNETRuntime). But the technique is used by legitimate plugin architectures.

### 2.10 Scheduled Task Script
- **Behavioral signature**: schtasks creates a task that runs a script or binary periodically. Task Scheduler service (svchost -k netsvcs) is the parent process.
- **Detection risk**: MEDIUM — Schtasks creation is logged by Sysmon Event 1 and multiple Sigma rules. But the parent process (svchost → taskeng.exe/taskhostw.exe) is normal.

---

## Dimension 3: Persistence Model

How the keylogger survives reboots and stays active. This shapes the long-term behavioral pattern the EDR observes.

### 3.1 Always-Running Process
- **Behavioral signature**: Process starts at boot, runs continuously. Constant presence in process list.
- **Detection risk**: MEDIUM — Long-lived unknown processes can be profiled over time. Behavioral analysis has more data to work with.
- **EDR sees**: Continuous CPU usage, persistent network connections, never-ending process lifetime.

### 3.2 Periodic Relaunch (Burst Capture)
- **Behavioral signature**: schtasks runs keylogger every N minutes. Each instance captures for a short period, then exits. No persistent process.
- **Detection risk**: LOW-MEDIUM — Short-lived processes generate less behavioral data. Schtasks creation itself is the main indicator.
- **EDR sees**: Brief process → keyboard API calls → exit. Repeated pattern over time, but each individual instance looks innocuous.
- **Why it matters**: Falcon's IOA needs behavioral chains. A process that lives for 30 seconds doesn't give it enough chain links.

### 3.3 Event-Driven (WMI Event Subscription)
- **Behavioral signature**: WMI EventFilter triggers on specific events (user logon, browser launch, network connection). EventConsumer starts the keylogger only when the trigger fires.
- **Detection risk**: MEDIUM — WMI subscription creation is well-monitored (Sysmon 19-21, Sigma rules). But the triggered execution is hard to predict.
- **EDR sees**: WMI subscription → trigger event → brief keylogger process → exit. The capture only happens when relevant (e.g., user opens banking site).

### 3.4 Parasitic (Inside Existing Persistent Process)
- **Behavioral signature**: Keylogger code injected into explorer.exe, svchost.exe, or another always-running process. No separate process.
- **Detection risk**: HIGH for injection, LOW ongoing — if injection succeeds, the keylogger is invisible as a process. All behavior attributed to host.
- **EDR sees**: explorer.exe making keyboard capture calls — which it already does legitimately. Very hard to distinguish.

### 3.5 DLL Search-Order Hijacking
- **Behavioral signature**: Malicious DLL placed where a legitimate application loads it (DLL search order hijack). Application launches at boot, loads the keylogger DLL.
- **Detection risk**: LOW — The legitimate application's launch is expected. The DLL load looks normal. No process injection, no hook installation, no schtasks.
- **Why it matters**: The persistence mechanism is invisible — it's the normal launch of a legitimate application. The keylogger runs as a DLL inside that application.

### 3.6 Registry Run Key / Startup Folder
- **Behavioral signature**: Registry key or LNK file causes keylogger to start on logon.
- **Detection risk**: MEDIUM — Registry Run keys are monitored by Sysmon Event 12/13 and multiple detection rules.

### 3.7 COM Hijacking
- **Behavioral signature**: Replace or redirect a frequently-used COM CLSID to the keylogger DLL. When any process CoCreates that CLSID, the keylogger loads.
- **Detection risk**: LOW-MEDIUM — COM registration changes are logged but there are thousands of COM objects. The load is attributed to whichever process instantiates the COM object.

### 3.8 AppInit_DLLs / Image File Execution Options
- **Behavioral signature**: AppInit_DLLs registry key causes DLL to load into every process that loads user32.dll. IFEO registers a "debugger" that launches instead of the target.
- **Detection risk**: HIGH for AppInit_DLLs (well-known, monitored). MEDIUM for IFEO (less commonly checked).

### 3.9 Group Policy / Logon Script
- **Behavioral signature**: Script added to Group Policy logon scripts. Executes under domain context at every logon.
- **Detection risk**: LOW-MEDIUM — Requires domain admin. But in AD environments, logon scripts are expected. EDR sees script execution under winlogon context.

### 3.10 Print Monitor / Port Monitor
- **Behavioral signature**: Register as a print monitor DLL (HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors). spoolsv.exe loads the DLL.
- **Detection risk**: LOW — Print monitor registration is rarely monitored. DLL runs inside the Print Spooler service (SYSTEM privileges).

---

## Dimension 4: Data Buffering

Where captured keystrokes accumulate before exfiltration. This affects forensic visibility.

### 4.1 In-Process Memory Buffer
- **Behavioral signature**: Keystrokes stored in heap-allocated buffer. No disk writes. Volatile — lost on crash/reboot.
- **Detection risk**: LOW — Nothing written to disk. Memory scanning could find it but must know what to look for.

### 4.2 Memory-Mapped File (Shared Memory)
- **Behavioral signature**: CreateFileMapping with named or unnamed section. Can be shared between processes.
- **Detection risk**: LOW — Shared memory is common IPC. No actual file on disk (if backed by pagefile).

### 4.3 Registry Values
- **Behavioral signature**: Keystrokes written to registry values, possibly encrypted. RegSetValueEx calls to unusual locations.
- **Detection risk**: MEDIUM — Registry writes are logged by Sysmon Event 12/13. But the volume of registry writes in Windows is enormous.
- **Why it matters**: Registry is persistent. Data survives reboot. But it's also a well-known staging location for malware.

### 4.4 Alternate Data Streams (ADS)
- **Behavioral signature**: Data written to NTFS alternate data stream on an existing file (e.g., desktop.ini:keylog). Not visible in normal dir listings.
- **Detection risk**: LOW-MEDIUM — ADS writes are logged by Sysmon Event 15. But ADS is used by legitimate Windows features (Zone.Identifier).
- **Why it matters**: Hidden from normal file browsing. Data attached to existing legitimate files.

### 4.5 Append to Legitimate Log Files
- **Behavioral signature**: Keystrokes appended to an existing log file (e.g., a Windows event log, application log, or temp file). Mixed with legitimate content.
- **Detection risk**: LOW — File writes to log directories are expected behavior. The data is hidden in plain sight.

### 4.6 Named Pipe to Separate Process
- **Behavioral signature**: Capture process sends keystrokes via named pipe to a separate exfiltration process.
- **Detection risk**: LOW — Named pipe IPC is common. Separates capture from exfil (different process identities).
- **Why it matters**: Separation of concerns — the capture process never touches the network, the exfil process never touches keyboard APIs. Neither process individually looks malicious.

### 4.7 Encrypted Temporary Files
- **Behavioral signature**: Encrypted keystroke data written to temp files with random names. Periodically read and deleted by exfil process.
- **Detection risk**: MEDIUM — Temp file creation + deletion patterns can be profiled. But %TEMP% has enormous write volume normally.

### 4.8 WMI Repository
- **Behavioral signature**: Store data as WMI class properties. Persistent across reboots. Retrieved via WMI queries.
- **Detection risk**: LOW — WMI repository writes are not commonly monitored at the data level.

### 4.9 Steganography in Existing Files
- **Behavioral signature**: Encode keystrokes into LSB of image files or metadata of documents already on disk. Files appear unchanged.
- **Detection risk**: VERY LOW — Files look normal. No new files created. Data is invisible without the extraction key.

---

## Dimension 5: Exfiltration Trigger

When captured data leaves the system.

### 5.1 Buffer Size Threshold
- **Behavioral signature**: Outbound connection triggered when buffer reaches N bytes. Irregular timing, data-dependent intervals.
- **Detection risk**: LOW — Irregular timing makes it harder to profile as a beacon pattern.

### 5.2 Fixed Interval (Timer-Based)
- **Behavioral signature**: Outbound connection every N minutes/hours regardless of data volume.
- **Detection risk**: MEDIUM — Regular intervals are detectable as beacon behavior (Falcon specifically looks for this).

### 5.3 User Idle Detection
- **Behavioral signature**: Exfiltrate only when user is idle (GetLastInputInfo shows no input for N minutes, or screensaver active).
- **Detection risk**: LOW — Network activity when user is idle is less visible. No user at the console to notice anything. Blends with Windows Update, OneDrive sync, and other idle-time activities.

### 5.4 Application-Specific Trigger
- **Behavioral signature**: Exfiltrate only after specific events — browser closed (indicating form submission complete), user switches from banking site to another tab, RDP session ends.
- **Detection risk**: LOW — Targeted exfiltration reduces data volume and network events. Fewer opportunities for EDR to build a pattern.

### 5.5 Never Exfiltrate (Local Storage Only)
- **Behavioral signature**: No outbound connections at all. Data stored locally, retrieved by a separate implant or physical access.
- **Detection risk**: VERY LOW — No network indicators. The keylogger is purely a local data collection tool.
- **Why it matters**: Completely eliminates the network behavioral chain. EDR can't use network analysis at all.

### 5.6 Piggybacked on Legitimate Traffic
- **Behavioral signature**: Data exfiltrated as part of legitimate application activity — embedded in browser requests, appended to OneDrive sync, included in Teams messages.
- **Detection risk**: LOW — Traffic originates from legitimate processes. Content inspection might catch it but encrypted channels (HTTPS) prevent deep inspection.

### 5.7 On-Demand (C2 Retrieval)
- **Behavioral signature**: Keylogger stores data locally. A separate C2 implant retrieves it on operator command.
- **Detection risk**: LOW — Separates collection from exfiltration entirely. Neither component independently looks suspicious.

---

## Dimension 6: Exfiltration Channel

The medium through which data leaves the system. Architectural choices, not transport-level details.

### 6.1 Direct Outbound Connection (TCP/UDP/HTTP)
- **Behavioral signature**: Process opens connection to external IP, sends data. New outbound connection from unknown/unexpected process.
- **Detection risk**: MEDIUM — New outbound connections from unknown processes are flagged. IP reputation checks.

### 6.2 DNS Tunneling / DNS-Based
- **Behavioral signature**: Unusually high volume of DNS queries with encoded data in subdomains (e.g., base32data.exfil.attacker.com). Or DNS TXT record responses containing data.
- **Detection risk**: MEDIUM — DNS tunneling detection exists but requires DNS-layer inspection. Many orgs don't monitor DNS payload content.

### 6.3 Cloud Storage Dead Drop
- **Behavioral signature**: Process uploads data to legitimate cloud services — OneDrive, Google Drive, Dropbox, S3 buckets. HTTPS traffic to Microsoft/Google/AWS IPs.
- **Detection risk**: LOW — HTTPS to major cloud providers is expected. Content is encrypted in transit. The process making the API call might be suspicious, but if done via a legitimate client (OneDrive.exe), it's invisible.

### 6.4 Email-Based Exfiltration
- **Behavioral signature**: Process connects to SMTP server or uses Outlook COM automation to send email with keystroke data.
- **Detection risk**: LOW-MEDIUM — SMTP connections from unexpected processes are a signal. But using the installed Outlook client via COM is much stealthier.

### 6.5 Legitimate Messaging Services
- **Behavioral signature**: Data sent via Slack API, Discord webhook, Telegram Bot API, Microsoft Teams webhook. HTTPS POST to legitimate service endpoints.
- **Detection risk**: LOW — These are legitimate HTTPS connections to well-known services. Webhook URLs are not reputation-flagged.

### 6.6 ICMP Tunneling
- **Behavioral signature**: Data embedded in ICMP echo request/reply payloads. ping.exe or raw socket ICMP.
- **Detection risk**: LOW-MEDIUM — ICMP is often allowed through firewalls. Payload inspection is rare. But raw sockets on Windows require administrator.

### 6.7 Steganographic Upload
- **Behavioral signature**: Data encoded into images or files, uploaded to legitimate image hosting, social media, or file sharing services.
- **Detection risk**: VERY LOW — The upload looks like normal user activity. The file appears to be a regular image.

### 6.8 Physical / USB Exfiltration
- **Behavioral signature**: Data written to USB drive when inserted. No network activity.
- **Detection risk**: LOW for network monitoring — no network indicators. DLP solutions may detect USB writes.

### 6.9 Bluetooth / WiFi Direct
- **Behavioral signature**: Data exfiltrated via Bluetooth or WiFi Direct to nearby receiver device.
- **Detection risk**: VERY LOW — Out-of-band channel that most EDR doesn't monitor.

### 6.10 SMB / Named Pipe (Intra-Network)
- **Behavioral signature**: Data sent to internal file share or named pipe to another compromised machine, which then exfiltrates.
- **Detection risk**: LOW — Internal SMB traffic is normal. The actual internet exfil happens from a different machine.

### 6.11 Print Queue / Fax
- **Behavioral signature**: Data "printed" to a network printer or fax modem that the attacker controls.
- **Detection risk**: VERY LOW — Print traffic is rarely monitored for data exfiltration.

---

## Dimension 7: Operational Tempo

When the keylogger actively captures, which shapes the behavioral pattern.

### 7.1 Continuous (24/7)
- **Behavioral signature**: Always capturing. Constant CPU usage pattern. Continuous API calls.
- **Detection risk**: MEDIUM — Long-lived activity gives EDR more data to profile.

### 7.2 Business Hours Only
- **Behavioral signature**: Active Mon-Fri 9-5. Dormant outside work hours.
- **Detection risk**: LOW — Matches human work patterns. Reduces total observation window for EDR.

### 7.3 Foreground Application-Based
- **Behavioral signature**: Only captures when specific applications are in foreground (browser, email client, RDP). Dormant otherwise.
- **Detection risk**: LOW — Targeted capture dramatically reduces activity volume. The keylogger is dormant most of the time.
- **Why it matters**: A keylogger that only activates when the user opens Chrome is nearly invisible during the 95% of time Chrome isn't in foreground.

### 7.4 URL/Site-Specific (Banking Trojan Model)
- **Behavioral signature**: Monitors window titles. Activates only when specific URLs (banking, email, VPN) are detected.
- **Detection risk**: LOW — Extremely low duty cycle. Captures only the highest-value keystrokes (credentials).
- **Why it matters**: This is how Zeus, SpyEye, and other banking trojans work. Minimal footprint, maximum value.

### 7.5 Burst Capture (N on, M off)
- **Behavioral signature**: Captures for 5 minutes every 30 minutes. Creates a periodic on/off pattern.
- **Detection risk**: LOW-MEDIUM — Each burst is short enough that behavioral analysis has limited data. But the periodicity itself could be a signal.

### 7.6 Event-Triggered
- **Behavioral signature**: Only captures after specific trigger events — network connection change (VPN connected), USB inserted, user logged in, specific process started.
- **Detection risk**: LOW — Captures only during high-value moments. Dormant the vast majority of the time.

### 7.7 Human-Paced (Randomized)
- **Behavioral signature**: Capture windows randomized to match natural human activity patterns. Active 2-8 minutes, idle 10-45 minutes, longer gaps during night hours.
- **Detection risk**: LOW — No detectable periodicity. Activity pattern is statistically indistinguishable from normal user behavior.

---

## Dimension 8: Context Enrichment

What metadata accompanies keystrokes, which changes what the keylogger needs to access.

### 8.1 Raw Keystrokes Only
- **Behavioral signature**: Minimal API calls. Just keyboard state polling. No window management or screen capture APIs.
- **Detection risk**: LOWEST — Smallest behavioral footprint. But least useful data.

### 8.2 Window Title Tracking
- **Behavioral signature**: GetForegroundWindow + GetWindowText to track which application/website receives keystrokes.
- **Detection risk**: LOW — These are benign API calls. Many legitimate applications track foreground window.
- **Why it matters**: Associates keystrokes with context (which site, which app). Essential for parsing credentials.

### 8.3 Screenshot on Context Switch
- **Behavioral signature**: Periodic or event-driven screen capture using GDI (GetDC, BitBlt, GetDIBits).
- **Detection risk**: LOW-MEDIUM — Screen capture APIs are legitimate (Snipping Tool, screenshotting). But combined with keyboard capture, the chain becomes more suspicious.
- **Why it matters**: Visual evidence of what was on screen when keystrokes were captured. But adds a significant behavioral signal (bitmap creation, GDI calls).

### 8.4 Clipboard Monitoring
- **Behavioral signature**: AddClipboardFormatListener + GetClipboardData.
- **Detection risk**: LOW — Clipboard managers are common. Adding this doesn't significantly change the profile if already capturing keystrokes.

### 8.5 Process/URL Tracking
- **Behavioral signature**: Enumerate browser tabs via UI Automation, COM (IWebBrowser2), or accessibility APIs. Track URLs in browser address bar.
- **Detection risk**: LOW-MEDIUM — More sophisticated context gathering. The COM/accessibility API calls add to the behavioral footprint.

### 8.6 Audio Capture
- **Behavioral signature**: waveInOpen or WASAPI (IAudioCaptureClient) to record microphone input.
- **Detection risk**: MEDIUM — Audio capture APIs are monitored by some EDR. OS may show microphone-in-use indicator (Windows 10+).

### 8.7 Webcam Capture
- **Behavioral signature**: DirectShow/Media Foundation camera access.
- **Detection risk**: MEDIUM-HIGH — Camera access triggers OS indicator light and may show in-use notification.

---

## APT vs Commodity Keylogger Architectural Differences

### Commodity (Agent Tesla, HawkEye, Snake Keylogger)
- **Architecture**: Monolithic .NET binary → SetWindowsHookEx → buffer in memory → SMTP/FTP/Telegram exfil → timer-based (every N minutes)
- **Detection**: Well-signatured, AMSI catches .NET payloads, behavioral rules exist
- **Why caught**: Known packer signatures, .NET reflection detectable, predictable SMTP exfil pattern

### APT Keyloggers (APT29 WellMess/WellMail, Turla Carbon, APT28 X-Agent)
- **Architecture**: Native C/C++ → targeted capture (specific apps only) → encrypted local staging → C2-commanded retrieval → multi-hop exfil
- **Key differences**:
  1. Modular — keylogger is one module loaded on-demand, not the whole implant
  2. Targeted — only captures during high-value windows (email client, browser to specific domains)
  3. Operator-paced — data retrieved by human operator, not automated timer
  4. Multi-stage exfil — data goes through intermediary machines before reaching C2
  5. Clean operation — removes traces, clears logs, timestamps matches legitimate activity

### Red Team Tools
- **Cobalt Strike**: Uses SetWindowsHookEx in beacon. Heavily signatured now.
- **Mythic**: Modular agents (Apollo, Athena) — keylogger is a loaded command module. Short-lived capture by default.
- **Sliver**: Session-based keylogging. Uses GetAsyncKeyState for stealth. In-beacon buffering.
- **Brute Ratel (BRC4)**: Most advanced — uses undocumented API calls, targets specific input pipelines per-application.

---

## What CrowdStrike Falcon Specifically Detects

Based on public documentation and red team reports:

1. **SetWindowsHookEx(WH_KEYBOARD_LL)** — Direct kernel callback detection. Cannot be evaded from usermode.
2. **High-frequency GetAsyncKeyState** — Detects polling patterns that exceed normal application behavior (>50 calls/sec for all key codes).
3. **Process reputation** — Unknown binary with no reputation that captures keyboard input. Prevalence scoring.
4. **Behavioral chain**: Process creation → keyboard API calls → buffer accumulation → network connection = IOA trigger.
5. **Injection + keyboard capture** — If a process is injected into (detected) and then starts making keyboard capture calls, that's a strong chain.
6. **Credential context** — Keyboard capture specifically during credential entry (banking sites, login forms) detected via URL monitoring.

### What Falcon misses (based on red team reports)
1. Low-frequency GetAsyncKeyState polling (< 10/sec, selective keys only)
2. UI Automation-based capture (indistinguishable from screen readers)
3. Clipboard-only monitoring (no keyboard hook)
4. Legitimate-process DLL sideloading with GetAsyncKeyState (process is trusted, API is benign, frequency is low)
5. Browser extension-based capture (runs in browser sandbox, no suspicious API calls)

---

## Summary: Highest-Impact Architectural Layers for Framework

In priority order of evasion impact:

1. **Capture Method** (19 options) — Largest impact. Switching from SetWindowsHookEx to GetAsyncKeyState/UI Automation/clipboard fundamentally changes what Falcon observes.
2. **Process Identity** (10 options) — DLL sideloading or COM hijacking eliminates the "unknown process" signal entirely.
3. **Persistence Model** (10 options) — Periodic relaunch vs always-running vs parasitic changes the temporal behavioral pattern completely.
4. **Exfiltration Channel** (11 options) — Cloud dead drop or legitimate service abuse eliminates the suspicious outbound connection.
5. **Operational Tempo** (7 options) — Targeted/burst capture reduces behavioral data available to EDR.
6. **Data Buffering** (9 options) — Named pipe separation breaks the single-process behavioral chain into two innocent-looking halves.
7. **Exfiltration Trigger** (7 options) — Idle-time or event-driven exfil avoids suspicious timing patterns.
8. **Context Enrichment** (7 options) — Each additional data type adds API calls and detection surface. Less is more for evasion.
