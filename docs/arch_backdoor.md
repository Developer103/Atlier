# Backdoor / RAT / C2 Implant — Architectural Layers

Each dimension below changes the **behavioral chain** an EDR's IOA engine observes. These are not implementation details (string encoding, API hashing) — they change the fundamental shape of what the implant looks like to kernel-level behavioral analysis.

---

## 1. C2 Paradigm

The communication model is the single most detectable architectural choice. Falcon's IOA engine is specifically tuned for beacon patterns.

| # | Option | Behavioral Profile Change | Real-World Example |
|---|--------|--------------------------|-------------------|
| 1 | Active beacon (periodic poll) | Regular outbound connections with jitter — the classic IOA target. Sleep-connect-receive-execute-report cycle is the most-detected pattern. | Cobalt Strike default, Meterpreter |
| 2 | Passive listener (bind shell) | No outbound connections at all. Implant opens a port and waits. EDR sees a listening socket on a non-standard port — different chain than beacon. | Netcat bind shell, some Turla implants |
| 3 | Dead-drop: cloud storage | Reads/writes to OneDrive, Google Drive, Dropbox, S3. Traffic goes to legitimate Microsoft/Google/Amazon IPs over HTTPS. Indistinguishable from normal cloud sync. | APT29 used OneDrive/Google Drive C2 in 2022 |
| 4 | Dead-drop: paste sites | Poll Pastebin, GitHub Gists for encoded commands. HTTPS to legitimate domains. | APT34 (OilRig) used paste sites |
| 5 | Dead-drop: social media | Commands in Twitter posts, Reddit comments, Instagram metadata, Telegram channels. Normal social media API calls. | Turla Instagram comments, Hammertoss (APT29) Twitter |
| 6 | Dead-drop: DNS TXT records | Commands as DNS TXT records on attacker domain. Only DNS queries — no TCP/HTTP connections. | DNSMessenger, multiple APT groups |
| 7 | Triggered: magic packet | Sniffs raw packets waiting for specific pattern. Zero network activity until triggered. EDR sees dormant process. | Equation Group YOURTYPE, CD00R |
| 8 | Triggered: file drop | Monitors directory (ReadDirectoryChangesW) for trigger file. No network from the implant process. | APT-style staged operations |
| 9 | Triggered: registry change | Watches registry key (RegNotifyChangeKeyValue). Another process sets the key to trigger. Decouples C2 channel from implant. | Custom APT techniques |
| 10 | Triggered: WMI event | WMI subscription fires on condition. Implant has no polling loop. | APT29 WMI usage |
| 11 | Triggered: named pipe | Creates named pipe and waits. Commands from another process. No network from this process. | Cobalt Strike SMB beacon, PoshC2 |
| 12 | Piggyback: browser injection | Inject into browser, use its HTTPS sessions. C2 is the browser making requests. | Zeus/SpyEye, some APT28 tools |
| 13 | Piggyback: legitimate app API | Use Slack webhook, Teams connector, Discord bot. Traffic is that app's normal protocol. | DCRAT Discord C2, Slackbot C2 |
| 14 | Proxy chain / P2P mesh | Only talks to another compromised host. One node phones home. Individual implants show only internal traffic. | Cobalt Strike SMB chains, Turla P2P mesh |
| 15 | Out-of-band (split channel) | Commands via DNS, results via HTTPS. No single channel carries a recognizable C2 conversation. | Lazarus Group split-channel implants |
| 16 | Email-based C2 | Read IMAP/POP3 mailbox for commands, send results as attachments. Standard email traffic. | Turla Outlook backdoor |
| 17 | Legitimate service polling | Check GitHub commit, RSS feed, blockchain memo, CDN config for encoded commands. HTTPS GETs to trusted domains. | APT41 GitHub C2 |
| 18 | Covert channel: ICMP | Commands in ICMP echo payloads. No TCP/UDP connections. | Pingback, ICMPsh |
| 19 | Covert channel: timing | Info encoded in packet timing or cache behavior. Nearly invisible. | Academic PoCs, state-level |
| 20 | WebSocket persistent | HTTPS upgrade to WebSocket. Looks like a web app real-time channel. | Mythic HTTP profile |
| 21 | Serverless function C2 | AWS Lambda / Azure Functions / Cloudflare Workers. New IP per request. Domain is *.amazonaws.com. | RedTeam Lambda C2 |
| 22 | CDN / domain fronting | HTTPS to CDN edge. SNI shows legitimate domain, Host header routes to attacker. | APT29 domain fronting, Cobalt Strike malleable C2 |

---

## 2. Execution Model

How the implant stays alive and when it runs.

| # | Option | Behavioral Profile Change | Real-World Example |
|---|--------|--------------------------|-------------------|
| 1 | Persistent process | Long-lived, always in memory. Easiest to detect — anomalous process for hours/days. | Most commodity RATs |
| 2 | Periodic relaunch (ephemeral) | Runs seconds/minutes, does one task, exits. Scheduler relaunches. No persistent process to profile. | APT32 schtasks relaunch |
| 3 | On-demand activation | Dormant on disk until external trigger starts it. Zero behavioral signal between activations. | Targeted APT operations |
| 4 | Fileless: registry storage | Payload in registry value (encoded). Small launcher reads and executes in memory. No file on disk. | Kovter, APT28 fileless |
| 5 | Fileless: WMI subscription | Payload in WMI consumer. wmiprvse.exe executes it. No custom process. | APT29 |
| 6 | Process parasitism (injection) | Injected into explorer.exe, svchost.exe, etc. No new process. | Nearly all advanced APTs |
| 7 | Windows service | Registered service, runs as SYSTEM under services.exe. Looks legitimate. | APT41 |
| 8 | COM object | In-proc COM server loaded by legitimate consumers on demand. Runs inside consuming process. | Turla COM hijack, DarkHotel |
| 9 | DLL search order hijack | DLL placed where legitimate exe searches first. Runs inside trusted signed process. | APT41, supply-chain attacks |
| 10 | Thread pool abuse | Queue work items to existing process thread pool. No suspicious thread creation. | Advanced red team tools |
| 11 | Callback-based execution | Register PTP_WORK/PTP_TIMER/PTP_WAIT callbacks. Code runs in Windows thread pool context. | Ekko sleep obfuscation |
| 12 | Fiber-based execution | Convert thread to fiber, switch in usermode. EDR kernel callbacks miss context switches. | Phantom thread technique |
| 13 | Exception handler chain | VEH/SEH handlers triggered by intentional exceptions. Unusual execution path. | Anti-analysis techniques |
| 14 | APC injection (early bird) | APC queued to suspended process. Runs before target entry point, before EDR instruments it. | Early Bird injection |

---

## 3. Command Execution Strategy

How commands are carried out — determines process-creation chains EDR sees.

| # | Option | Behavioral Profile Change | Real-World Example |
|---|--------|--------------------------|-------------------|
| 1 | In-process API calls | All via Windows API in own process. Zero child processes. No parent-child chain. | Brute Ratel, custom APT |
| 2 | cmd.exe child | Spawns cmd.exe /c. Obvious parent-child chain IOA rules target. | Most commodity RATs |
| 3 | powershell.exe child | Spawns powershell.exe. AMSI, ScriptBlock logging, heavily monitored. | PowerShell Empire |
| 4 | LOLBins | certutil, bitsadmin, mshta, wmic, regsvr32, rundll32. Each has own detection profile. | Nearly all APT groups |
| 5 | Inject into target process | Inject code into process with needed access. No child creation. | Advanced credential access |
| 6 | WMI execution | IWbemServices::ExecMethod. Command runs as child of wmiprvse.exe. Breaks parent chain. | APT29, Lazarus |
| 7 | Scheduled task execution | One-shot task. Execution parent is svchost.exe Task Scheduler. Clean parent chain. | Multiple APT groups |
| 8 | COM object instantiation | WScript.Shell, MMC20.Application, ShellBrowserWindow. Runs in COM server process. | DCOM lateral, Turla |
| 9 | .NET CLR hosting | Load CLR (ICLRRuntimeHost). Execute C# without spawning powershell.exe or csc.exe. | Cobalt Strike execute-assembly |
| 10 | Embedded script engine | Lua, ChakraCore, embedded Python. Complex ops without external interpreters. | Some Mythic agents |
| 11 | Direct syscalls | Bypass ntdll entirely. EDR usermode hooks see nothing. Kernel EDR still sees syscalls. | SysWhispers, HellsGate |
| 12 | Indirect syscalls | Route through legitimate ntdll code. Return address points to ntdll. Defeats stack analysis. | SysWhispers3 |
| 13 | DLL proxy loading | Load legitimate DLL, call its exports. Using legitimate code, not custom implementation. | DLL proxying |
| 14 | API sets redirection | Abuse API set resolution to redirect calls through implant DLLs. | Research-stage |

---

## 4. Network Profile

Traffic pattern for network-level behavioral analysis.

| # | Option | Behavioral Profile Change | Real-World Example |
|---|--------|--------------------------|-------------------|
| 1 | Raw TCP custom port | Anomalous outbound connection. Easy to spot. | Basic reverse shells |
| 2 | HTTPS attacker domain | Encrypted to unknown domain. Cert/reputation flags possible. | Most modern C2 |
| 3 | HTTPS domain fronting | SNI shows legitimate domain, Host header routes to attacker. Traffic to trusted CDN. | APT29, Cobalt Strike |
| 4 | HTTPS legitimate SaaS | Traffic to api.github.com, graph.microsoft.com, api.slack.com. Legitimate certs and domains. | APT29 OneDrive C2, Discord RATs |
| 5 | DNS-only | All C2 in DNS queries. No TCP connections. Blends with DNS resolution. | DNSMessenger, CS DNS beacon |
| 6 | DNS over HTTPS (DoH) | DNS tunneled via HTTPS to 1.1.1.1 or 8.8.8.8. Even DNS monitoring can't inspect. | Godlua, BazarLoader |
| 7 | SMB named pipes | Windows file sharing. Normal on domain networks. Internal only. | Cobalt Strike SMB beacon |
| 8 | ICMP | Data in ping packets. Often allowed through firewalls. | Pingback, ICMPsh |
| 9 | WebSocket | Single upgrade, persistent bidirectional. Looks like web app feature. | Mythic WebSocket |
| 10 | HTTP/2 multiplexing | C2 streams mixed with legitimate requests on same connection. | Advanced C2 profiles |
| 11 | Protocol mimicry | Traffic shaped to match Teams, OneDrive, Windows Update, Chrome telemetry byte patterns. | CS malleable C2 profiles |
| 12 | WinRM / PS Remoting | Legitimate Windows remote management. Expected on domain networks. | APT groups using legit admin channels |
| 13 | RDP virtual channels | C2 inside RDP protocol stream during active sessions. | SocGholish-style |
| 14 | QUIC / HTTP/3 | UDP-based encrypted. Many inspection tools don't parse it. | Emerging transport |
| 15 | Legitimate protocol tunnel | Valid HTTPS/DNS/SMTP outer layer with encrypted C2 payload inside. | Standard for advanced C2 |

---

## 5. Persistence Architecture

| # | Option | Behavioral Profile Change | Real-World Example |
|---|--------|--------------------------|-------------------|
| 1 | Always-on process | Continuous presence. Easy to profile. | Basic RATs |
| 2 | Periodic relaunch (schtasks) | Short-lived, repeated. No long-lived process. | APT32 |
| 3 | Periodic relaunch (WMI timer) | Execution from wmiprvse.exe. Different parent than schtasks. | APT29 |
| 4 | Event-triggered (user logon) | Runs only after logon. Natural correlation reduces suspicion. | Common APT pattern |
| 5 | Event-triggered (process start) | Activates when target app launches. Zero activity otherwise. | Banking trojans |
| 6 | Event-triggered (network change) | Activate on VPN connect, domain reachable. Dormant on test networks. | Sandbox-aware implants |
| 7 | Parasitic DLL | Loaded by explorer/svchost. No separate process. | Turla, APT41 |
| 8 | Registry Run key | HKCU Run. Simple, well-known, monitored. | Commodity malware fallback |
| 9 | Startup folder | Shell:startup shortcut. Simple. | Commodity malware |
| 10 | COM hijack | Override InProcServer32 for frequent CLSID. Legitimate process loads DLL via COM. No Run key. | Turla, DarkHotel |
| 11 | DLL search order hijack | DLL in directory auto-start program searches. No malicious autostart entry. | APT41, SolarWinds |
| 12 | IFEO debugger | Debugger for common exe. Your code runs when target launches. | StickyKeys backdoor, APT3 |
| 13 | Print monitor | Print monitor DLL loaded by spoolsv.exe at boot. Runs as SYSTEM. | DePriMon loader |
| 14 | Network provider | Loaded at logon. Can intercept credentials. | Custom APT tools |
| 15 | AppInit_DLLs | Loaded into every user32.dll process. Very broad. | Some commodity malware |
| 16 | Security Support Provider | SSP in LSA. Loaded by lsass.exe. Intercept credentials. | Mimikatz mimilib |
| 17 | Bootkit / UEFI | Before OS and EDR. Survives reinstall. Complex. | BlackLotus, MosaicRegressor |
| 18 | Supply chain | Modify legitimate update mechanism. Persistence via legit auto-update. | SolarWinds SUNBURST |
| 19 | None (one-shot redeploy) | No persistence. Fresh binary each time. | High-OPSEC targeted ops |
| 20 | WMI permanent subscription | Survives reboots. Via wmiprvse.exe. No files if fileless payload. | APT29, Turla |
| 21 | GPO deployment | AD Group Policy deploys implant to domain machines. | APT28 post-compromise |
| 22 | Accessibility replacement | Replace sethc.exe/utilman.exe. Triggered from login screen. Runs as SYSTEM. | APT3, APT41 |

---

## 6. Operational Security Model

| # | Option | Behavioral Profile Change | Real-World Example |
|---|--------|--------------------------|-------------------|
| 1 | Time-limited operation | Active only business hours. Zero signal off-hours. | APT29, most sophisticated APTs |
| 2 | Geofenced | Check locale, timezone, keyboard, IP geolocation. Refuse outside target geography. | Turla, Lazarus |
| 3 | Execution guardrails | Check domain, hostname, username, software. Only execute on intended target. | APT29 SUNBURST domain checks |
| 4 | Self-destruct timer | Auto-remove after N days or if no C2 contact. Limits forensic window. | APT28 kill dates |
| 5 | Canary-aware | Detect honeypots, decoy creds, analysis processes. Abort if deception detected. | Advanced APT tools |
| 6 | Staged revelation | Minimal initial implant. More capabilities only after environment confirmed safe. | CS staged, Brute Ratel |
| 7 | Anti-forensics | Timestomp, clear logs, remove prefetch, delete USN journal. | APT28 |
| 8 | Volume-aware | Throttle activity based on network traffic volume. Operate during high-traffic only. | Sophisticated APT ops |
| 9 | Process environment validation | Check for EDR, analysis tools, VM before activating. Dormant in analysis. | Nearly all advanced malware |
| 10 | Credential-gated | Require password to activate. Appears benign without key. | Some targeted implants |

---

## 7. Multi-Stage Architecture

| # | Option | Behavioral Profile Change | Real-World Example |
|---|--------|--------------------------|-------------------|
| 1 | Monolithic | Single binary, all functionality. Simple. If caught, everything exposed. | Most commodity RATs |
| 2 | Staged (loader-stager-implant) | Small loader, downloads stager, stager loads full implant. Each independently replaceable. | Cobalt Strike, Metasploit |
| 3 | Modular (core + plugins) | Minimal C2 core. Capability modules loaded on demand, never on disk. | Turla Carbon/Gazer, PlugX, ShadowPad |
| 4 | Cooperative (multi-binary) | Multiple small binaries each doing ONE thing. Coordinated via shared state. Capturing one reveals nothing about others. | Some APT operations |
| 5 | Disposable (phase-specific) | Different binary per phase. Each deployed, used, deleted. No single binary for full kill chain. | High-OPSEC APT |
| 6 | Reflective loading | Modules loaded reflectively in memory. Never on disk. Memory forensics required. | CS Reflective DLL, BRc4 |
| 7 | Script-based stages | Initial script (PS, VBS, JS) downloads compiled binary. Script is disposable. | APT28, Lazarus |
| 8 | Shellcode-first | Position-independent shellcode, not PE. Via callbacks, APC, fiber. No PE headers. | CS beacon shellcode, Donut |
| 9 | Hybrid native+managed | Native C loader does evasion, then loads .NET for functionality. Splits evasion from capability. | Common red team pattern |

---

## 8. Process Identity

What the implant looks like to the OS and EDR.

| # | Option | Behavioral Profile Change | Real-World Example |
|---|--------|--------------------------|-------------------|
| 1 | Standalone new process | Unknown exe, no reputation, no signature. Most visible. | Basic malware |
| 2 | Renamed legitimate binary | Looks normal but wrong path. Some EDR checks path+name. | Common APT technique |
| 3 | DLL sideloading signed exe | Running process IS the legitimate signed binary. EDR trusts it. | APT41, hundreds of known signable EXEs |
| 4 | Service DLL (svchost) | Inside svchost with service SID. Blends with dozens of instances. | Turla, APT28, Stuxnet |
| 5 | Shell extension (explorer) | Context menu/icon handler in explorer.exe. Trusted process. | DarkHotel |
| 6 | Browser extension | Runs in browser sandbox. Network is from browser — normal. | APT browser credential theft |
| 7 | Print monitor (spoolsv) | Loaded by spoolsv.exe at boot. SYSTEM. Unusual, less monitored. | DePriMon |
| 8 | Network provider DLL | Loaded at logon by mpnotify.exe. Can intercept credentials. | Custom APT tools |
| 9 | LSA plugin (lsass) | SSP/auth package in lsass.exe. Highest privileges. Heavily monitored. | Mimikatz mimilib |
| 10 | WMI provider | WMI provider DLL in wmiprvse.exe. Looks like management instrumentation. | Some APT tools |
| 11 | Phantom DLL | DLL in path legitimate process searches but doesn't find. Fill the gap. No registry mod needed. | Many MS binaries have phantom loads |
| 12 | PPID spoofing | Spoofed parent PID via NtCreateProcess. Trusted parent chain that doesn't exist. | CS PPID spoofing |
| 13 | Process ghosting | Create file, write, delete, map section, create process. Runs from deleted file. Defeats file-scan. | 2021 Gabriel Landau technique |
| 14 | Process herpaderping | Write payload, map section, modify file to look benign. File on disk looks clean. | 2020 Johnny Shaw technique |
| 15 | Process doppelganging | NTFS transaction write, create section, rollback. File never exists on disk. | 2017 enSilo technique |
| 16 | AppInit_DLLs | Loaded into every GUI process. Very broad presence. | Some commodity malware |
| 17 | IFEO debugger | Set as debugger for common binary. Your code runs first. | APT3, accessibility backdoors |

---

## Cross-Dimensional Composition Examples

1. **Minimal footprint**: DLL sideload identity + triggered C2 (file drop) + in-process API execution + no persistence + time-limited = nearly zero behavioral signal.

2. **Maximum resilience**: Service DLL identity + dead-drop C2 (cloud storage) + .NET CLR execution + COM hijack persistence + modular architecture = hard to detect and hard to remove.

3. **Forensic nightmare**: Process ghosting identity + DNS-only C2 + direct syscalls + no persistence + disposable multi-stage + self-destruct timer = minimal forensic artifacts.
