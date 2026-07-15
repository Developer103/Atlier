# Infostealer Architectural Layers — Deep Research

These are BEHAVIORAL-ARCHITECTURE layers, not implementation details. Each option changes what the EDR's behavioral engine observes at the kernel/driver level.

---

## 1. Execution Model (what the OS sees running)

| Option | Behavioral Profile | Why It Changes Detection |
|---|---|---|
| **standalone_exe** | New unknown process appears, runs, exits | Baseline — EDR sees full process lifecycle of unknown binary |
| **dll_sideload** | Legitimate signed process loads a DLL from its directory | EDR sees a trusted process (e.g., OneDrive.exe, Teams.exe) doing all the work. No new process. Process tree looks clean. |
| **dll_proxying** | Legitimate app loads attacker DLL thinking it's a system DLL (e.g., version.dll, dbghelp.dll) | Same as sideload but abuses DLL search order. The "process" doing collection is the legitimate app. |
| **com_object** | Registered as COM server, instantiated by legitimate process via CoCreateInstance | EDR sees COM activation — extremely common, hard to distinguish malicious from legitimate |
| **shellcode_in_memory** | No file on disk. Code injected into existing process via APC, thread hijack, etc. | No new process creation event. No file I/O for the payload. EDR only sees the host process's behavior change. |
| **script_host** | Runs as JScript/VBScript via wscript.exe or cscript.exe | EDR sees script interpreter — well-monitored but lots of legitimate use. Can blend in enterprise environments. |
| **dotnet_assembly_load** | Loaded via Assembly.Load into existing .NET process (e.g., PowerShell, MSBuild) | EDR sees a trusted .NET host executing. No new PE on disk. |
| **wmi_consumer** | Registered as WMI event consumer — WMI service executes the code | EDR sees wmiprvse.exe doing the collection. WMI is a legitimate management framework. |
| **scheduled_task_action** | Code runs inside svchost.exe task scheduler context | Process tree shows svchost.exe as parent — same as hundreds of legitimate tasks |
| **service_dll** | Registered as a service DLL loaded by svchost.exe | EDR sees svchost.exe (trusted system process) doing collection. Extremely hard to distinguish. |
| **browser_extension** | Runs inside browser process (chrome.exe/msedge.exe) | All network activity comes from the browser — indistinguishable from browsing. File access is browser accessing its own data stores. |
| **lsa_plugin** | Loaded by lsass.exe as a security package (SSP) | EDR sees lsass.exe accessing credentials — that's what lsass does normally. The malicious access blends with legitimate. |
| **print_processor** | Loaded by spoolsv.exe as a print processor | Obscure, rarely monitored execution context |
| **minifilter_callback** | Kernel minifilter driver — runs in kernel space | Below EDR's usermode visibility. But requires driver signing or exploit. |

**Why this layer matters**: Falcon's IOA engine starts with "which process is doing this?" If the process is OneDrive.exe (trusted, signed, Microsoft), the same API calls that would trigger on an unknown.exe get a pass. Process identity is the first gate in behavioral analysis.

---

## 2. Collection Strategy (when and how data is gathered)

| Option | Behavioral Profile | Why It Changes Detection |
|---|---|---|
| **bulk_immediate** | Process opens 15 data sources in 5 seconds | Rapid sequential access to credentials, browser DBs, crypto wallets — recognizable burst pattern |
| **incremental_slow** | Collects one data source per hour/day over weeks | No burst. Each individual access looks like a normal file read. Time-spread defeats temporal correlation. |
| **piggyback_legitimate** | Hooks into legitimate backup/sync operations, copies data when the legitimate tool accesses it | EDR sees the legitimate tool accessing its own data. The stealer just reads the data the tool already surfaced. |
| **on_demand** | Collects nothing until operator sends command. Then collects one specific thing. | No automated collection pattern. Looks like a user action. |
| **event_triggered** | Monitors for specific events (user logs into banking site, opens password manager) then captures only that | Minimal footprint. Only activates when high-value data appears. Looks like application-specific behavior. |
| **opportunistic** | Monitors filesystem events — when a user opens a file containing credentials, copies it | Passive monitoring + targeted read. Looks like a file indexer or backup agent. |
| **memory_scraping** | Reads other processes' memory for credentials/tokens in transit | Never touches credential files on disk. Targets decrypted data in memory. Different detection surface. |
| **clipboard_watch** | Monitors clipboard for passwords/crypto addresses | Single API monitoring point. Extremely lightweight. Many legitimate apps do this. |
| **api_hooking** | Hooks browser/app APIs to intercept credentials at point of use | Captures plaintext passwords as user types them. Never touches encrypted stores. |
| **etw_consumer** | Subscribes to ETW providers that emit credential/authentication events | Reads legitimate Windows telemetry. Looks like a monitoring tool. |

**Why this layer matters**: Falcon looks for "credential access" behavioral patterns — rapid access to DPAPI, browser SQLite DBs, SAM hive, etc. An incremental collector that reads one Chrome cookie DB per day doesn't trigger the same IOA as one that hits all credential stores in 5 seconds.

---

## 3. Data Staging (where collected data lives before exfil)

| Option | Behavioral Profile | Why It Changes Detection |
|---|---|---|
| **memory_only** | All data stays in process heap. Never written to disk. | No suspicious file creation. No filesystem events. Memory-only is invisible to file-based scanning. |
| **temp_file** | Writes to %TEMP%\randomname.tmp | Filesystem activity visible. But %TEMP% writes are extremely common. |
| **registry_values** | Stores data in registry under legitimate-looking keys | Registry writes visible to Sysmon. But no file creation. Data survives process restart. |
| **alternate_data_streams** | Writes to NTFS ADS (file.txt:hidden) | Data exists on disk but invisible to dir/Explorer. Many EDRs don't monitor ADS writes. |
| **wmi_repository** | Stores data in WMI classes/instances | Persists in WMI database. Obscure. Survives most cleanup. |
| **event_log_entries** | Writes data as custom event log entries | Data stored in legitimate Windows event log infrastructure. Looks like application logging. |
| **cert_store** | Stores data as certificate blobs in Windows certificate store | Extremely unusual staging location. Rarely monitored. |
| **shared_memory** | Uses named sections/memory-mapped files for cross-process staging | No disk I/O. Data exists only in pageable memory. Disappears on reboot. |
| **steganography_file** | Embeds data in existing image/document files on disk | No new files created. Modified files look normal. Requires knowledge of file format. |
| **browser_storage** | Writes to browser localStorage/IndexedDB via browser process | Looks like normal browser data. Stored in browser's own data files. |
| **cloud_note** | Saves data to OneNote/Notion/Google Keep via legitimate app's sync | Data leaves via the note-taking app's own encrypted sync channel. |

**Why this layer matters**: EDR file monitoring watches for new suspicious files (credential dumps, data archives). Staging in memory or in legitimate data stores avoids triggering file-creation alerts.

---

## 4. Exfiltration Paradigm (how data fundamentally leaves the system)

| Option | Behavioral Profile | Why It Changes Detection |
|---|---|---|
| **direct_socket** | Process opens outbound TCP/UDP connection to attacker IP | EDR sees unknown process making external connection. Network IOA. |
| **http_to_attacker** | HTTP/HTTPS POST to attacker-controlled server | Looks like web traffic. But destination is unknown/new domain. |
| **legitimate_cloud_api** | Uses OneDrive/Google Drive/Dropbox/S3 API to upload | Traffic goes to Microsoft/Google/Amazon servers. Encrypted. Indistinguishable from legitimate cloud sync. |
| **legitimate_app_sync** | Drops data into OneDrive/Dropbox sync folder — the app syncs it | Process writes a local file. The legitimate sync client (which is trusted) handles all network activity. Zero suspicious network connections from the stealer process. |
| **dns_exfil** | Encodes data in DNS queries (A/TXT/CNAME) | Uses port 53. Looks like DNS resolution. Each query carries small payload. Very slow but hard to detect without DNS inspection. |
| **icmp_tunnel** | Embeds data in ICMP echo payloads | Looks like ping traffic. Many networks allow ICMP. But unusual volume would stand out. |
| **email_via_com** | Uses Outlook COM object (MAPI) to send email with data | Traffic is Outlook sending email — completely legitimate network pattern. Data goes through Exchange/M365. |
| **smb_share** | Writes to attacker SMB share on local network or VPN | Looks like normal file share access. Common in enterprise environments. |
| **webdav** | Uploads via WebDAV to attacker-controlled server | Uses HTTP but through Windows WebClient service. Looks like mapped network drive access. |
| **paste_site** | Posts to Pastebin/GitHub Gist/privatebin via HTTPS | Traffic to legitimate developer services. HTTPS encrypted. Common in enterprise. |
| **dead_drop** | Writes to shared location (public cloud storage, steganographic image on image hosting). Attacker retrieves separately. | Zero direct connection between stealer and attacker. Decoupled. Attribution-resistant. |
| **bluetooth** | Transfers via Bluetooth to nearby attacker device | No network traffic at all. Invisible to network monitoring. Requires physical proximity. |
| **usb_hid** | Writes to USB device when plugged in | No network traffic. Data leaves via physical media. Requires physical access. |
| **print_spool** | Embeds data in print jobs to network printer (attacker-controlled or intercepted) | Looks like printing. Uses SMB/IPP. Unusual but rarely monitored. |
| **browser_post** | Injects JavaScript into browser to POST data via the browser's own connection | Network activity comes from browser process to a website. Completely normal browsing pattern. |
| **cert_transparency** | Embeds data in certificate transparency logs via specially crafted cert requests | Extremely covert. Data is publicly logged but hidden in plain sight. Very low bandwidth. |

**Why this layer matters**: Falcon's network IOA watches for "unknown process connects to external IP." If exfil goes through OneDrive's sync client, Falcon sees OneDrive.exe (trusted, signed) connecting to onedrive.live.com (trusted destination). Zero alerts.

---

## 5. Process Lifetime (how long the stealer process exists)

| Option | Behavioral Profile | Why It Changes Detection |
|---|---|---|
| **ephemeral_seconds** | Run for 3-10 seconds, collect, send, exit | Short window for behavioral analysis. But rapid activity burst. |
| **ephemeral_staged** | Multiple short-lived instances, each collecting one thing | Many brief processes. Each one looks innocuous alone. Temporal gap defeats correlation. |
| **medium_minutes** | Run for 2-15 minutes with pacing | Enough time for behavioral engine to observe but with delays that look like user interaction. |
| **long_persistent** | Run for hours/days as a persistent service | Longest observation window. But if doing nothing most of the time, looks like a background service. |
| **burst_and_die** | Collect everything as fast as possible in <2 seconds, send, exit, self-delete | Faster than behavioral engine's analysis window. Binary gone before cloud analysis returns. |
| **process_chain** | Each stage is a different short-lived process (collector → stager → exfiltrator) | No single process shows the full behavioral chain. Falcon must correlate across process boundaries. |

**Why this layer matters**: Falcon's behavioral engine builds confidence over time. A process that exists for 1 second gives the IOA engine almost nothing to work with. But rapid API access in that second might still trigger. The sweet spot varies by what the stealer needs to access.

---

## 6. Process Ancestry (how the process tree looks)

| Option | Behavioral Profile | Why It Changes Detection |
|---|---|---|
| **user_double_click** | explorer.exe → stealer.exe | Normal user-launched process. Clean parent. |
| **schtasks_launch** | svchost.exe → stealer.exe | Task scheduler parent. Legitimate but sometimes suspicious for unknown binaries. |
| **com_activation** | svchost.exe (COM) → process | COM surrogate launch. Very common in Windows. |
| **wmi_spawn** | wmiprvse.exe → process | WMI-spawned. Common for management tools. Monitored but not blocked. |
| **ppid_spoofed** | Any chosen parent (explorer, svchost, services) | Faked parent process. Falcon detects some spoofing methods. |
| **no_parent** (orphaned) | Parent exits before child — shows as orphaned in process tree | Breaks process tree analysis. Some EDRs flag orphans. |
| **service_start** | services.exe → svchost.exe → stealer (as service DLL) | Legitimate service startup chain. Highest trust. |
| **logon_trigger** | userinit.exe → stealer | Runs at logon. Same tree as many legitimate startup programs. |

**Why this layer matters**: Falcon IOAs heavily weight process ancestry. `svchost.exe → unknown.exe → net.exe` triggers differently than `explorer.exe → totalcmd.exe → unknown.exe`. The parent determines the initial trust score.

---

## 7. Target Selectivity (what data is collected)

| Option | Behavioral Profile | Why It Changes Detection |
|---|---|---|
| **comprehensive_full** | Access browser DBs + DPAPI + crypto wallets + email + files + screenshots + clipboard | Touches every credential store. Maximum signal. Classic infostealer pattern. |
| **browser_only** | Only browser cookies/passwords/history | Limited scope. Accesses browser data files — could be a browser sync tool. |
| **credential_only** | Only passwords/tokens (DPAPI, SAM, credential manager) | Targets highest-value stores. Recognized credential access pattern. |
| **file_targeted** | Only specific files matching patterns (*.doc, *.pdf, *.xlsx in user dirs) | Looks like a backup or indexing tool. No credential store access. |
| **clipboard_only** | Only monitors clipboard for crypto addresses/passwords | Single API. Minimal footprint. Many legitimate clipboard managers. |
| **session_tokens** | Only steals active session cookies/tokens from memory | Memory reads only. Never touches encrypted credential stores. Targets transient data. |
| **network_creds** | Only captures credentials from network traffic (MITM, ETW network events) | No filesystem access for credentials. Operates on network layer. |
| **environment_recon** | Only system info, processes, network config — no credentials | Looks like a system inventory tool. Very low suspicion. Can be used for targeting. |

**Why this layer matters**: Falcon has specific IOAs for "credential access" — touching DPAPI master keys, reading browser SQLite DBs, accessing SAM hive. A stealer that only reads documents or monitors clipboard doesn't trigger credential-access IOAs at all.

---

## 8. Privilege Architecture (elevation strategy)

| Option | Behavioral Profile | Why It Changes Detection |
|---|---|---|
| **user_only** | Operates entirely as standard user. No elevation attempt. | Avoids UAC prompts. Limited to user-accessible data. No privilege escalation IOAs. |
| **token_impersonation** | Steal/duplicate tokens from higher-privilege processes | Uses SeImpersonatePrivilege. Specific detection surface. |
| **uac_bypass** | Exploits auto-elevate or bypass to get admin without prompt | Specific IOAs exist for known UAC bypasses (fodhelper, computerdefaults, etc.) |
| **exploit_elevation** | Uses kernel exploit or service exploit for SYSTEM | Very noisy. Exploitation events are heavily monitored. |
| **abuse_existing_priv** | Already running in elevated context (service, scheduled task with highest privileges) | No elevation event. Already has the needed access. |
| **split_privilege** | Low-priv collector sends data to high-priv exfiltrator (or vice versa) via IPC | Each process operates within its privilege. IPC bridges the gap. No single process needs both. |

**Why this layer matters**: Every privilege escalation method has its own IOA fingerprint. User-only operation avoids the entire category. But limits what can be stolen (no SAM, no other users' data, no DPAPI master keys for other users).

---

## 9. Anti-Forensics Architecture (structural, not technical)

| Option | Behavioral Profile | Why It Changes Detection |
|---|---|---|
| **no_cleanup** | Leave everything. Binary stays on disk. | Simplest. Full forensic trail. |
| **self_delete** | Binary deletes itself after execution | Process ghosting or delayed self-delete. Reduces evidence. |
| **timestomp** | Modify file timestamps to blend in | Avoids "new file" detection based on creation time. |
| **log_clearing** | Clear relevant event logs | Very suspicious behavior. Detected by most EDRs. |
| **memory_only_entire** | Never touch disk. Fileless from start to finish. | Zero disk artifacts. Memory forensics required. Much harder to investigate. |
| **legitimate_tool_chain** | Only use LOLBins (certutil, bitsadmin, powershell) | Every action is done by a signed Microsoft binary. Forensics sees legitimate tools used in sequence. |
| **blend_with_noise** | Generate legitimate-looking activity to hide malicious actions | Noise dilutes signal. Analyst has to find the needle in a haystack. |

---

## 10. Interaction with Security Products

| Option | Behavioral Profile | Why It Changes Detection |
|---|---|---|
| **ignore** | Don't interact with security products at all | Simplest. If APIs aren't monitored, no detection. |
| **blind_etw** | Patch ETW to stop telemetry generation | Specific IOAs exist for ETW tampering. But if successful, reduces behavioral data. |
| **unhook_usermode** | Remap ntdll to remove EDR hooks | Works against usermode EDR. Detected by kernel-level EDR (Falcon). |
| **timestop** | Modify KUSER_SHARED_DATA to break timing-based analysis | Kernel-level technique. Defeats sandbox time acceleration. |
| **detect_and_adapt** | Check which EDR is running, change behavior accordingly | Increases complexity. But can avoid specific IOAs known for each EDR. |
| **coexist** | Operate below detection thresholds — never trigger any single rule | The "normal software" approach. Most subtle. Requires understanding every detection threshold. |
| **abuse_exclusions** | Find and exploit EDR exclusion paths (some AV excludes certain paths/processes) | Zero detection if inside an excluded path. Common in enterprise (AV exclusions for backup agents, databases). |

---

## Cross-Reference: APT vs Commodity

| Dimension | Commodity (RedLine/Raccoon/Vidar) | APT (APT29/Turla/Lazarus) |
|---|---|---|
| Execution model | Standalone EXE | DLL sideload, service DLL, COM |
| Collection | Bulk immediate | Incremental, on-demand, targeted |
| Staging | Temp files | Memory only, registry, WMI |
| Exfil | Direct HTTP POST | Legitimate cloud, dead drop, steganography |
| Lifetime | Ephemeral (seconds) | Long-lived persistent |
| Process identity | Unknown EXE | Inside trusted process |
| Selectivity | Everything | Targeted based on recon |
| Cleanup | Minimal | Full anti-forensics |

The gap between commodity and APT is exactly the architectural layer variation described above. Commodity stealers use the simplest architecture (standalone exe, bulk collect, direct exfil). APTs use sophisticated architectures that blend with legitimate behavior. Our framework currently operates at the commodity level — adding these layers moves it toward APT-grade architecture.
