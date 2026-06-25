"""
Web portal for the Malware Gen Framework.

Launched via:  python -m malware_gen_framework portal [--port 7070]
"""
import asyncio
import json
import sys
import uuid
from pathlib import Path

import asyncssh
from aiohttp import web, WSMsgType

FRAMEWORK_ROOT = Path(__file__).parent.parent
RESULTS_DIR = FRAMEWORK_ROOT / "results"


# ---------------------------------------------------------------------------
# Command builder
# ---------------------------------------------------------------------------

def build_command(data: dict) -> list[str]:
    cmd = [sys.executable, "-m", "malware_gen_framework"]
    command = data.get("command", "run")
    cmd.append(command)

    if data.get("verbose"):
        cmd.append("-v")
    if data.get("debug"):
        cmd.append("--debug")

    # Shared flags
    if data.get("spec"):
        cmd += ["--spec", data["spec"]]
    if data.get("malware_type"):
        cmd += ["--malware-type", data["malware_type"]]
    if data.get("behavior"):
        cmd += ["--behavior", data["behavior"]]
    if data.get("output"):
        cmd += ["--output", data["output"]]

    mode = data.get("mode", "local-run")
    if command in ("run", "generate", "verify", "analyze"):
        cmd += ["--mode", mode]
    if mode == "cloud-run" and command in ("run", "generate", "verify"):
        provider = data.get("cloud_provider", "fugu")
        if provider and provider != "fugu":
            cmd += ["--cloud-provider", provider]
        cloud_model = data.get("cloud_model", "").strip()
        if cloud_model:
            cmd += ["--cloud-model", cloud_model]

    if command in ("run", "generate", "verify"):
        llm_url = data.get("llm_url", "").strip()
        if llm_url and llm_url != "http://localhost:1234":
            cmd += ["--llm-url", llm_url]
        llm_model = data.get("llm_model", "").strip()
        if llm_model:
            cmd += ["--llm-model", llm_model]
        if data.get("plan_review_infinite"):
            cmd += ["--plan-review-cycles", "0"]
        else:
            try:
                prc = int(data.get("plan_review_cycles", 10))
                if prc != 10:
                    cmd += ["--plan-review-cycles", str(prc)]
            except (ValueError, TypeError):
                pass

    if command == "run":
        if data.get("loop"):
            cmd.append("--loop")
        if data.get("exhaustive"):
            cmd.append("--exhaustive")
        try:
            mi = int(data.get("max_iters") or 5)
            if mi != 5:
                cmd += ["--max-iters", str(mi)]
        except (ValueError, TypeError):
            pass
        try:
            mi = int(data.get("min_iters") or 1)
            if mi != 1:
                cmd += ["--min-iters", str(mi)]
        except (ValueError, TypeError):
            pass
        if data.get("boot_existing"):
            cmd.append("--boot-existing")
            cmd += ["--os", data.get("os") or "windows-11"]
        elif data.get("use_existing_vm"):
            cmd.append("--use-existing-vm")
        try:
            port = int(data.get("vm_port") or 10022)
            if port != 10022:
                cmd += ["--vm-port", str(port)]
        except (ValueError, TypeError):
            pass
        vm_user = data.get("vm_user", "").strip()
        vm_pass = data.get("vm_pass", "").strip()
        if vm_user and vm_user != "vmuser":
            cmd += ["--vm-user", vm_user]
        if vm_pass and vm_pass != "vmuser123":
            cmd += ["--vm-pass", vm_pass]

    elif command == "provision":
        cmd += ["--os", data.get("os") or "windows-11"]
        if data.get("boot_existing"):
            cmd.append("--boot-existing")

    elif command == "verify":
        if data.get("source"):
            cmd += ["--source", data["source"]]
        if data.get("loop"):
            cmd.append("--loop")
        try:
            mi = int(data.get("max_iters") or 5)
            if mi != 5:
                cmd += ["--max-iters", str(mi)]
        except (ValueError, TypeError):
            pass
        if data.get("boot_existing"):
            cmd.append("--boot-existing")
            cmd += ["--os", data.get("os") or "windows-11"]
        elif data.get("use_existing_vm"):
            cmd.append("--use-existing-vm")
        try:
            port = int(data.get("vm_port") or 10022)
            if port != 10022:
                cmd += ["--vm-port", str(port)]
        except (ValueError, TypeError):
            pass
        vm_user = data.get("vm_user", "").strip()
        vm_pass = data.get("vm_pass", "").strip()
        if vm_user and vm_user != "vmuser":
            cmd += ["--vm-user", vm_user]
        if vm_pass and vm_pass != "vmuser123":
            cmd += ["--vm-pass", vm_pass]

    elif command == "analyze":
        try:
            n = int(data.get("db_n") or 10)
            if n != 10:
                cmd += ["--db-n", str(n)]
        except (ValueError, TypeError):
            pass

    elif command == "clean":
        if data.get("clean_all"):
            cmd.append("--all")

    return cmd


# ---------------------------------------------------------------------------
# In-memory job store
# ---------------------------------------------------------------------------

jobs: dict[str, dict] = {}


async def _run_subprocess(job_id: str, cmd: list[str]) -> None:
    job = jobs[job_id]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(FRAMEWORK_ROOT),
        )
        job["proc"] = proc

        async for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace").rstrip()
            job["output"].append(line)
            for q in list(job["listeners"]):
                await q.put(("log", line))

        await proc.wait()
        job["exit_code"] = proc.returncode
        job["status"] = "success" if proc.returncode == 0 else "failed"

    except Exception as exc:
        job["status"] = "error"
        err = f"[PORTAL] error starting subprocess: {exc}"
        job["output"].append(err)

    for q in list(job["listeners"]):
        await q.put(("done", job["status"]))


# ---------------------------------------------------------------------------
# HTTP handlers
# ---------------------------------------------------------------------------

async def handle_index(request: web.Request) -> web.Response:
    return web.FileResponse(Path(__file__).parent / "static" / "index.html")


async def handle_post_jobs(request: web.Request) -> web.Response:
    data = await request.json()
    job_id = uuid.uuid4().hex[:8]
    cmd = build_command(data)
    jobs[job_id] = {
        "id": job_id,
        "status": "running",
        "cmd": cmd,
        "cmd_str": " ".join(cmd),
        "output": [],
        "listeners": [],
        "proc": None,
        "exit_code": None,
    }
    asyncio.create_task(_run_subprocess(job_id, cmd))
    return web.json_response({"job_id": job_id, "cmd_str": " ".join(cmd)})


async def handle_get_jobs(request: web.Request) -> web.Response:
    return web.json_response([
        {"id": j["id"], "status": j["status"], "cmd_str": j["cmd_str"]}
        for j in reversed(list(jobs.values()))
    ])


async def handle_get_job(request: web.Request) -> web.Response:
    job_id = request.match_info["job_id"]
    job = jobs.get(job_id)
    if not job:
        raise web.HTTPNotFound()
    return web.json_response({
        "id": job["id"],
        "status": job["status"],
        "cmd_str": job["cmd_str"],
        "output": job["output"],
        "exit_code": job["exit_code"],
    })


async def handle_kill_job(request: web.Request) -> web.Response:
    job_id = request.match_info["job_id"]
    job = jobs.get(job_id)
    if not job:
        raise web.HTTPNotFound()
    if job.get("proc") and job["status"] == "running":
        try:
            job["proc"].terminate()
        except ProcessLookupError:
            pass
    return web.json_response({"ok": True})


async def handle_get_results(request: web.Request) -> web.Response:
    if not RESULTS_DIR.exists():
        return web.json_response([])
    files = sorted(
        [f.name for f in RESULTS_DIR.iterdir() if f.is_file()],
        key=lambda n: RESULTS_DIR.joinpath(n).stat().st_mtime,
        reverse=True,
    )
    return web.json_response(files)


async def handle_get_result_file(request: web.Request) -> web.Response:
    filename = request.match_info["filename"]
    if "/" in filename or ".." in filename:
        raise web.HTTPBadRequest()
    filepath = RESULTS_DIR / filename
    if not filepath.exists():
        raise web.HTTPNotFound()
    return web.Response(
        text=filepath.read_text(errors="replace"),
        content_type="text/plain",
    )


# ---------------------------------------------------------------------------
# WebSocket handler — live log streaming
# ---------------------------------------------------------------------------

async def handle_ws(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(heartbeat=25)
    await ws.prepare(request)

    job_id = request.match_info["job_id"]
    job = jobs.get(job_id)
    if not job:
        await ws.send_str(json.dumps({"type": "error", "msg": "job not found"}))
        await ws.close()
        return ws

    # Send already-buffered output to late-joining clients
    for line in list(job["output"]):
        await ws.send_str(json.dumps({"type": "log", "msg": line}))

    if job["status"] != "running":
        await ws.send_str(json.dumps({"type": "done", "status": job["status"]}))
        return ws

    # Fan-out live output via per-client queue
    q: asyncio.Queue = asyncio.Queue()
    job["listeners"].append(q)

    async def _drain() -> None:
        while True:
            try:
                event_type, payload = await q.get()
                if ws.closed:
                    break
                await ws.send_str(json.dumps({"type": event_type, "msg": payload}))
                if event_type == "done":
                    break
            except Exception:
                break

    drain_task = asyncio.create_task(_drain())
    try:
        async for msg in ws:
            if msg.type in (WSMsgType.ERROR, WSMsgType.CLOSE):
                break
    finally:
        drain_task.cancel()
        try:
            job["listeners"].remove(q)
        except ValueError:
            pass

    return ws


# ---------------------------------------------------------------------------
# WebSocket handler — SSH terminal proxy
# ---------------------------------------------------------------------------

async def handle_ssh_ws(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(heartbeat=25)
    await ws.prepare(request)

    # First message must be a JSON config blob
    msg = await ws.receive()
    if msg.type != WSMsgType.TEXT:
        await ws.close()
        return ws

    try:
        cfg = json.loads(msg.data)
    except (ValueError, TypeError):
        await ws.send_str(json.dumps({"type": "error", "msg": "bad config"}))
        await ws.close()
        return ws

    host = cfg.get("host", "localhost")
    port = int(cfg.get("port", 10022))
    username = cfg.get("username", "vmuser")
    password = cfg.get("password", "vmuser123")
    cols = int(cfg.get("cols", 200))
    rows = int(cfg.get("rows", 50))

    try:
        ssh_conn = await asyncssh.connect(
            host, port=port,
            username=username, password=password,
            known_hosts=None,
        )
    except Exception as exc:
        await ws.send_str(json.dumps({"type": "error", "msg": str(exc)}))
        await ws.close()
        return ws

    proc = await ssh_conn.create_process(
        term_type="xterm-256color",
        term_size=(cols, rows),
        encoding=None,
    )
    await ws.send_str(json.dumps({"type": "connected"}))

    async def _ssh_to_ws() -> None:
        try:
            while True:
                data = await proc.stdout.read(4096)
                if not data:
                    break
                await ws.send_bytes(data)
        except Exception:
            pass
        if not ws.closed:
            await ws.send_str(json.dumps({"type": "disconnected"}))

    fwd = asyncio.create_task(_ssh_to_ws())
    try:
        async for msg in ws:
            if msg.type == WSMsgType.BINARY:
                proc.stdin.write(msg.data)
            elif msg.type == WSMsgType.TEXT:
                try:
                    ctrl = json.loads(msg.data)
                    if ctrl.get("type") == "resize":
                        proc.change_terminal_size(int(ctrl["cols"]), int(ctrl["rows"]))
                except (ValueError, TypeError):
                    proc.stdin.write(msg.data.encode())
            elif msg.type in (WSMsgType.CLOSE, WSMsgType.ERROR):
                break
    finally:
        fwd.cancel()
        proc.close()
        ssh_conn.close()

    return ws


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", handle_index)
    app.router.add_post("/api/jobs", handle_post_jobs)
    app.router.add_get("/api/jobs", handle_get_jobs)
    app.router.add_get("/api/jobs/{job_id}", handle_get_job)
    app.router.add_post("/api/jobs/{job_id}/kill", handle_kill_job)
    app.router.add_get("/api/results", handle_get_results)
    app.router.add_get("/api/results/{filename}", handle_get_result_file)
    app.router.add_get("/ws/ssh", handle_ssh_ws)
    app.router.add_get("/ws/{job_id}", handle_ws)
    return app
