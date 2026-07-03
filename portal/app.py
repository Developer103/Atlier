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
import yaml
from aiohttp import web, WSMsgType

FRAMEWORK_ROOT = Path(__file__).parent.parent
RESULTS_DIR = FRAMEWORK_ROOT / "results"
CHUNKS_DIR = FRAMEWORK_ROOT / "templates" / "chunks"
RECIPES_DIR = CHUNKS_DIR / "recipes"


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
    if data.get("malware_type") and command == "analyze":
        cmd += ["--malware-type", data["malware_type"]]
    if data.get("behavior") and command == "analyze":
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


_C2_MALWARE_KEYWORDS = ("keylog", "infostealer", "info steal", "info-steal", "rat", "backdoor", "spyware")


async def _run_subprocess(job_id: str, cmd: list[str], env_extra: dict = None) -> None:
    job = jobs[job_id]
    import os
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=str(FRAMEWORK_ROOT),
            env=env,
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

    # Auto-start C2 listener for connection-back malware on success
    if job["status"] == "success":
        cmd_str = job.get("cmd_str", "").lower()
        if any(kw in cmd_str for kw in _C2_MALWARE_KEYWORDS):
            from .c2_listener import listener as c2
            if not c2.running:
                ok = await c2.start(port=9001)
                if ok:
                    msg = "[PORTAL] C2 listener started on 0.0.0.0:9001 — waiting for callback"
                    job["output"].append(msg)
                    for q in list(job["listeners"]):
                        await q.put(("log", msg))

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
        "command": data.get("command", "run"),
        "output": [],
        "listeners": [],
        "proc": None,
        "exit_code": None,
        "paused": False,
    }
    asyncio.create_task(_run_subprocess(job_id, cmd))
    return web.json_response({"job_id": job_id, "cmd_str": " ".join(cmd)})


async def handle_get_jobs(request: web.Request) -> web.Response:
    return web.json_response([
        {"id": j["id"], "status": j["status"], "cmd_str": j["cmd_str"],
         "command": j.get("command", ""), "paused": j.get("paused", False)}
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
        "command": job.get("command", ""),
        "paused": job.get("paused", False),
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
        job["paused"] = False
    return web.json_response({"ok": True})


async def handle_pause_job(request: web.Request) -> web.Response:
    import signal
    job_id = request.match_info["job_id"]
    job = jobs.get(job_id)
    if not job:
        raise web.HTTPNotFound()
    if job.get("proc") and job["status"] == "running" and not job.get("paused"):
        try:
            job["proc"].send_signal(signal.SIGSTOP)
            job["paused"] = True
            msg = f"[PORTAL] Job {job_id} paused (checkpoint saved)"
            job["output"].append(msg)
            for q in list(job["listeners"]):
                await q.put(("log", msg))
        except (ProcessLookupError, OSError):
            pass
    return web.json_response({"ok": True, "paused": job.get("paused", False)})


async def handle_resume_job(request: web.Request) -> web.Response:
    import signal
    job_id = request.match_info["job_id"]
    job = jobs.get(job_id)
    if not job:
        raise web.HTTPNotFound()
    if job.get("proc") and job["status"] == "running" and job.get("paused"):
        try:
            job["proc"].send_signal(signal.SIGCONT)
            job["paused"] = False
            msg = f"[PORTAL] Job {job_id} resumed"
            job["output"].append(msg)
            for q in list(job["listeners"]):
                await q.put(("log", msg))
        except (ProcessLookupError, OSError):
            pass
    return web.json_response({"ok": True, "paused": job.get("paused", False)})


async def handle_get_spec(request: web.Request) -> web.Response:
    spec_path = FRAMEWORK_ROOT / "spec.yaml"
    if not spec_path.exists():
        raise web.HTTPNotFound(text=json.dumps({"error": "spec.yaml not found"}),
                               content_type="application/json")
    content = spec_path.read_text(errors="replace")
    return web.json_response({"content": content, "path": str(spec_path.resolve())})


async def handle_put_spec(request: web.Request) -> web.Response:
    data = await request.json()
    content = data.get("content", "")
    try:
        yaml.safe_load(content)
    except yaml.YAMLError as exc:
        return web.json_response({"error": f"Invalid YAML: {exc}"}, status=400)
    spec_path = FRAMEWORK_ROOT / "spec.yaml"
    spec_path.write_text(content)
    return web.json_response({"ok": True})


async def handle_merge_spec(request: web.Request) -> web.Response:
    """Merge form field values into spec.yaml before a run."""
    data = await request.json()
    spec_path = FRAMEWORK_ROOT / "spec.yaml"

    if spec_path.exists():
        existing = yaml.safe_load(spec_path.read_text()) or {}
    else:
        existing = {}

    behavior = (data.get("behavior") or "").strip()
    malware_type = (data.get("malware_type") or "").strip()
    if malware_type:
        existing["malware_type"] = malware_type
    if behavior:
        existing["behavior_spec"] = behavior

    os_val = (data.get("os") or "").strip()
    if os_val:
        existing["os_version"] = os_val
        if "windows" in os_val.lower():
            existing["os_platform"] = "windows"
        elif any(x in os_val.lower() for x in ("ubuntu", "debian", "linux")):
            existing["os_platform"] = "linux"

    lang = (data.get("source_language") or "").strip()
    if lang:
        existing["source_language"] = lang

    fmt = (data.get("output_format") or "").strip()
    if fmt:
        existing["output_format"] = fmt

    c2_addr = (data.get("c2_address") or "").strip()
    if c2_addr:
        existing["c2_address"] = c2_addr

    c2_port = data.get("c2_port")
    if c2_port:
        try:
            existing["c2_port"] = int(c2_port)
        except (ValueError, TypeError):
            pass

    spec_path.write_text(yaml.dump(existing, default_flow_style=False, allow_unicode=True, sort_keys=False))
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
# Chunk Builder API
# ---------------------------------------------------------------------------


def _load_evasion_selector():
    """Lazy-import evasion_selector from templates/chunks/."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "evasion_selector",
        str(CHUNKS_DIR / "evasion_selector.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


async def handle_chunk_recipes(request: web.Request) -> web.Response:
    """List available chunk recipes."""
    recipes = []
    if RECIPES_DIR.exists():
        for f in sorted(RECIPES_DIR.glob("*.yaml")):
            try:
                data = yaml.safe_load(f.read_text())
                recipes.append({
                    "name": f.stem,
                    "description": data.get("description", ""),
                })
            except Exception:
                recipes.append({"name": f.stem, "description": ""})
    return web.json_response(recipes)


async def handle_chunk_layers(request: web.Request) -> web.Response:
    """Return evasion layer definitions for the UI dropdowns."""
    es = _load_evasion_selector()
    layers = {}
    for name, info in es.LAYERS.items():
        layers[name] = {
            "description": info["description"],
            "default": info["default"],
            "options": {
                opt: {"risk": v["risk"], "desc": v["desc"]}
                for opt, v in info["options"].items()
            },
        }
    return web.json_response(layers)


async def handle_chunk_auto_select(request: web.Request) -> web.Response:
    """Auto-select evasion layers based on detection feedback text."""
    data = await request.json()
    detection = data.get("detection", "")
    es = _load_evasion_selector()
    config = es.select_layers(detection_text=detection)
    return web.json_response(config)


async def handle_chunk_build(request: web.Request) -> web.Response:
    """Start a chunk build job (recipe-based or custom layers)."""
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "invalid JSON body"}, status=400)
    mode = data.get("mode", "recipe")
    compile_flag = data.get("compile", True)
    job_id = uuid.uuid4().hex[:8]

    if mode == "custom":
        layers = data.get("layers", {})
        malware_type = data.get("malware_type", "infostealer")
        es = _load_evasion_selector()
        recipe_yaml = es.config_to_recipe(layers, malware_type=malware_type)
        custom_path = RESULTS_DIR / "custom_recipe.yaml"
        custom_path.parent.mkdir(parents=True, exist_ok=True)
        custom_path.write_text(recipe_yaml)
        cmd = [sys.executable, "-m", "malware_gen_framework", "chunk",
               "--recipe", str(custom_path)]
    else:
        recipe = data.get("recipe", "infostealer_full")
        cmd = [sys.executable, "-m", "malware_gen_framework", "chunk",
               "--recipe", recipe]

    if compile_flag:
        cmd.append("--compile")

    obf_level = data.get("obfuscation", "none")
    if obf_level and obf_level != "none":
        cmd.extend(["--obfuscate", obf_level])

    deploy = data.get("deploy", False)
    if deploy:
        cmd.append("--test")

    env_extra = {}
    llm_url = data.get("llm_url", "").strip()
    llm_model = data.get("llm_model", "").strip()
    if llm_url:
        env_extra["LLM_URL"] = llm_url
    if llm_model:
        env_extra["LLM_MODEL"] = llm_model
    vm_port = data.get("vm_port", "")
    vm_user = data.get("vm_user", "")
    vm_pass = data.get("vm_pass", "")
    c2_port = data.get("c2_port", "")
    if vm_port:
        env_extra["VM_PORT"] = str(vm_port)
    if vm_user:
        env_extra["VM_USER"] = vm_user
    if vm_pass:
        env_extra["VM_PASS"] = vm_pass
    if c2_port:
        env_extra["C2_PORT"] = str(c2_port)

    jobs[job_id] = {
        "id": job_id,
        "status": "running",
        "cmd": cmd,
        "cmd_str": " ".join(cmd),
        "command": "chunk",
        "output": [],
        "listeners": [],
        "proc": None,
        "exit_code": None,
        "paused": False,
    }
    asyncio.create_task(_run_subprocess(job_id, cmd, env_extra=env_extra or None))
    return web.json_response({"job_id": job_id, "cmd_str": " ".join(cmd)})


async def handle_chunk_hybrid(request: web.Request) -> web.Response:
    """Start the hybrid evasion loop as a background job."""
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "invalid JSON body"}, status=400)
    malware_type = data.get("malware_type", "infostealer")
    dry_run = data.get("dry_run", False)
    av_type = data.get("av_type", "defender")
    max_runs = data.get("max_runs", 10)
    custom_cmd = data.get("custom_cmd", "")
    job_id = uuid.uuid4().hex[:8]

    cmd = [
        sys.executable, str(CHUNKS_DIR / "evasion_selector.py"),
        "--run", malware_type,
    ]
    if dry_run:
        cmd.append("--dry-run")

    # Pass AV type and max runs via environment
    env_extra = {
        "MALGEN_AV_TYPE": av_type,
        "MALGEN_MAX_RUNS": str(max_runs),
    }
    if custom_cmd:
        env_extra["MALGEN_DETECTION_CMD"] = custom_cmd
    obf_level = data.get("obfuscation", "heavy")
    env_extra["MALGEN_OBFUSCATION"] = obf_level
    llm_url = data.get("llm_url", "").strip()
    llm_model = data.get("llm_model", "").strip()
    if llm_url:
        env_extra["LLM_URL"] = llm_url
    if llm_model:
        env_extra["LLM_MODEL"] = llm_model
    vm_port = data.get("vm_port", "")
    vm_user = data.get("vm_user", "")
    vm_pass = data.get("vm_pass", "")
    c2_port = data.get("c2_port", "")
    if vm_port:
        env_extra["VM_PORT"] = str(vm_port)
    if vm_user:
        env_extra["VM_USER"] = vm_user
    if vm_pass:
        env_extra["VM_PASS"] = vm_pass
    if c2_port:
        env_extra["C2_PORT"] = str(c2_port)

    jobs[job_id] = {
        "id": job_id,
        "status": "running",
        "cmd": cmd,
        "cmd_str": " ".join(cmd),
        "command": "chunk-hybrid",
        "output": [],
        "listeners": [],
        "proc": None,
        "exit_code": None,
        "paused": False,
        "env_extra": env_extra,
    }
    asyncio.create_task(_run_subprocess(job_id, cmd, env_extra=env_extra))
    return web.json_response({"job_id": job_id, "cmd_str": " ".join(cmd)})


async def handle_chunk_history(request: web.Request) -> web.Response:
    """Return evasion selector run history."""
    es = _load_evasion_selector()
    history = es.load_history()
    return web.json_response(history)


# ---------------------------------------------------------------------------
# C2 listener management
# ---------------------------------------------------------------------------

from .c2_listener import listener as c2_listener


async def handle_c2_status(request: web.Request) -> web.Response:
    return web.json_response(c2_listener.status())


async def handle_c2_start(request: web.Request) -> web.Response:
    data = await request.json() if request.content_length else {}
    port = int(data.get("port", 9001))
    host = data.get("host", "0.0.0.0")
    ok = await c2_listener.start(port=port, host=host)
    return web.json_response({"ok": ok, **c2_listener.status()})


async def handle_c2_stop(request: web.Request) -> web.Response:
    await c2_listener.stop()
    return web.json_response({"ok": True})


async def handle_c2_data(request: web.Request) -> web.Response:
    filename = request.match_info["filename"]
    if "/" in filename or ".." in filename:
        raise web.HTTPBadRequest()
    filepath = RESULTS_DIR / filename
    if not filepath.exists() or not filename.startswith("c2_received_"):
        raise web.HTTPNotFound()
    content = filepath.read_bytes()
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        text = content.hex()
    return web.Response(text=text, content_type="text/plain")


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
    app.router.add_post("/api/jobs/{job_id}/pause", handle_pause_job)
    app.router.add_post("/api/jobs/{job_id}/resume", handle_resume_job)
    app.router.add_get("/api/spec", handle_get_spec)
    app.router.add_put("/api/spec", handle_put_spec)
    app.router.add_post("/api/spec/merge", handle_merge_spec)
    app.router.add_get("/api/results", handle_get_results)
    app.router.add_get("/api/results/{filename}", handle_get_result_file)
    app.router.add_get("/api/c2", handle_c2_status)
    app.router.add_post("/api/c2/start", handle_c2_start)
    app.router.add_post("/api/c2/stop", handle_c2_stop)
    app.router.add_get("/api/c2/data/{filename}", handle_c2_data)
    app.router.add_get("/api/chunk/recipes", handle_chunk_recipes)
    app.router.add_get("/api/chunk/layers", handle_chunk_layers)
    app.router.add_post("/api/chunk/auto-select", handle_chunk_auto_select)
    app.router.add_post("/api/chunk/build", handle_chunk_build)
    app.router.add_post("/api/chunk/hybrid", handle_chunk_hybrid)
    app.router.add_get("/api/chunk/history", handle_chunk_history)
    app.router.add_get("/ws/ssh", handle_ssh_ws)
    app.router.add_get("/ws/{job_id}", handle_ws)
    return app
