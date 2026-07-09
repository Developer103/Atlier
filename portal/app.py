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
EDR_SCORES_DIR = RESULTS_DIR / "edr_scores"
SCRIPTS_DIR = FRAMEWORK_ROOT / "scripts"
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
        if llm_url:
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
            start_new_session=True,
        )
        job["proc"] = proc

        async for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace").rstrip()
            job["output"].append(line)
            for q in list(job["listeners"]):
                await q.put(("log", line))

        await proc.wait()
        if job["status"] == "killed":
            return
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
    import os, signal
    job_id = request.match_info["job_id"]
    job = jobs.get(job_id)
    if not job:
        raise web.HTTPNotFound()
    if job.get("proc") and job["status"] == "running":
        proc = job["proc"]
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, OSError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        job["paused"] = False
        job["status"] = "killed"
        job["exit_code"] = -15
        msg = f"[PORTAL] Job {job_id} killed by user"
        job["output"].append(msg)
        for q in list(job["listeners"]):
            await q.put(("log", msg))
            await q.put(("done", "killed"))
    return web.json_response({"ok": True, "status": "killed"})


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
    active_edrs = data.get("active_edrs", ["defender"])
    max_algorithmic = data.get("max_algorithmic", 5)
    max_llm = data.get("max_llm", 3)
    max_cloud = data.get("max_cloud", 2)
    job_id = uuid.uuid4().hex[:8]

    cmd = [
        sys.executable, str(CHUNKS_DIR / "evasion_selector.py"),
        "--run", malware_type,
    ]
    if dry_run:
        cmd.append("--dry-run")

    env_extra = {
        "MALGEN_ACTIVE_EDRS": ",".join(active_edrs) if isinstance(active_edrs, list) else str(active_edrs),
        "MALGEN_MAX_ALGORITHMIC": str(max_algorithmic),
        "MALGEN_MAX_LLM": str(max_llm),
        "MALGEN_MAX_CLOUD": str(max_cloud),
    }
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
# EDR Score endpoints
# ---------------------------------------------------------------------------

async def handle_edr_run(request: web.Request) -> web.Response:
    """Start an EDR score job: deploy payload to VM, capture Sysmon, score."""
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "invalid JSON body"}, status=400)
    payload_path = data.get("payload", "").strip()
    payload_type = data.get("type", "infostealer")
    if not payload_path:
        return web.json_response({"error": "payload path required"}, status=400)

    job_id = uuid.uuid4().hex[:8]
    script = str(SCRIPTS_DIR / "edr_score.sh")
    cmd = [script, payload_path, "--type", payload_type]

    jobs[job_id] = {
        "id": job_id,
        "status": "running",
        "cmd": cmd,
        "cmd_str": " ".join(cmd),
        "command": "edr-score",
        "output": [],
        "listeners": [],
        "proc": None,
        "exit_code": None,
        "paused": False,
    }
    asyncio.create_task(_run_subprocess(job_id, cmd))
    return web.json_response({"job_id": job_id, "cmd_str": " ".join(cmd)})


async def handle_edr_score_only(request: web.Request) -> web.Response:
    """Score an existing .evtx file without deploying."""
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"error": "invalid JSON body"}, status=400)
    evtx_path = data.get("evtx", "").strip()
    if not evtx_path:
        return web.json_response({"error": "evtx path required"}, status=400)

    job_id = uuid.uuid4().hex[:8]
    script = str(SCRIPTS_DIR / "edr_score.sh")
    cmd = [script, "--score-only", evtx_path]

    jobs[job_id] = {
        "id": job_id,
        "status": "running",
        "cmd": cmd,
        "cmd_str": " ".join(cmd),
        "command": "edr-score",
        "output": [],
        "listeners": [],
        "proc": None,
        "exit_code": None,
        "paused": False,
    }
    asyncio.create_task(_run_subprocess(job_id, cmd))
    return web.json_response({"job_id": job_id, "cmd_str": " ".join(cmd)})


async def handle_edr_scores(request: web.Request) -> web.Response:
    """List EDR score reports."""
    if not EDR_SCORES_DIR.exists():
        return web.json_response([])
    files = sorted(
        [f.name for f in EDR_SCORES_DIR.iterdir()
         if f.is_file() and (f.name.startswith("score_") or f.name.startswith("sysmon_"))],
        key=lambda n: EDR_SCORES_DIR.joinpath(n).stat().st_mtime,
        reverse=True,
    )
    return web.json_response(files)


async def handle_edr_score_file(request: web.Request) -> web.Response:
    """View a specific EDR score report."""
    filename = request.match_info["filename"]
    if "/" in filename or ".." in filename:
        raise web.HTTPBadRequest()
    filepath = EDR_SCORES_DIR / filename
    if not filepath.exists():
        raise web.HTTPNotFound()
    return web.Response(
        text=filepath.read_text(errors="replace"),
        content_type="text/plain",
    )


# ---------------------------------------------------------------------------
# EDR management
# ---------------------------------------------------------------------------

async def _ssh_run(cmd: str, port: int = 10022, user: str = "vmuser",
                   pwd: str = "vmuser123", timeout: int = 15) -> str:
    async with asyncssh.connect(
        "localhost", port=port, username=user, password=pwd,
        known_hosts=None, connect_timeout=5,
    ) as conn:
        r = await conn.run(cmd, check=False, timeout=timeout)
        return (r.stdout or "").replace("\r", "").strip()


async def handle_edr_status(request: web.Request) -> web.Response:
    """Get status of all EDR components."""
    edrs = {}
    try:
        # Defender
        out = await _ssh_run(
            'powershell -Command "'
            'Get-MpPreference | Select-Object DisableRealtimeMonitoring | Format-List"'
        )
        rt_disabled = "True" in out
        edrs["defender"] = {
            "name": "Windows Defender",
            "enabled": not rt_disabled,
            "detail": "RealTimeProtection " + ("OFF" if rt_disabled else "ON"),
        }
    except Exception as e:
        edrs["defender"] = {"name": "Windows Defender", "enabled": None, "detail": str(e)}

    try:
        # Sysmon
        out = await _ssh_run('sc query Sysmon64')
        running = "RUNNING" in out
        edrs["sysmon"] = {
            "name": "Sysmon",
            "enabled": running,
            "detail": "RUNNING" if running else "STOPPED",
        }
    except Exception as e:
        edrs["sysmon"] = {"name": "Sysmon", "enabled": None, "detail": str(e)}

    try:
        # Wazuh agent
        out = await _ssh_run('sc query WazuhSvc')
        running = "RUNNING" in out
        edrs["wazuh"] = {
            "name": "Wazuh Agent",
            "enabled": running,
            "detail": "RUNNING" if running else "STOPPED",
        }
    except Exception as e:
        edrs["wazuh"] = {"name": "Wazuh Agent", "enabled": None, "detail": str(e)}

    # Wazuh manager (host-side)
    try:
        import urllib.request
        url = "http://localhost:9201/_cluster/health"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            health = json.loads(resp.read())
            edrs["wazuh_indexer"] = {
                "name": "Wazuh Indexer",
                "enabled": health.get("status") in ("green", "yellow"),
                "detail": health.get("status", "unknown"),
            }
    except Exception as e:
        edrs["wazuh_indexer"] = {"name": "Wazuh Indexer", "enabled": False, "detail": str(e)}

    return web.json_response(edrs)


async def handle_edr_toggle(request: web.Request) -> web.Response:
    """Toggle an EDR component on/off."""
    data = await request.json()
    component = data.get("component", "")
    enable = data.get("enable", True)

    cmds = {
        "defender": (
            'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"'
            if enable else
            'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"'
        ),
        "sysmon": (
            'net start Sysmon64' if enable else 'net stop Sysmon64'
        ),
        "wazuh": (
            'net start WazuhSvc' if enable else 'net stop WazuhSvc'
        ),
    }

    if component not in cmds:
        return web.json_response({"error": f"Unknown component: {component}"}, status=400)

    try:
        out = await _ssh_run(cmds[component], timeout=30)
        return web.json_response({"ok": True, "component": component, "enable": enable, "output": out})
    except Exception as e:
        return web.json_response({"error": str(e)}, status=500)


async def handle_edr_preset(request: web.Request) -> web.Response:
    """Apply an EDR preset (all-on, defender-only, none)."""
    data = await request.json()
    preset = data.get("preset", "all")

    presets = {
        "all":            {"defender": True,  "sysmon": True,  "wazuh": True},
        "defender-only":  {"defender": True,  "sysmon": False, "wazuh": False},
        "wazuh-only":     {"defender": False, "sysmon": True,  "wazuh": True},
        "none":           {"defender": False, "sysmon": False, "wazuh": False},
    }

    if preset not in presets:
        return web.json_response({"error": f"Unknown preset: {preset}"}, status=400)

    results = {}
    for component, enable in presets[preset].items():
        try:
            body = json.dumps({"component": component, "enable": enable}).encode()
            # Reuse the toggle logic directly
            cmds = {
                "defender": (
                    'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"'
                    if enable else
                    'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"'
                ),
                "sysmon": ('net start Sysmon64' if enable else 'net stop Sysmon64'),
                "wazuh": ('net start WazuhSvc' if enable else 'net stop WazuhSvc'),
            }
            out = await _ssh_run(cmds[component], timeout=30)
            results[component] = {"ok": True, "enabled": enable}
        except Exception as e:
            results[component] = {"ok": False, "error": str(e)}

    return web.json_response({"preset": preset, "results": results})


# ---------------------------------------------------------------------------
# VM management
# ---------------------------------------------------------------------------

_vm_qemu: "QEMUProcess | None" = None


def _vm_paths(os_name: str = "windows-11"):
    """Return (cow_img, qmp_socket, vm_name) for the given OS."""
    base_dir = Path("/tmp/vm_provision")
    cow = base_dir / f"base_{os_name}.cow.qcow2"
    qmp = base_dir / f"vm-{os_name}.qmp"
    name = f"vm-{os_name}"
    return cow, qmp, name


def _qemu_running(qmp: Path, vm_name: str) -> bool:
    """Check if a QEMU process for this VM is alive."""
    import subprocess as _sp
    for pattern in [str(qmp), f"-name {vm_name}"]:
        try:
            _sp.check_output(
                ["pgrep", "-f", f"qemu-system-x86_64.*{pattern}"],
                text=True, stderr=_sp.DEVNULL, timeout=5,
            )
            return True
        except (_sp.CalledProcessError, FileNotFoundError):
            pass
    return False


async def _ssh_reachable(port: int = 10022, user: str = "vmuser",
                         pwd: str = "vmuser123") -> bool:
    try:
        async with asyncssh.connect(
            "localhost", port=port, username=user, password=pwd,
            known_hosts=None, connect_timeout=5,
        ) as conn:
            r = await conn.run("echo ok", check=False, timeout=5)
            return r.exit_status == 0
    except Exception:
        return False


async def handle_vm_status(request: web.Request) -> web.Response:
    """Return VM status: qemu running, ssh reachable, disk exists."""
    data = dict(request.query)
    os_name = data.get("os", "windows-11")
    cow, qmp, vm_name = _vm_paths(os_name)
    qemu_up = await asyncio.to_thread(_qemu_running, qmp, vm_name)
    ssh_up = False
    if qemu_up:
        ssh_up = await _ssh_reachable()
    return web.json_response({
        "os": os_name,
        "disk_exists": cow.exists() or qemu_up,
        "qemu_running": qemu_up,
        "ssh_reachable": ssh_up,
    })


async def handle_vm_boot(request: web.Request) -> web.Response:
    """Boot an existing VM disk."""
    global _vm_qemu
    data = await request.json() if request.content_length else {}
    os_name = data.get("os", "windows-11")
    cow, qmp, vm_name = _vm_paths(os_name)

    if not cow.exists():
        return web.json_response(
            {"error": f"No disk at {cow}. Install the VM first."}, status=400)

    if _qemu_running(qmp, vm_name):
        return web.json_response(
            {"error": "VM is already running."}, status=409)

    from .provision_engine import QEMUProcess, ProvisionEngine

    qemu = QEMUProcess(
        vm_name=vm_name, qmp_socket=qmp, disk_img=cow,
        cpu_cores=4, ram_mb=8192, windows_boot_only=True,
    )
    try:
        await qemu.start()
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)

    _vm_qemu = qemu

    ssh_ok = await ProvisionEngine._wait_for_ssh(
        10022, timeout=180, username="vmuser", password="vmuser123")

    return web.json_response({
        "ok": True,
        "pid": qemu.process.pid if qemu.process else None,
        "ssh_ready": ssh_ok,
    })


async def handle_vm_shutdown(request: web.Request) -> web.Response:
    """Gracefully shut down the VM."""
    global _vm_qemu
    data = await request.json() if request.content_length else {}
    os_name = data.get("os", "windows-11")
    cow, qmp, vm_name = _vm_paths(os_name)

    if not _qemu_running(qmp, vm_name):
        return web.json_response({"error": "VM is not running."}, status=400)

    if _vm_qemu and _vm_qemu.process and _vm_qemu.process.poll() is None:
        await _vm_qemu.stop(wait=True)
        _vm_qemu = None
        return web.json_response({"ok": True})

    # Fallback: SSH shutdown then kill stale QEMU
    try:
        await _ssh_reachable()
        async with asyncssh.connect(
            "localhost", port=10022, username="vmuser", password="vmuser123",
            known_hosts=None, connect_timeout=5,
        ) as conn:
            await conn.run("shutdown /s /t 0", check=False, timeout=10)
    except Exception:
        pass

    # Wait up to 30s for QEMU to exit, then force kill
    import time
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if not _qemu_running(qmp, vm_name):
            _vm_qemu = None
            return web.json_response({"ok": True})
        await asyncio.sleep(1)

    # Force kill
    from .provision_engine import QEMUProcess
    await asyncio.to_thread(QEMUProcess._kill_stale_qemu, vm_name, qmp)
    _vm_qemu = None
    return web.json_response({"ok": True, "forced": True})


async def handle_vm_snapshot(request: web.Request) -> web.Response:
    """Run a VM snapshot save/restore."""
    data = await request.json() if request.content_length else {}
    action = data.get("action", "save")
    tag = data.get("tag", "portal_snapshot")
    if action not in ("save", "restore", "list"):
        return web.json_response({"error": "action must be save, restore, or list"}, status=400)
    script = str(SCRIPTS_DIR / "vm_snapshot.sh")
    job_id = uuid.uuid4().hex[:8]
    cmd = [script, action, tag]
    jobs[job_id] = {
        "id": job_id, "status": "running", "cmd": cmd,
        "cmd_str": " ".join(cmd), "command": "vm-snapshot",
        "output": [], "listeners": [], "proc": None,
        "exit_code": None, "paused": False,
    }
    asyncio.create_task(_run_subprocess(job_id, cmd))
    return web.json_response({"job_id": job_id, "cmd_str": " ".join(cmd)})


async def handle_vm_install(request: web.Request) -> web.Response:
    """Start a fresh VM installation (provision) as a background job."""
    data = await request.json() if request.content_length else {}
    os_name = data.get("os", "windows-11")
    job_id = uuid.uuid4().hex[:8]
    cmd = [sys.executable, "-m", "malware_gen_framework", "provision",
           "--os", os_name]
    jobs[job_id] = {
        "id": job_id, "status": "running", "cmd": cmd,
        "cmd_str": " ".join(cmd), "command": "provision",
        "output": [], "listeners": [], "proc": None,
        "exit_code": None, "paused": False,
    }
    asyncio.create_task(_run_subprocess(job_id, cmd))
    return web.json_response({"job_id": job_id, "cmd_str": " ".join(cmd)})


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
    is_test_run = bool(data.get("is_test_run", False))
    ok = await c2_listener.start(port=port, host=host, is_test_run=is_test_run)
    return web.json_response({"ok": ok, **c2_listener.status()})


async def handle_c2_stop(request: web.Request) -> web.Response:
    await c2_listener.stop()
    return web.json_response({"ok": True})


async def handle_c2_data(request: web.Request) -> web.Response:
    filename = request.match_info["filename"]
    if "/" in filename or ".." in filename:
        raise web.HTTPBadRequest()
    if not filename.startswith("c2_received_"):
        raise web.HTTPNotFound()
    c2_root = RESULTS_DIR / "c2_data"
    filepath = c2_root / filename
    if not filepath.exists():
        for session_dir in sorted(c2_root.iterdir(), reverse=True):
            if session_dir.is_dir():
                candidate = session_dir / filename
                if candidate.exists():
                    filepath = candidate
                    break
    if not filepath.exists():
        raise web.HTTPNotFound()
    content = filepath.read_bytes()
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        text = content.hex()
    return web.Response(text=text, content_type="text/plain")


# ---------------------------------------------------------------------------
# Detection engines: Wazuh + Elastic + Defender
# ---------------------------------------------------------------------------

WAZUH_API = "https://localhost:55000"
WAZUH_USER = "wazuh-wui"
WAZUH_PASS = "MyS3cr3tP4ssw0rd*"
ELASTIC_URL = "http://localhost:9201"


async def _wazuh_token() -> str | None:
    import aiohttp as _aio
    try:
        conn = _aio.TCPConnector(ssl=False)
        async with _aio.ClientSession(connector=conn) as s:
            async with s.post(
                f"{WAZUH_API}/security/user/authenticate",
                auth=_aio.BasicAuth(WAZUH_USER, WAZUH_PASS),
                timeout=_aio.ClientTimeout(total=5),
            ) as r:
                data = await r.json()
                return data.get("data", {}).get("token")
    except Exception:
        return None


async def _wazuh_request(path: str, params: dict = None) -> dict | None:
    import aiohttp as _aio
    token = await _wazuh_token()
    if not token:
        return None
    try:
        conn = _aio.TCPConnector(ssl=False)
        async with _aio.ClientSession(connector=conn) as s:
            async with s.get(
                f"{WAZUH_API}{path}",
                headers={"Authorization": f"Bearer {token}"},
                params=params or {},
                timeout=_aio.ClientTimeout(total=10),
            ) as r:
                return await r.json()
    except Exception:
        return None


async def handle_detection_status(request: web.Request) -> web.Response:
    """Combined status of all detection engines."""
    import aiohttp as _aio

    result = {
        "wazuh": {"online": False, "agent_id": None, "agent_status": None},
        "elastic": {"online": False, "alert_index_exists": False},
        "defender": {"online": False, "realtime": False},
    }

    # Wazuh
    agents = await _wazuh_request("/agents", {"pretty": "true", "status": "active"})
    if agents and "data" in agents:
        result["wazuh"]["online"] = True
        for a in agents["data"].get("affected_items", []):
            if a.get("id") != "000":
                result["wazuh"]["agent_id"] = a["id"]
                result["wazuh"]["agent_status"] = a.get("status", "unknown")
                result["wazuh"]["agent_name"] = a.get("name", "")
                result["wazuh"]["agent_os"] = a.get("os", {}).get("name", "")
                break

    # Elastic / Wazuh Indexer
    try:
        conn = _aio.TCPConnector(ssl=False)
        async with _aio.ClientSession(connector=conn) as s:
            async with s.get(
                f"{ELASTIC_URL}/_cluster/health",
                timeout=_aio.ClientTimeout(total=5),
            ) as r:
                health = await r.json()
                result["elastic"]["online"] = True
                result["elastic"]["cluster_status"] = health.get("status", "unknown")
            async with s.get(
                f"{ELASTIC_URL}/_cat/indices/wazuh-alerts-*?format=json",
                timeout=_aio.ClientTimeout(total=5),
            ) as r:
                indices = await r.json()
                if isinstance(indices, list) and indices:
                    result["elastic"]["alert_index_exists"] = True
                    total_docs = sum(int(i.get("docs.count", 0)) for i in indices)
                    result["elastic"]["total_alerts"] = total_docs
    except Exception:
        pass

    # Defender (via VM SSH)
    ssh_up = await _ssh_reachable()
    if ssh_up:
        try:
            async with asyncssh.connect(
                "localhost", port=10022, username="vmuser", password="vmuser123",
                known_hosts=None, connect_timeout=5,
            ) as conn:
                r = await conn.run(
                    'powershell -Command "Get-MpComputerStatus | Select-Object '
                    'AMServiceEnabled,RealTimeProtectionEnabled,AntivirusEnabled '
                    '| ConvertTo-Json"',
                    check=False, timeout=10,
                )
                if r.exit_status == 0:
                    import re
                    cleaned = re.sub(r'\r', '', r.stdout.strip())
                    dstatus = json.loads(cleaned)
                    result["defender"]["online"] = True
                    result["defender"]["realtime"] = bool(
                        dstatus.get("RealTimeProtectionEnabled", False)
                    )
                    result["defender"]["antivirus"] = bool(
                        dstatus.get("AntivirusEnabled", False)
                    )
        except Exception:
            pass

    return web.json_response(result)


async def handle_detection_alerts(request: web.Request) -> web.Response:
    """Recent alerts from Wazuh, Elastic, and Defender."""
    import aiohttp as _aio

    minutes = int(request.query.get("minutes", "10"))
    min_level = int(request.query.get("min_level", "1"))
    result = {"wazuh": [], "defender": []}

    # Wazuh alerts via indexer (faster than API)
    try:
        conn = _aio.TCPConnector(ssl=False)
        async with _aio.ClientSession(connector=conn) as s:
            body = {
                "size": 50,
                "sort": [{"timestamp": "desc"}],
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"agent.id": "001"}},
                            {"range": {"rule.level": {"gte": min_level}}},
                            {"range": {"timestamp": {"gte": f"now-{minutes}m"}}},
                        ]
                    }
                },
            }
            async with s.post(
                f"{ELASTIC_URL}/wazuh-alerts-*/_search",
                json=body,
                headers={"Content-Type": "application/json"},
                timeout=_aio.ClientTimeout(total=10),
            ) as r:
                data = await r.json()
                for hit in data.get("hits", {}).get("hits", []):
                    src = hit["_source"]
                    rule = src.get("rule", {})
                    result["wazuh"].append({
                        "timestamp": src.get("timestamp", ""),
                        "level": rule.get("level", 0),
                        "rule_id": rule.get("id", ""),
                        "description": rule.get("description", ""),
                        "groups": rule.get("groups", []),
                        "mitre": rule.get("mitre", {}),
                    })
    except Exception:
        pass

    # Defender recent threats
    ssh_up = await _ssh_reachable()
    if ssh_up:
        try:
            async with asyncssh.connect(
                "localhost", port=10022, username="vmuser", password="vmuser123",
                known_hosts=None, connect_timeout=5,
            ) as conn:
                r = await conn.run(
                    'powershell -Command "Get-MpThreatDetection | '
                    f'Where-Object {{ $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-{minutes}) }} | '
                    'Select-Object ThreatID,Resources,InitialDetectionTime | '
                    'ConvertTo-Json"',
                    check=False, timeout=15,
                )
                if r.exit_status == 0 and r.stdout.strip():
                    import re
                    cleaned = re.sub(r'\r', '', r.stdout.strip())
                    threats = json.loads(cleaned)
                    if isinstance(threats, dict):
                        threats = [threats]
                    for t in threats:
                        result["defender"].append({
                            "threat_id": str(t.get("ThreatID", "")),
                            "resources": t.get("Resources", []),
                            "time": str(t.get("InitialDetectionTime", "")),
                        })
        except Exception:
            pass

    # Summary counts
    wazuh_high = sum(1 for a in result["wazuh"] if a["level"] >= 8)
    wazuh_med = sum(1 for a in result["wazuh"] if 5 <= a["level"] < 8)
    wazuh_low = sum(1 for a in result["wazuh"] if a["level"] < 5)
    result["summary"] = {
        "wazuh_total": len(result["wazuh"]),
        "wazuh_high": wazuh_high,
        "wazuh_medium": wazuh_med,
        "wazuh_low": wazuh_low,
        "defender_total": len(result["defender"]),
    }

    return web.json_response(result)


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
    app.router.add_get("/api/vm/status", handle_vm_status)
    app.router.add_post("/api/vm/boot", handle_vm_boot)
    app.router.add_post("/api/vm/shutdown", handle_vm_shutdown)
    app.router.add_post("/api/vm/install", handle_vm_install)
    app.router.add_post("/api/vm/snapshot", handle_vm_snapshot)
    app.router.add_get("/api/c2", handle_c2_status)
    app.router.add_post("/api/c2/start", handle_c2_start)
    app.router.add_post("/api/c2/stop", handle_c2_stop)
    app.router.add_get("/api/c2/data/{filename}", handle_c2_data)
    app.router.add_get("/api/edr/manage/status", handle_edr_status)
    app.router.add_post("/api/edr/manage/toggle", handle_edr_toggle)
    app.router.add_post("/api/edr/manage/preset", handle_edr_preset)
    app.router.add_post("/api/edr/run", handle_edr_run)
    app.router.add_post("/api/edr/score-only", handle_edr_score_only)
    app.router.add_get("/api/edr/scores", handle_edr_scores)
    app.router.add_get("/api/edr/scores/{filename}", handle_edr_score_file)
    app.router.add_get("/api/chunk/recipes", handle_chunk_recipes)
    app.router.add_get("/api/chunk/layers", handle_chunk_layers)
    app.router.add_post("/api/chunk/auto-select", handle_chunk_auto_select)
    app.router.add_post("/api/chunk/build", handle_chunk_build)
    app.router.add_post("/api/chunk/hybrid", handle_chunk_hybrid)
    app.router.add_get("/api/chunk/history", handle_chunk_history)
    app.router.add_get("/api/detection/status", handle_detection_status)
    app.router.add_get("/api/detection/alerts", handle_detection_alerts)
    app.router.add_get("/ws/ssh", handle_ssh_ws)
    app.router.add_get("/ws/{job_id}", handle_ws)
    return app
