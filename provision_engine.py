"""
Main VM Provision Engine.

Orchestrates the full provisioning pipeline:
  1. Create COW disk from base OS image
  2. Create cloud-init (Linux) or autounattend (Windows) ISO
  3. Boot VM with QEMU
  4. Wait for SSH readiness
  5. Return a VMInstance ready for command execution
"""

import asyncio
import json
import logging
import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Optional

import asyncssh

from .config_models import TargetOS, VMProvisionConfig
from .image_sources import ensure_linux_image, ensure_windows_iso
from .linux_provisioner import generate_cloud_init_yaml, create_cloud_init_iso
from .windows_provisioner import generate_autounattend_xml, create_autounattend_iso

logger = logging.getLogger(__name__)


def _get_host_ip() -> str:
    """Get the host IP reachable from a QEMU guest (10.0.2.2 for user-mode networking)."""
    return "10.0.2.2"


class SSHBridgeException(Exception):
    pass


def cleanup_orphan_vms(name_prefix: str = "malgen_") -> int:
    """Kill QEMU processes whose -name starts with name_prefix.

    Returns the number of processes killed.
    """
    killed = 0
    try:
        out = subprocess.check_output(
            ["pgrep", "-a", "-f", f"qemu-system.*-name {name_prefix}"],
            text=True, stderr=subprocess.DEVNULL,
        )
        for line in out.strip().splitlines():
            pid_str = line.split()[0]
            try:
                pid = int(pid_str)
                os.kill(pid, 15)
                killed += 1
                logger.info("Killed orphan QEMU pid %d", pid)
            except (ValueError, ProcessLookupError):
                pass
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return killed


# ---------------------------------------------------------------------------
# QEMUProcess  -  wraps a single QEMU VM lifecycle
# ---------------------------------------------------------------------------

class QEMUProcess:
    """Manage a single QEMU virtual machine process."""

    def __init__(
        self,
        vm_name: str,
        qmp_socket: Path,
        disk_img: Path,
        cpu_cores: int = 4,
        ram_mb: int = 8192,
        iso_path: Optional[Path] = None,
        windows_install_iso: Optional[Path] = None,
        windows_virtio_iso: Optional[Path] = None,
        windows_boot_only: bool = False,
        use_tpm: bool = False,
        ssh_port: int = 10022,
        vm_user: str = "vmuser",
        vm_pass: str = "vmuser123",
    ):
        self.vm_name: str = vm_name
        self.qmp_socket: Path = qmp_socket
        self.disk_img: Path = disk_img
        self.cpu_cores: int = cpu_cores
        self.ram_mb: int = ram_mb
        self.iso_path: Optional[Path] = iso_path
        self.windows_install_iso: Optional[Path] = windows_install_iso
        self.windows_virtio_iso: Optional[Path] = windows_virtio_iso
        self.windows_boot_only: bool = windows_boot_only
        self.use_tpm: bool = use_tpm
        self.ssh_port: int = ssh_port
        self.vm_user: str = vm_user
        self.vm_pass: str = vm_pass
        self.process = None
        self._swtpm_proc: Optional[subprocess.Popen] = None
        self._keypress_task: Optional[asyncio.Task] = None
        self.started: bool = False

    # ------------------------------------------------------------------
    # command helpers
    # ------------------------------------------------------------------

    def build_command(self) -> list[str]:
        """Build the QEMU command line, dispatching on Linux vs Windows guest."""
        if self.windows_boot_only:
            return self._build_windows_boot_command()
        if self.windows_install_iso:
            return self._build_windows_command()
        return self._build_linux_command()

    def _build_linux_command(self) -> list[str]:
        """QEMU command line for a Linux cloud-image guest."""
        cmd: list[str] = [
            "qemu-system-x86_64",
            "-enable-kvm",
            "-name", self.vm_name,
            "-m", str(self.ram_mb),
            "-cpu", "host",
            "-smp", f"cores={self.cpu_cores}",
            "-machine", "q35,accel=kvm",
            # Ubuntu cloud images work fine with SeaBIOS — no UEFI needed.
            "-drive", f"file={self.disk_img},format=qcow2,if=virtio,cache=none",
            "-netdev", "user,id=net0,hostfwd=tcp::10022-:22",
            "-device", "virtio-net-pci,netdev=net0,romfile=off",
            "-qmp", f"unix:{self.qmp_socket},server,nowait",
            "-nographic",
            "-display", "none",
            "-serial", "file:/tmp/vm.log",
        ]
        if self.iso_path:
            cmd.extend([
                "-drive", f"file={self.iso_path},if=ide,format=raw,media=cdrom,index=3",
            ])
        return cmd

    def _build_windows_command(self) -> list[str]:
        """QEMU command line for a Windows installation guest.

        Uses if=ide,index=N (implicit ICH9-AHCI) rather than explicit
        -device ich9-ahci.  The implicit path correctly sets the PI (Ports
        Implemented) register for every attached port; with an explicit
        ich9-ahci device QEMU only marks the port that OVMF probed during
        the initial (failing) boot attempt, leaving HDD/VirtIO/autounattend
        invisible in the EFI shell mapping table.

        The autounattend disk is a raw FAT12 image presented as a USB storage
        device (qemu-xhci + usb-storage,removable=on).  Windows WinPE only
        scans removable USB drives for autounattend.xml; additional CD-ROMs
        and plain IDE disks are ignored.  The removable=on flag sets the SCSI
        RMB bit so Windows classifies it as a flash drive, not a fixed disk.
        """
        cmd: list[str] = [
            "qemu-system-x86_64",
            "-enable-kvm",
            "-name", self.vm_name,
            "-m", str(self.ram_mb),
            "-cpu", "host",
            "-smp", f"cores={self.cpu_cores}",
            "-machine", "q35,accel=kvm",
            "-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
            "-drive", f"if=pflash,format=raw,file={self.disk_img.parent / 'OVMF_VARS_4M.fd'}",
            "-drive", f"if=ide,index=0,file={self.disk_img},format=qcow2,cache=none",
            "-drive", f"if=ide,index=1,file={self.windows_install_iso},format=raw,media=cdrom,readonly=on,cache=unsafe",
        ]
        if self.windows_virtio_iso and self.windows_virtio_iso.exists():
            cmd.extend([
                "-drive", f"if=ide,index=2,file={self.windows_virtio_iso},format=raw,media=cdrom,readonly=on,cache=unsafe",
            ])
        if self.iso_path and self.iso_path.exists():
            # Present autounattend FAT12 as USB storage so Windows WinPE reliably
            # finds autounattend.xml (WinPE always scans removable USB drives for
            # autounattend.xml; additional CD-ROMs and plain IDE disks are not
            # scanned). OVMF's USB stack also reads the device so startup.nsh
            # works from the EFI shell in Phase-2 reboots.
            cmd.extend([
                "-device", "qemu-xhci,id=xhci0",
                "-drive", f"if=none,id=autounattend_disk,format=raw,file={self.iso_path},cache=unsafe",
                "-device", "usb-storage,bus=xhci0.0,drive=autounattend_disk,removable=on",
            ])
        if self.use_tpm:
            tpm_sock = self.disk_img.parent / f"{self.vm_name}-tpm.sock"
            cmd.extend([
                "-chardev", f"socket,id=chrtpm,path={tpm_sock}",
                "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
                "-device", "tpm-tis,tpmdev=tpm0",
            ])
        cmd.extend([
            "-qmp", f"unix:{self.qmp_socket},server,nowait",
            "-netdev", "user,id=net0,hostfwd=tcp::10022-:22",
            "-device", "e1000,netdev=net0,romfile=",
            "-vga", "std",
            "-vnc", "127.0.0.1:1",
            "-serial", "file:/tmp/vm.log",
        ])
        return cmd

    def _build_windows_boot_command(self) -> list[str]:
        """QEMU command to boot an already-installed Windows disk — no installer ISO."""
        cmd = [
            "qemu-system-x86_64",
            "-enable-kvm",
            "-name", self.vm_name,
            "-m", str(self.ram_mb),
            "-cpu", "host",
            "-smp", f"cores={self.cpu_cores}",
            "-machine", "q35,accel=kvm",
            "-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
            "-drive", f"if=pflash,format=raw,file={self.disk_img.parent / 'OVMF_VARS_4M.fd'}",
            "-drive", f"if=ide,index=0,file={self.disk_img},format=qcow2,cache=none",
        ]
        if self.use_tpm:
            tpm_sock = self.disk_img.parent / f"{self.vm_name}-tpm.sock"
            cmd.extend([
                "-chardev", f"socket,id=chrtpm,path={tpm_sock}",
                "-tpmdev", "emulator,id=tpm0,chardev=chrtpm",
                "-device", "tpm-tis,tpmdev=tpm0",
            ])
        cmd.extend([
            "-qmp", f"unix:{self.qmp_socket},server,nowait",
            "-netdev", "user,id=net0,hostfwd=tcp::10022-:22",
            "-device", "e1000,netdev=net0,romfile=",
            "-vga", "std",
            "-vnc", "127.0.0.1:1",
            "-serial", "file:/tmp/vm.log",
        ])
        return cmd

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    @staticmethod
    def _kill_stale_qemu(vm_name: str, qmp_socket: Path) -> None:
        """Kill any lingering QEMU process for this VM and wait until it exits.

        fuser -n tcp cannot see QEMU SLIRP listening sockets, so we identify
        the stale process by its QMP socket path or -name flag instead.
        """
        import signal as _signal
        import time

        def _pid_alive(pid: int) -> bool:
            try:
                os.kill(pid, 0)
                return True
            except ProcessLookupError:
                return False

        killed: set[int] = set()
        for pattern in [str(qmp_socket), f"-name {vm_name}"]:
            try:
                out = subprocess.check_output(
                    ["pgrep", "-f", f"qemu-system-x86_64.*{pattern}"],
                    text=True, stderr=subprocess.DEVNULL, timeout=5,
                )
                for pid_str in out.splitlines():
                    try:
                        pid = int(pid_str.strip())
                        os.kill(pid, _signal.SIGKILL)
                        killed.add(pid)
                        logger.warning("Killed stale QEMU PID=%d (matched %r)", pid, pattern)
                    except (ValueError, ProcessLookupError, PermissionError):
                        pass
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass

        qmp_socket.unlink(missing_ok=True)

        if not killed:
            return
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if not any(_pid_alive(pid) for pid in killed):
                return
            time.sleep(0.1)
        logger.warning("Stale QEMU PIDs %s still alive after 5 s", killed)

    @staticmethod
    def _start_swtpm(state_dir: Path, socket_path: Path) -> "subprocess.Popen[bytes]":
        """Start a swtpm TPM 2.0 emulator and wait until its control socket appears."""
        import time
        state_dir.mkdir(parents=True, exist_ok=True)
        socket_path.unlink(missing_ok=True)
        proc = subprocess.Popen(
            [
                "swtpm", "socket",
                "--tpmstate", f"dir={state_dir}",
                "--ctrl", f"type=unixio,path={socket_path}",
                "--tpm2",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if socket_path.exists():
                logger.info("swtpm ready (PID=%d, socket=%s)", proc.pid, socket_path)
                return proc
            if proc.poll() is not None:
                raise RuntimeError(f"swtpm exited early (code={proc.returncode})")
            time.sleep(0.1)
        proc.kill()
        raise RuntimeError(f"swtpm did not create {socket_path} within 10 s")

    @staticmethod
    def _wait_for_port_free(port: int, timeout: float = 5.0) -> None:
        """Block until *port* is bindable on 0.0.0.0 (what QEMU uses), or log a warning."""
        import time

        def _free() -> bool:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("0.0.0.0", port))
                s.close()
                return True
            except OSError:
                return False

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if _free():
                return
            time.sleep(0.2)
        logger.error("Port %d still occupied after %.1f s — QEMU may fail to bind", port, timeout)

    @staticmethod
    def _check_kvm_access() -> None:
        """Raise a clear error if /dev/kvm is not accessible."""
        try:
            fd = os.open("/dev/kvm", os.O_RDWR)
            os.close(fd)
        except PermissionError:
            raise RuntimeError(
                "/dev/kvm is not accessible by the current user.\n"
                "Fix: sudo usermod -aG kvm $USER  then start a new shell session."
            )
        except FileNotFoundError:
            raise RuntimeError("/dev/kvm not found — is KVM enabled in the kernel/BIOS?")

    async def start(self, background: bool = True) -> None:
        """Start the VM using QEMU."""
        self._check_kvm_access()
        # Kill any stale QEMU for this VM (fuser cannot see SLIRP sockets, so
        # we identify the process by QMP socket path / -name flag instead).
        await asyncio.to_thread(self._kill_stale_qemu, self.vm_name, self.qmp_socket)
        # Start swtpm before QEMU so the control socket exists when QEMU starts.
        if self.use_tpm:
            tpm_state = self.disk_img.parent / f"{self.vm_name}-tpm"
            tpm_sock = self.disk_img.parent / f"{self.vm_name}-tpm.sock"
            # Fresh install needs a clean TPM so Windows initialises it from
            # scratch.  Boot-only mode must preserve state (Windows already
            # enrolled the vTPM during install).
            if self.windows_install_iso and not self.windows_boot_only:
                shutil.rmtree(tpm_state, ignore_errors=True)
            self._swtpm_proc = await asyncio.to_thread(
                self._start_swtpm, tpm_state, tpm_sock
            )
        cmd = self.build_command()
        for arg in cmd:
            if "hostfwd=tcp::" in arg:
                try:
                    port = int(arg.split("hostfwd=tcp::")[1].split("-")[0])
                    await asyncio.to_thread(self._wait_for_port_free, port)
                except (IndexError, ValueError):
                    pass
                break
        logger.info("Starting VM: %s ...", " ".join(cmd[:10]))
        log_path = Path("/tmp/vm_output.log")
        if background:
            self.process = subprocess.Popen(
                cmd,
                stdout=open(log_path, "w"),
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        else:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            await asyncio.to_thread(self.process.poll)

        # Brief pause then check whether QEMU is still alive — it exits within
        # milliseconds on a bad command-line flag, saving us a 90-minute wait.
        await asyncio.sleep(2)
        if self.process.poll() is not None:
            log_text = log_path.read_text(errors="replace") if log_path.exists() else "(no log)"
            raise RuntimeError(
                f"QEMU exited immediately (rc={self.process.returncode}).\n"
                f"Command: {' '.join(cmd)}\n"
                f"Output:\n{log_text.strip()}"
            )

        self.started = True
        self.status = "running"
        logger.info("VM started: PID=%d", self.process.pid)
        if self.windows_install_iso and not self.windows_boot_only:
            self._keypress_task = asyncio.ensure_future(self._inject_boot_keypresses())
            logger.info("Scheduled cdboot.efi keypress injection (T+1s to T+16s via VNC)")

    async def stop(self, wait: bool = True) -> None:
        """Stop the VM gracefully, then clean up."""
        if not self.process or self.process.poll() is not None:
            self.status = "stopped"
            return

        # Try graceful shutdown via QMP
        try:
            await self._send_qmp("system_powerdown")
            logger.info("Sent powerdown via QMP")
        except Exception:
            logger.warning("QMP powerdown failed")

        # Try SSH poweroff as fallback
        try:
            await self._ssh_poweroff()
        except Exception:
            pass

        if wait:
            deadline = asyncio.get_event_loop().time() + 30
            while asyncio.get_event_loop().time() < deadline:
                if self.process.poll() is not None:
                    break
                await asyncio.sleep(0.1)
            else:
                logger.warning("VM didn't power down gracefully; force killing")
                self.process.kill()

        if self._keypress_task and not self._keypress_task.done():
            self._keypress_task.cancel()
            self._keypress_task = None

        if self._swtpm_proc and self._swtpm_proc.poll() is None:
            self._swtpm_proc.kill()
            self._swtpm_proc = None

        self.status = "stopped"
        self.process = None
        self.started = False
        logger.info("VM stopped: %s", self.qmp_socket)

    async def _send_qmp(self, command: str, arguments: Optional[dict] = None) -> dict:
        """Send a QMP command and return the parsed response dict."""
        if not self.qmp_socket.exists():
            raise SSHBridgeException("QMP socket missing")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(str(self.qmp_socket))
            # QMP: server sends greeting first, then we negotiate capabilities
            _ = sock.recv(4096)  # read greeting
            sock.sendall(b'{"execute":"qmp_capabilities"}\n')
            _ = sock.recv(4096)  # read {"return":{}}
            # issue command
            payload_dict: dict = {"execute": command}
            if arguments:
                payload_dict["arguments"] = arguments
            payload = json.dumps(payload_dict).encode() + b"\n"
            sock.sendall(payload)
            data = sock.recv(4096).decode()
            for line in data.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if "return" in obj or "error" in obj:
                        return obj
                except json.JSONDecodeError:
                    continue
            return json.loads(data.split('\n')[0])
        finally:
            sock.close()

    async def _inject_boot_keypresses(self) -> None:
        """Inject Enter keypresses into the VM to hit cdboot.efi's 'Press any key' window.

        OVMF POST + BDS takes ~3-5 s; cdboot.efi then shows a 5-s countdown.
        Firing Enter every 0.5 s from T=3 s to T=16 s ensures we land in the window.
        cdboot.efi accepts the key and immediately boots WinPE (no prompt variant isn't
        reachable from the EFI shell context, so we press the key in the BDS path instead).
        """
        await asyncio.sleep(1.0)
        deadline = asyncio.get_event_loop().time() + 15.0
        while asyncio.get_event_loop().time() < deadline:
            try:
                await self._send_qmp(
                    "send-key",
                    {"keys": [{"type": "qcode", "data": "ret"}]},
                )
            except Exception:
                pass
            await asyncio.sleep(0.5)

    async def save_snapshot(self, tag: str = "clean_state") -> None:
        """Create a disk overlay so all subsequent writes go to a temp file.

        Uses blockdev-snapshot-sync instead of savevm because UEFI pflash
        devices don't support qcow2 internal snapshots (savevm crashes with
        "Device 'pflash1' is writable but does not support snapshots").

        The overlay file is named after the tag.  restore_snapshot() discards
        it and reboots from the clean base disk.
        """
        overlay = self.disk_img.parent / f"{self.disk_img.stem}.overlay-{tag}.qcow2"
        overlay.unlink(missing_ok=True)
        result = await self._send_qmp("blockdev-snapshot-sync", {
            "device": "ide0-hd0",
            "snapshot-file": str(overlay),
            "format": "qcow2",
        })
        if "error" in str(result):
            raise RuntimeError(f"blockdev-snapshot-sync failed: {result}")
        self._overlay_path = overlay
        logger.info("Overlay snapshot created: tag=%s overlay=%s", tag, overlay.name)

    async def restore_snapshot(self, tag: str = "clean_state") -> None:
        """Restore VM to pre-snapshot state by discarding the overlay.

        Sequence: SSH shutdown → wait for QEMU exit → delete overlay →
        restart swtpm → reboot QEMU → wait for SSH.
        """
        overlay = getattr(self, "_overlay_path", None)
        if not overlay:
            overlay = self.disk_img.parent / f"{self.disk_img.stem}.overlay-{tag}.qcow2"

        # 1. Graceful shutdown
        try:
            await self._ssh_poweroff()
        except Exception:
            try:
                await self._send_qmp("system_powerdown")
            except Exception:
                pass

        # 2. Wait for QEMU to exit
        if self.process:
            deadline = asyncio.get_event_loop().time() + 30
            while asyncio.get_event_loop().time() < deadline:
                if self.process.poll() is not None:
                    break
                await asyncio.sleep(0.5)
            else:
                self.process.kill()
                await asyncio.sleep(1)

        # 3. Discard overlay
        if overlay.exists():
            overlay.unlink()
        self._overlay_path = None

        # 4. Clean up sockets
        self.qmp_socket.unlink(missing_ok=True)

        # 5. Restart swtpm if needed
        if self.use_tpm:
            if self._swtpm_proc and self._swtpm_proc.poll() is None:
                self._swtpm_proc.kill()
                self._swtpm_proc = None
            tpm_state = self.disk_img.parent / f"{self.vm_name}-tpm"
            tpm_sock = self.disk_img.parent / f"{self.vm_name}-tpm.sock"
            tpm_sock.unlink(missing_ok=True)
            self._swtpm_proc = await asyncio.to_thread(
                self._start_swtpm, tpm_state, tpm_sock
            )

        # 6. Reboot from clean base disk
        await self.start(background=True)

        # 7. Wait for SSH
        _is_windows = bool(self.windows_install_iso or self.windows_boot_only)
        ssh_timeout = 120 if _is_windows else 60
        ssh_ready = await ProvisionEngine._wait_for_ssh(
            port=10022, timeout=ssh_timeout, interval=5.0,
        )
        if not ssh_ready:
            logger.error("VM did not come back after overlay restore (timeout=%ds)", ssh_timeout)
            raise RuntimeError("VM failed to boot after snapshot restore")
        logger.info("Snapshot restored: tag=%s (overlay discarded, VM rebooted)", tag)

    async def _ssh_poweroff(self) -> None:
        """Send poweroff to the running guest over SSH (fallback)."""
        if self.status != "running":
            return
        _is_windows = bool(self.windows_install_iso or self.windows_boot_only)
        _cmd = "shutdown /s /t 0" if _is_windows else "poweroff"
        async with asyncssh.connect("localhost", port=self.ssh_port, username=self.vm_user,
                                    password=self.vm_pass, known_hosts=None) as conn:
            await conn.run(_cmd, check=True)

    def destroy(self) -> None:
        """Destroy the VM process and clean up files."""
        if self.qmp_socket.exists():
            self.qmp_socket.unlink()
        if self.disk_img.exists():
            self.disk_img.unlink()
        self.status = "destroyed"


# ---------------------------------------------------------------------------
# VMInstance  -  thin wrapper around QEMUProcess with SSH bridge semantics
# ---------------------------------------------------------------------------

class VMInstance:
    """Represents a running VM instance ready for SSH command execution.

    Pass ``qemu=None`` when attaching to an already-running VM (i.e. with
    ``--use-existing-vm``) — start/stop become no-ops in that case.
    """

    def __init__(
        self,
        qemu: Optional[QEMUProcess] = None,
        vm_user: str = "vmuser",
        vm_pass: str = "vmuser123",
        ssh_port: int = 10022,
    ):
        self.qemu = qemu
        self.vm_user = vm_user
        self.vm_pass = vm_pass
        self.ssh_port = ssh_port
        self.ip: Optional[str] = None
        self.status: str = "provisioning"

    async def start(self, background: bool = True) -> None:
        """Start the underlying QEMU process (no-op for pre-existing VMs)."""
        if self.qemu:
            await self.qemu.start(background)
        self.status = "running"

    async def stop(self, wait: bool = True) -> None:
        """Gracefully stop the VM (no-op for pre-existing VMs)."""
        if self.qemu:
            await self.qemu.stop(wait)
        self.status = "stopped"

    async def execute_command(self, command: str, timeout: int = 30) -> str:
        """Execute *command* on the running VM via SSH."""
        if self.status != "running":
            raise SSHBridgeException("VM is not running")
        async with asyncssh.connect(
            "localhost", port=self.ssh_port,
            username=self.vm_user, password=self.vm_pass,
            known_hosts=None,
        ) as conn:
            result = await conn.run(command, check=False, timeout=timeout)
        return (result.stdout or "") + (result.stderr or "")

    async def upload_file(self, local_path: str, remote_path: str) -> None:
        """Upload a local file to the VM via SFTP."""
        if self.status != "running":
            raise SSHBridgeException("VM is not running")
        async with asyncssh.connect(
            "localhost", port=self.ssh_port,
            username=self.vm_user, password=self.vm_pass,
            known_hosts=None,
        ) as conn:
            async with conn.start_sftp_client() as sftp:
                await sftp.put(local_path, remote_path)

    async def save_snapshot(self, tag: str = "clean_state") -> None:
        """Create a disk overlay snapshot (no-op for pre-existing VMs without QEMU handle)."""
        if self.qemu:
            await self.qemu.save_snapshot(tag)

    async def restore_snapshot(self, tag: str = "clean_state") -> None:
        """Restore VM by discarding overlay, rebooting, and waiting for SSH.

        The underlying QEMUProcess handles the full shutdown→discard→reboot cycle.
        """
        if self.qemu:
            await self.qemu.restore_snapshot(tag)
            self.status = "running"

    def get_status(self) -> dict:
        """Return current status dictionary."""
        status = {
            "status": self.status,
            "ip": self.ip,
            "ssh_port": self.ssh_port,
            "user": self.vm_user,
        }
        if self.qemu:
            status["qmp_socket"] = str(self.qemu.qmp_socket)
            status["disk"] = str(self.qemu.disk_img)
        return status


# ---------------------------------------------------------------------------
# ProvisionEngine  -  full pipeline orchestrator
# ---------------------------------------------------------------------------

class ProvisionEngine:
    """
    Orchestrates the VM provisioning pipeline:
      1. Ensure base OS image
      2. Create COW snapshot
      3. Create auto-provisioning ISO
      4. Boot VM
      5. Wait for SSH
      6. Return active VMInstance
    """

    def __init__(self, base_dir: Optional[Path] = None, daemonize: bool = False):
        self.base_dir = Path(base_dir) if base_dir else Path("/tmp/vm_provision")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.instances: dict[str, VMInstance] = {}
        self.daemonize = daemonize
        if not daemonize:
            import atexit
            atexit.register(self._atexit_cleanup)

    # ---------------------------------------------------------------
    # public API
    # ---------------------------------------------------------------

    # apt package name for each required binary
    _APT_PACKAGES: dict[str, str] = {
        "qemu-system-x86_64":        "qemu-system-x86",
        "qemu-img":                  "qemu-utils",
        "genisoimage":               "genisoimage",
        "aria2c":                    "aria2",
        "swtpm":                     "swtpm",
        "x86_64-w64-mingw32-gcc":    "gcc-mingw-w64-x86-64",
    }

    @staticmethod
    def ensure_prerequisites() -> None:
        """Auto-install any missing system tools required for VM provisioning.

        Attempts a non-interactive ``sudo apt-get install`` for each missing
        package.  If ``sudo`` is unavailable or requires a password, raises a
        ``RuntimeError`` with manual install instructions.
        """
        missing = {
            tool: pkg
            for tool, pkg in ProvisionEngine._APT_PACKAGES.items()
            if not shutil.which(tool)
        }
        if not missing:
            return

        pkgs = list(dict.fromkeys(missing.values()))  # deduplicated, order-preserving
        logger.info("Auto-installing missing VM dependencies: %s", " ".join(pkgs))
        env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
        result = subprocess.run(
            ["sudo", "-n", "apt-get", "install", "-y", "--no-install-recommends"] + pkgs,
            env=env,
            timeout=300,
        )

        # Refresh PATH cache and re-check
        still_missing = [t for t in missing if not shutil.which(t)]
        if still_missing or result.returncode != 0:
            lines = [
                f"  sudo apt install {pkg}  # provides {tool!r}"
                for tool, pkg in missing.items()
                if not shutil.which(tool)
            ]
            raise RuntimeError(
                "Could not auto-install required VM tools "
                f"(apt exit={result.returncode}). Install manually:\n"
                + "\n".join(lines)
            )
        logger.info("VM dependencies installed: %s", " ".join(pkgs))

    async def provision(
        self,
        config: VMProvisionConfig,
        background: bool = True,
    ) -> VMInstance:
        """Run the full provisioning pipeline and return a ready VMInstance."""

        # Auto-install any missing system tools before touching disk or network.
        self.ensure_prerequisites()

        # Resolve all computed paths (base_img, cow_img, qmp_socket, etc.) if not
        # already done by the caller.
        if config.base_img is None:
            config.compute_paths()

        # Flatten nested config fields into local variables so the rest of this
        # method doesn't need to know about the nesting.
        _username = "vmuser"
        _password = "vmuser123"
        _ssh_key: Optional[str] = None
        _enable_ssh = True
        _skip_tpm = True
        _cpu_cores = config.resources.CPU_cores
        _ram_mb = config.resources.RAM_GB * 1024
        _ssh_port = config.network.port_fwd_ssh
        _vm_name = f"vm-{config.os_type.value}"

        # 1. Ensure base OS image
        if config.os_type in (TargetOS.UBUNTU_24_04, TargetOS.UBUNTU_22_04):
            config.base_img = await ensure_linux_image(config.os_type, config.base_img)
        elif config.os_type in (TargetOS.WINDOWS_11, TargetOS.WINDOWS_10):
            config.base_img = await ensure_windows_iso(
                config.os_type, config.base_img,
                config.base_dir / f"virtio-{config.os_type.value}.iso",
            )
        else:
            raise ValueError(f"Unsupported OS type: {config.os_type}")

        if not config.base_img.exists():
            raise FileNotFoundError(f"Base image missing: {config.base_img}")

        # 2. Disk setup — Linux gets a COW snapshot; Windows gets a fresh empty disk
        #    because qemu-img can't use a Windows ISO as a qcow2 backing file.
        #    For Windows: reuse existing COW disk if present (avoids 15+ min reinstall).
        _is_windows = config.os_type in (TargetOS.WINDOWS_11, TargetOS.WINDOWS_10)
        if _is_windows and config.cow_img.exists() and config.cow_img.stat().st_size > 1_000_000_000:
            logger.info("Reusing existing Windows disk: %s (%.1f GB)",
                        config.cow_img, config.cow_img.stat().st_size / 1e9)
        else:
            config.cow_img.unlink(missing_ok=True)
            if not _is_windows:
                subprocess.run(
                    ["qemu-img", "create", "-f", "qcow2",
                     "-b", str(config.base_img), "-F", "qcow2",
                     str(config.cow_img)],
                    check=True, capture_output=True,
                )
                logger.info("COW disk created: %s", config.cow_img)
            else:
                _disk_gb = config.resources.disk_GB
                subprocess.run(
                    ["qemu-img", "create", "-f", "qcow2", str(config.cow_img), f"{_disk_gb}G"],
                    check=True, capture_output=True,
                )
                logger.info("Empty Windows disk created: %s (%d GB)", config.cow_img, _disk_gb)
            # Always start with a fresh OVMF vars — stale vars from a previous
            # failed provision attempt contain bad boot entries that would cause
            # the same UEFI timeout on the next run.
            ovmf_vars_src = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
            ovmf_vars_dst = config.cow_img.parent / "OVMF_VARS_4M.fd"
            if ovmf_vars_src.exists():
                shutil.copy2(ovmf_vars_src, ovmf_vars_dst)

        # 3. Auto-provisioning ISO
        iso_path: Optional[Path] = None
        _virtio_iso_path: Optional[Path] = None
        if not _is_windows:
            cloud_yaml = generate_cloud_init_yaml(
                username=_username,
                password=_password,
                ssh_key=_ssh_key,
            )
            iso_path = create_cloud_init_iso(cloud_yaml, Path("/tmp/cloud-init.iso"))
        else:
            xml_root = generate_autounattend_xml(
                username=_username,
                password=_password,
                enable_ssh=_enable_ssh,
                skip_tpm=_skip_tpm,
            )
            iso_path = create_autounattend_iso(
                xml_root,
                Path("/tmp/autounattend.iso"),
            )
            _virtio_iso_path = config.base_dir / f"virtio-{config.os_type.value}.iso"

        # 4. Build QEMU process + VMInstance
        qemu = QEMUProcess(
            vm_name=_vm_name,
            qmp_socket=config.qmp_socket,
            disk_img=config.cow_img,
            cpu_cores=_cpu_cores,
            ram_mb=_ram_mb,
            iso_path=iso_path,
            windows_install_iso=config.base_img if _is_windows else None,
            windows_virtio_iso=_virtio_iso_path,
            use_tpm=_is_windows,
            ssh_port=_ssh_port,
            vm_user=_username,
            vm_pass=_password,
        )
        vm = VMInstance(qemu, vm_user=_username, vm_pass=_password,
                        ssh_port=_ssh_port)

        # 5. Start VM
        await vm.start(background)

        # 6. Wait for SSH readiness
        # Linux cloud images boot pre-installed (~2 min); Windows installs from
        # scratch and takes 30-60 min under QEMU, so give it 90 min.
        _ssh_timeout = 5400 if _is_windows else 300
        _ssh_timeout_label = f"{_ssh_timeout // 60} minutes"
        logger.info("Waiting for SSH on port %d (timeout: %s) …", vm.ssh_port, _ssh_timeout_label)
        if not await self._wait_for_ssh(vm.ssh_port, timeout=_ssh_timeout,
                                         username=_username, password=_password):
            vm.status = "failed"
            await vm.stop()
            raise TimeoutError(f"VM did not become ready in {_ssh_timeout_label}")

        vm.status = "running"
        key = f"{config.os_type.value}_{config.cow_img.name}"
        self.instances[key] = vm
        logger.info("Provisioned: %s (ready at localhost:%d)", key, vm.ssh_port)

        if self.daemonize and qemu.process:
            pidfile = self.base_dir / f"{_vm_name}.pid"
            pidfile.write_text(str(qemu.process.pid))
            logger.info("Daemon PID file written: %s (pid=%d)", pidfile, qemu.process.pid)

        return vm

    async def install_edr_on_vm(
        self,
        vm: "VMInstance",
        edr_config,
        server_ip: str = "",
    ) -> bool:
        """Install an EDR agent on an already-running VM.

        Works with both provisioned and pre-existing VMs.  Substitutes
        {server_ip}, {token}, {hostname} placeholders in install_command.
        For agent-only EDRs (OpenEDR), no server_ip is needed.
        """
        install_cmd = getattr(edr_config, "install_command", "")
        if not install_cmd:
            logger.warning("No install_command for EDR %s", edr_config.name)
            return False

        if not server_ip:
            server_ip = _get_host_ip()

        install_cmd = install_cmd.replace("{server_ip}", server_ip)
        install_cmd = install_cmd.replace("{fleet_url}", f"https://{server_ip}:8220")
        install_cmd = install_cmd.replace("{token}", edr_config.token or "")

        try:
            hostname_out = await vm.execute_command("hostname", timeout=10)
            install_cmd = install_cmd.replace("{hostname}", hostname_out.strip())
        except Exception:
            pass

        if edr_config.setup_script:
            logger.info("EDR %s: running setup script...", edr_config.name)
            try:
                await vm.execute_command(edr_config.setup_script, timeout=120)
            except Exception as exc:
                logger.warning("EDR %s setup script failed: %s", edr_config.name, exc)

        logger.info("EDR %s: installing agent — %s", edr_config.name, install_cmd[:200])
        try:
            output = await vm.execute_command(install_cmd, timeout=300)
            logger.info("EDR %s install output: %s", edr_config.name, output[:500])
        except Exception as exc:
            logger.error("EDR %s install failed: %s", edr_config.name, exc)
            return False

        return True

    async def create_edr_overlay(
        self,
        base_cow: Path,
        edr_config,
        ssh_port: int = 10022,
        username: str = "vmuser",
        password: str = "vmuser123",
        server_ip: str = "",
    ) -> Path:
        """Create a VM overlay with an EDR agent pre-installed.

        Boots from a COW snapshot of base_cow, installs the EDR agent via SSH,
        shuts down cleanly, and returns the overlay path.  The overlay can then
        be swapped in for testing against that specific EDR.
        """
        overlay_path = self.base_dir / f"edr_{edr_config.name}_overlay.qcow2"
        if overlay_path.exists() and overlay_path.stat().st_size > 500_000_000:
            logger.info("EDR overlay already exists for %s: %s (%.1f GB)",
                        edr_config.name, overlay_path, overlay_path.stat().st_size / 1e9)
            edr_config.vm_overlay = overlay_path
            return overlay_path

        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2",
             "-b", str(base_cow), "-F", "qcow2",
             str(overlay_path)],
            check=True, capture_output=True,
        )
        logger.info("EDR overlay COW created for %s: %s", edr_config.name, overlay_path)

        install_cmd = getattr(edr_config, "install_command", "")
        if not install_cmd:
            logger.warning("No install_command for EDR %s — overlay created but agent not installed",
                           edr_config.name)
            edr_config.vm_overlay = overlay_path
            return overlay_path

        # Boot the overlay VM, install the agent, shut down
        qemu = QEMUProcess(
            vm_name=f"edr-{edr_config.name}",
            qmp_socket=self.base_dir / f"edr-{edr_config.name}.qmp",
            disk_img=overlay_path,
            cpu_cores=2,
            ram_mb=4096,
            windows_boot_only=True,
            use_tpm=True,
            ssh_port=ssh_port,
            vm_user=username,
            vm_pass=password,
        )
        vm = VMInstance(qemu, vm_user=username, vm_pass=password, ssh_port=ssh_port)

        try:
            await vm.start(background=True)
            ssh_ready = await self._wait_for_ssh(
                ssh_port, timeout=300, username=username, password=password,
            )
            if not ssh_ready:
                raise TimeoutError(f"VM for EDR {edr_config.name} did not become SSH-ready")
            vm.status = "running"

            installed = await self.install_edr_on_vm(vm, edr_config, server_ip=server_ip)
            if not installed:
                logger.error("EDR %s agent installation failed on overlay", edr_config.name)

            # Graceful shutdown to commit changes to overlay
            try:
                await vm.execute_command("shutdown /s /t 5", timeout=10)
                await asyncio.sleep(30)
            except Exception:
                pass
            await vm.stop(wait=True)

        except Exception as exc:
            logger.error("EDR overlay provisioning failed for %s: %s", edr_config.name, exc)
            await vm.stop(wait=True)
            raise

        edr_config.vm_overlay = overlay_path
        logger.info("EDR %s overlay ready at %s", edr_config.name, overlay_path)
        return overlay_path

    async def provision_edr_overlays(
        self,
        config: VMProvisionConfig,
        edr_configs: list = None,
    ) -> dict[str, Path]:
        """Create EDR overlays for all requested EDRs.

        Returns dict mapping EDR name → overlay path.
        """
        from .config_models import BUILTIN_EDRS
        if edr_configs is None:
            edr_configs = list(BUILTIN_EDRS.values())

        if not config.cow_img or not config.cow_img.exists():
            logger.warning("Base COW disk not found — cannot create EDR overlays")
            return {}

        results = {}
        for edr_cfg in edr_configs:
            try:
                path = await self.create_edr_overlay(
                    base_cow=config.cow_img,
                    edr_config=edr_cfg,
                    ssh_port=config.network.port_fwd_ssh,
                )
                results[edr_cfg.name] = path
            except Exception as exc:
                logger.error("Failed to create EDR overlay for %s: %s", edr_cfg.name, exc)

        return results

    async def shutdown_all(self, wait: bool = True) -> None:
        """Stop every tracked instance (skipped for daemonized VMs)."""
        if self.daemonize:
            logger.info("Daemonize mode — leaving %d VM(s) running", len(self.instances))
            return
        for key, vm in list(self.instances.items()):
            try:
                await vm.stop(wait)
            except Exception as exc:
                logger.error("Error stopping %s: %s", key, exc)
        self.instances.clear()

    def _atexit_cleanup(self) -> None:
        """Kill any QEMU processes we launched (atexit handler)."""
        for key, vm in list(self.instances.items()):
            if hasattr(vm, '_qemu') and vm._qemu.process and vm._qemu.process.poll() is None:
                try:
                    vm._qemu.process.kill()
                    logger.info("atexit: killed VM %s (pid %d)", key, vm._qemu.process.pid)
                except Exception:
                    pass
        self.instances.clear()

    @staticmethod
    def find_running_vm(base_dir: Optional[Path] = None, vm_name: str = "vm-windows-11") -> Optional[int]:
        """Check if a daemonized VM is still running. Returns PID or None."""
        base = Path(base_dir) if base_dir else Path("/tmp/vm_provision")
        pidfile = base / f"{vm_name}.pid"
        if not pidfile.exists():
            return None
        try:
            pid = int(pidfile.read_text().strip())
            os.kill(pid, 0)
            return pid
        except (ValueError, ProcessLookupError):
            pidfile.unlink(missing_ok=True)
            return None

    # ---------------------------------------------------------------
    # internal helpers
    # ---------------------------------------------------------------

    @staticmethod
    async def _wait_for_ssh(
        port: int,
        timeout: int = 300,
        interval: float = 15.0,
        username: str = "vmuser",
        password: str = "vmuser123",
    ) -> bool:
        """Block until SSH on *port* is up AND authentication succeeds.

        Two-stage check: first confirm the SSH banner (b"SSH-") so we know
        sshd is running, then attempt a real login.  QEMU SLIRP binds the
        forwarded port immediately at VM start (plain TCP always connects), so
        we cannot skip the banner read.  The auth check catches the case where
        sshd started but the guest user account wasn't created yet (e.g. OOBE
        still running).
        """
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            # Stage 1: SSH banner
            try:
                reader, writer = await asyncio.open_connection("localhost", port)
                try:
                    banner = await asyncio.wait_for(reader.read(32), timeout=5.0)
                    got_banner = banner.startswith(b"SSH-")
                except asyncio.TimeoutError:
                    got_banner = False
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                if not got_banner:
                    await asyncio.sleep(interval)
                    continue
            except (ConnectionRefusedError, OSError):
                await asyncio.sleep(interval)
                continue

            # Stage 2: authentication
            try:
                async with asyncssh.connect(
                    "localhost", port=port,
                    username=username, password=password,
                    known_hosts=None, connect_timeout=10,
                ):
                    return True
            except asyncssh.PermissionDenied:
                pass  # sshd up but user not ready yet — keep waiting
            except Exception:
                pass
            await asyncio.sleep(interval)
        return False
