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


class SSHBridgeException(Exception):
    pass


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
    ):
        self.vm_name: str = vm_name
        self.qmp_socket: Path = qmp_socket
        self.disk_img: Path = disk_img
        self.cpu_cores: int = cpu_cores
        self.ram_mb: int = ram_mb
        self.iso_path: Optional[Path] = iso_path
        self.process = None
        self.started: bool = False

    # ------------------------------------------------------------------
    # command helpers
    # ------------------------------------------------------------------

    def build_command(self) -> list[str]:
        """Build the full QEMU command line for a Linux guest."""
        cmd: list[str] = [
            "qemu-system-x86_64",
            "-enable-kvm",
            "-name", self.vm_name,
            "-m", str(self.ram_mb),
            "-cpu", "host",
            "-smp", f"cores={self.cpu_cores}",
            "-machine", "q35,accel=kvm",
            "-bios", "/usr/share/OVMF/OVMF_CODE_4M.fd",
            "-drive", "if=pflash,format=raw,file=/usr/share/OVMF/OVMF_VARS_4M.fd,readonly=on",
            "-drive", f"file={self.disk_img},format=qcow2,if=virtio,cache=none",
            "-mon", f"qmp=unix:{self.qmp_socket},server,nowait",
            "-nographic",
            "-display", "none",
        ]

        # Guest agent
        cmd.extend([
            "-chardev", f"socket,id=gua,path=/tmp/ua.sock,server,nowait",
            "-device", "virtio-serial",
            "-device", "virtioserialport,chardev=gua,name=com.redhat.rhevm.virtioserial.0",
        ])

        # Network (user-mode NAT with host port forwarding)
        cmd.extend([
            "-netdev", "user,id=net0,hostfwd=tcp::10022-:22,tftp=/tmp/tftp",
            "-device", "virtio-net-pci,netdev=net0,romfile=off",
        ])

        # Inject cloud-init / autounattend ISO if present
        if self.iso_path:
            cmd.extend([
                "-drive", f"file={self.iso_path},if=ide,format=raw,media=cdrom,index=3",
            ])

        cmd.extend(["-serial", "file:/tmp/vm.log"])
        return cmd

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    async def start(self, background: bool = True) -> None:
        """Start the VM using QEMU."""
        cmd = self.build_command()
        logger.info("Starting VM: %s ...", " ".join(cmd[:10]))
        if background:
            self.process = subprocess.Popen(
                cmd,
                stdout=open("/tmp/vm_output.log", "w"),
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        else:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            await asyncio.to_thread(self.process.poll)
        self.started = True
        self.status = "running"
        logger.info("VM started: PID=%d", self.process.pid)

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

        self.status = "stopped"
        self.process = None
        self.started = False
        logger.info("VM stopped: %s", self.qmp_socket)

    async def _send_qmp(self, command: str) -> dict:
        """Send a QMP command and return the parsed response dict."""
        if not self.qmp_socket.exists():
            raise SSHBridgeException("QMP socket missing")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(str(self.qmp_socket))
            # hello round-trip
            hello = b'{"execute":"qmp_capabilities"}\n'
            sock.sendall(hello)
            _ = sock.recv(4096)
            # issue command
            payload = json.dumps({"execute": command}).encode() + b"\n"
            sock.sendall(payload)
            data = sock.recv(4096).decode()
            return json.loads(data)
        finally:
            sock.close()

    async def _ssh_poweroff(self) -> None:
        """Send poweroff to the running guest over SSH (fallback)."""
        if self.status != "running":
            return
        async with asyncssh.connect("localhost", port=10022, username="vmuser",
                                    password="vmuser123") as conn:
            await conn.run("poweroff", check=True)

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
    """Represents a running VM instance ready for SSH command execution."""

    def __init__(
        self,
        qemu: QEMUProcess,
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
        """Start the underlying QEMU process."""
        await self.qemu.start(background)
        self.status = "running"

    async def stop(self, wait: bool = True) -> None:
        """Gracefully stop the VM."""
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
            result = await conn.run(command, check=True, timeout=timeout)
        return (result.stdout or "") + (result.stderr or "")

    def get_status(self) -> dict:
        """Return current status dictionary."""
        return {
            "status": self.status,
            "ip": self.ip,
            "ssh_port": self.ssh_port,
            "user": self.vm_user,
            "qmp_socket": str(self.qemu.qmp_socket),
            "disk": str(self.qemu.disk_img),
        }


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

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = Path(base_dir) if base_dir else Path("/tmp/vm_provision")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.instances: dict[str, VMInstance] = {}

    # ---------------------------------------------------------------
    # public API
    # ---------------------------------------------------------------

    async def provision(
        self,
        config: VMProvisionConfig,
        background: bool = True,
    ) -> VMInstance:
        """Run the full provisioning pipeline and return a ready VMInstance."""

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

        # 2. COW snapshot
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2",
             "-b", str(config.base_img), "-F", "qcow2",
             str(config.cow_img)],
            check=True, capture_output=True,
        )
        logger.info("COW disk created: %s", config.cow_img)

        # 3. Auto-provisioning ISO
        iso_path: Optional[Path] = None
        if config.os_type in (TargetOS.UBUNTU_24_04, TargetOS.UBUNTU_22_04):
            cloud_yaml = generate_cloud_init_yaml(
                username=config.username,
                password=config.password,
                ssh_key=config.ssh_key,
            )
            iso_path = create_cloud_init_iso(cloud_yaml, Path("/tmp/cloud-init.iso"))
        elif config.os_type in (TargetOS.WINDOWS_11, TargetOS.WINDOWS_10):
            xml_root = generate_autounattend_xml(
                username=config.username,
                password=config.password,
                enable_ssh=config.enable_ssh,
                skip_tpm=config.skip_tpm,
            )
            iso_path = create_autounattend_iso(xml_root, Path("/tmp/autounattend.iso"))

        # 4. Build QEMU process  + VMInstance
        qemu = QEMUProcess(
            vm_name=config.vm_name,
            qmp_socket=config.qmp_socket,
            disk_img=config.cow_img,
            cpu_cores=config.cpu_cores,
            ram_mb=config.ram_mb,
            iso_path=iso_path,
        )
        vm = VMInstance(qemu, vm_user=config.username, vm_pass=config.password,
                        ssh_port=config.ssh_port)

        # 5. Start VM
        await vm.start(background)

        # 6. Wait for SSH readiness
        logger.info("Waiting for SSH on port %d …", vm.ssh_port)
        if not await self._wait_for_ssh(vm.ssh_port, timeout=300):
            vm.status = "failed"
            await vm.stop()
            raise TimeoutError("VM did not become ready in 5 minutes")

        vm.status = "ready"
        key = f"{config.os_type.value}_{config.cow_img.name}"
        self.instances[key] = vm
        logger.info("Provisioned: %s (ready at localhost:%d)", key, vm.ssh_port)
        return vm

    async def shutdown_all(self, wait: bool = True) -> None:
        """Stop every tracked instance."""
        for key, vm in list(self.instances.items()):
            try:
                await vm.stop(wait)
            except Exception as exc:
                logger.error("Error stopping %s: %s", key, exc)
        self.instances.clear()

    # ---------------------------------------------------------------
    # internal helpers
    # ---------------------------------------------------------------

    @staticmethod
    async def _wait_for_ssh(port: int, timeout: int = 300, interval: float = 0.5) -> bool:
        """Block until *port* is listening on localhost."""
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            try:
                reader, writer = await asyncio.open_connection("localhost", port)
                writer.close()
                await writer.wait_closed()
                return True
            except (ConnectionRefusedError, OSError):
                await asyncio.sleep(interval)
        return False
