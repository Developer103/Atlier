"""
Pydantic models for VM configuration.
"""

import enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


class TargetOS(enum.Enum):
    WINDOWS_11 = "windows-11"
    WINDOWS_10 = "windows-10"
    UBUNTU_24_04 = "ubuntu-24.04"
    UBUNTU_22_04 = "ubuntu-22.04"
    DEBIAN_BOOKWORM = "debian-bookworm"


class EDRConfig(BaseModel):
    """EDR to install on the provisioned VM."""
    name: str  # "crowdstrike", "defender", "sentinelone", "sysmon"
    token: Optional[str] = None  # Customer token if required
    config_path: Optional[Path] = None  # Path to config/overrides


class NetworkConfig(BaseModel):
    """QEMU network config."""
    port_fwd_ssh: int = 10022  # Host port -> VM port 22
    port_fwd_rdp: Optional[int] = 10033  # Optional: host port -> VM port 3389
    vm_ip_in_subnet: str = "10.0.0.10"  # Static IP via guest agent
    use_internet: bool = False


class VMResourceSpec(BaseModel):
    CPU_cores: int = 4
    RAM_GB: int = 8
    disk_GB: int = 64


class VMProvisionConfig(BaseModel):
    """Master config for provisioning a single VM."""
    os_type: TargetOS
    resources: VMResourceSpec = Field(default_factory=VMResourceSpec)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    edrs: list[EDRConfig] = Field(default_factory=list)

    # Internal paths (set by provision engine)
    base_dir: Path = Field(default=Path("/tmp/vm_provision"))
    base_img: Optional[Path] = None
    cow_img: Optional[Path] = None
    cloud_init_iso: Optional[Path] = None
    autounattend_iso: Optional[Path] = None
    qmp_socket: Optional[Path] = None
    vm_name: str = "vm_%s"
    disk: Optional[Path] = Field(default=None, exclude=True)  # Computed, not serialized

    def compute_paths(self):
        """Fill in computed paths based on os_type and base_dir."""
        self.base_dir.mkdir(parents=True, exist_ok=True)
        _is_windows = self.os_type.value.startswith("windows")
        # Windows base image is an ISO file; Linux base image is a qcow2 cloud image.
        _base_ext = ".iso" if _is_windows else ".qcow2"
        self.base_img = self.base_dir / f"base_{self.os_type.value}{_base_ext}"
        self.cow_img = self.base_dir / f"base_{self.os_type.value}.cow.qcow2"
        self.cloud_init_iso = self.base_dir / f"cloud-init-{self.os_type.value}.iso"
        self.autounattend_iso = self.base_dir / f"autounattend-{self.os_type.value}.iso"
        self.qmp_socket = self.base_dir / f"vm-{self.os_type.value}.qmp"
        self.disk = self.cow_img if self.cow_img else self.base_img
