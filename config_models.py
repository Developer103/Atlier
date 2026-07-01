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

    # Detection integration
    detection_method: str = "ssh_command"  # "rest_api", "elasticsearch", "log_file", "ssh_command"
    detection_api: str = ""  # API endpoint URL or log path for detection checks
    api_auth: dict = Field(default_factory=dict)  # Auth credentials dict
    alert_query: str = ""  # Query template for checking detection
    severity_threshold: str = "low"  # Minimum severity to count as detected

    # VM setup
    setup_script: Optional[str] = None  # Script to run on VM before each test
    vm_overlay: Optional[Path] = None  # Path to pre-built qcow2 overlay with this EDR
    install_command: str = ""  # Command to install the EDR agent on the VM via SSH


# ---------------------------------------------------------------------------
# Built-in EDR configs
# ---------------------------------------------------------------------------

BUILTIN_EDRS: dict[str, EDRConfig] = {
    "defender": EDRConfig(
        name="defender",
        detection_method="ssh_command",
        alert_query=r'powershell -NoProfile -Command "Get-WinEvent -LogName Microsoft-Windows-Windows-Defender/Operational -MaxEvents 20 -ErrorAction SilentlyContinue | Where-Object { $_.Id -in 1116,1117,1006,1007 } | Select-Object -ExpandProperty Message"',
    ),
    "wazuh": EDRConfig(
        name="wazuh",
        detection_method="rest_api",
        detection_api="https://{server_ip}:55000",
        api_auth={"user": "wazuh-wui", "password": "MyS3cr3tP4ssw0rd*"},
        alert_query="/security/events?pretty&limit=20&q=rule.level>=5",
        install_command=(
            r'powershell -NoProfile -Command "'
            r"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
            r"$msi = 'C:\Users\vmuser\wazuh-agent.msi'; "
            r"if (-not (Test-Path $msi)) { "
            r"  Invoke-WebRequest -Uri 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi' -OutFile $msi "
            r"}; "
            r'msiexec /i $msi /q WAZUH_MANAGER=\"{server_ip}\" WAZUH_REGISTRATION_SERVER=\"{server_ip}\"; '
            r"Start-Sleep -Seconds 5; "
            r"Start-Service WazuhSvc -ErrorAction SilentlyContinue"
            r'"'
        ),
    ),
    "elastic": EDRConfig(
        name="elastic",
        detection_method="elasticsearch",
        detection_api="https://localhost:9200",
        api_auth={"user": "elastic", "password": "changeme"},
        alert_query="/.alerts-security*/_search?q=host.name:{hostname}",
        install_command=r'elastic-agent.exe install --url={fleet_url} --enrollment-token={token}',
    ),
    "openedr": EDRConfig(
        name="openedr",
        detection_method="log_file",
        detection_api=r"C:\ProgramData\edrsvc\log",
        install_command=(
            r'powershell -NoProfile -Command "'
            r"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
            r"$msi = 'C:\Users\vmuser\openedr-agent.msi'; "
            r"if (-not (Test-Path $msi)) { "
            r"  Invoke-WebRequest -Uri 'https://github.com/ComodoSecurity/openedr/releases/download/release-2.5.1/OpenEDR-Installation-2.5.1-Win64.msi' -OutFile $msi "
            r"}; "
            r"msiexec /i $msi /q; "
            r"Start-Sleep -Seconds 10"
            r'"'
        ),
    ),
    "velociraptor": EDRConfig(
        name="velociraptor",
        detection_method="rest_api",
        detection_api="https://{server_ip}:8889",
        alert_query="api/v1/GetArtifacts?artifact=Windows.Detection.Yara.Process",
        install_command=(
            r'powershell -NoProfile -Command "'
            r"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "
            r"$exe = 'C:\Users\vmuser\velociraptor.exe'; "
            r"if (-not (Test-Path $exe)) { "
            r"  Invoke-WebRequest -Uri 'https://github.com/Velocidex/velociraptor/releases/download/v0.77.1/velociraptor-v0.77.1-windows-amd64.exe' -OutFile $exe "
            r"}; "
            r"& $exe service install --config C:\Users\vmuser\client.config.yaml"
            r'"'
        ),
    ),
}


def get_edr_config(name: str) -> EDRConfig:
    """Look up a built-in EDR config by name, or create a minimal one."""
    return BUILTIN_EDRS.get(name, EDRConfig(name=name))


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
