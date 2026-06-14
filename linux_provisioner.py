"""
Linux VM Provisioner using Cloud-init (NoCloud).
- Generates user-data YAML and packages it into a bootable ISO
- Configures SSH key + user creation on first boot
"""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import yaml

from .config_models import TargetOS

logger = logging.getLogger(__name__)


# Default cloud-init user-data schema
DEFAULT_CLOUD_INIT_YAML = {
    "ssh_authorized_keys": [],
    "chpasswd": {
        "expire": False,
    },
    "users": [
        {
            "name": "vmuser",
            "plain_text_passwd": "vmuser123",
            "shell": "/bin/bash",
            "groups": "adm,dialout,cdrom,floppy,sudo,audio,dip,video,plugdev,netdev,lxd",
            "sudo": "ALL=(ALL) NOPASSWD:ALL",
        }
    ],
    "disable_root": False,
    "ssh_pwauth": True,
    "package_update": True,
    "package_upgrade": "none",
    "runcmd": [
        ["systemctl", "enable", "ssh"],
        ["systemctl", "start", "ssh"],
        # Disable screen blanking
        ["xset", "s", "off", "-dpms"],
    ],
}


def generate_cloud_init_yaml(
    username: str = "vmuser",
    password: str = "vmuser123",
    ssh_key: Optional[str] = None,
) -> dict:
    """Generate cloud-init user-data as a Python dict."""
    data = dict(json.loads(json.dumps(DEFAULT_CLOUD_INIT_YAML)))
    data["users"] = [
        {
            "name": username,
            "plain_text_passwd": password,
            "shell": "/bin/bash",
            "groups": "adm,dialout,cdrom,floppy,sudo,audio,dip,video,plugdev,netdev,lxd",
            "sudo": "ALL=(ALL) NOPASSWD:ALL",
        }
    ]
    if ssh_key:
        data["ssh_authorized_keys"] = [ssh_key]
    return data


def create_cloud_init_iso(user_data: dict, output_path: Path) -> Path:
    """
    Package cloud-init user-data and meta-data into a NoCloud ISO (iso9660)
    using genisoimage.
    
    Structure expected by cloud-init:
    /user-data
    /meta-data
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        meta_data = {
            "instance-id": f"ci-{hash(str(user_data)) % 10000}",
            "local-hostname": "malware-vm",
        }

        # Write metadata files
        user_data_path = tmpdir / "user-data"
        meta_data_path = tmpdir / "meta-data"
        
        with open(user_data_path, "w") as f:
            yaml.dump(user_data, f, default_flow_style=False)
        with open(meta_data_path, "w") as f:
            yaml.dump(meta_data, f, default_flow_style=False)

        # Use genisoimage to create the ISO
        result = subprocess.run(
            [
                "genisoimage", "-volid", "cidata", "-joliet", "-rock",
                "-o", str(output_path), str(tmpdir)
            ],
            capture_output=True, timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"genisoimage failed: {result.stderr.decode().strip()}"
            )

    logger.info(f"Cloud-init ISO created: {output_path}")
    return output_path


def generate_meta_data(instance_id: str = "ci-vm", local_hostname: str = "malware-vm") -> dict:
    """Generate cloud-init meta-data as a Python dict."""
    return {
        "instance-id": instance_id,
        "local-hostname": local_hostname,
    }


# ---------------------------------------------------------------------------
# Wrapper class for class-based usage patterns
# ---------------------------------------------------------------------------

class CloudInitProvisioner:
    """Class-based wrapper around cloud-init provisioning functions."""

    def __init__(self, username="vmuser", password="vmuser123"):
        self.username = username
        self.password = password

    def create_nocloud_iso(self, target_dir: str) -> str:
        """Create a cloud-init NoCloud ISO in the given directory."""
        user_data = generate_cloud_init_yaml(self.username, self.password)
        output_path = Path(target_dir) / "cloud-init.iso"
        create_cloud_init_iso(user_data, output_path)
        return str(output_path)
