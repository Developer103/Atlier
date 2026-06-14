"""
Image sourcing: Download OS disk images or ISOs for provisioning.
- Linux: Ubuntu cloud images (pre-built .qcow2)
- Windows: quickget from Quickemu + VirtIO drivers
"""

import hashlib
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Optional

import aiohttp

from .config_models import TargetOS

logger = logging.getLogger(__name__)

# Predefined URLs for cloud images (Ubuntu)
CLOUD_IMAGES = {
    TargetOS.UBUNTU_24_04: "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
    TargetOS.UBUNTU_22_04: "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img",
}

# Quickget CLI pattern (from quickemu project)
# quickget --os <os> --arch amd64
QUICKGET_URL = "https://raw.githubusercontent.com/wimpysworld/quickget/main/quickget"
QUICKGET_CMD = "quickget"

VIRTIO_WIN_ISO = {
    "url": "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso",
    "sha256": None,  # Could verify if needed
}


async def ensure_linux_image(os_type: TargetOS, output_path: Path) -> Path:
    """
    Download or return existing Ubuntu cloud image.
    """
    if output_path.exists():
        logger.info(f"Image already exists: {output_path}")
        return output_path

    output_path.parent.mkdir(parents=True, exist_ok=True)

    url = CLOUD_IMAGES.get(os_type)
    if not url:
        raise ValueError(f"No cloud image URL defined for {os_type.value}")

    logger.info(f"Downloading cloud image: {url} -> {output_path}")
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            resp.raise_for_status()
            with open(output_path, "wb") as f:
                while True:
                    chunk = await resp.content.read(8192)
                    if not chunk:
                        break
                    f.write(chunk)

    logger.info(f"Cloud image downloaded: {output_path}")
    return output_path


async def ensure_windows_iso(os_type: TargetOS, output_path: Path, virtio_path: Path) -> Path:
    """
    Use quickget to download Windows ISO and VirtIO drivers.
    Falls back to manual download if quickget CLI is unavailable.
    """
    if output_path.exists() and virtio_path.exists():
        logger.info(f"Windows ISO and VirtIO already exist")
        return output_path

    output_path.parent.mkdir(parents=True, exist_ok=True)
    virtio_path.parent.mkdir(parents=True, exist_ok=True)

    # Try quickget first
    try:
        cmd = [QUICKGET_CMD, "--help"]
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        has_quickget = result.returncode == 0
    except FileNotFoundError:
        has_quickget = False

    if has_quickget:
        logger.info(f"Using quickget to download Windows {os_type}")
        # quickget --os <os> --dir <dir>
        qdir = output_path.parent
        subprocess.run(
            [QUICKGET_CMD, "--os", os_type.value, "--dir", str(qdir)],
            check=True,
            capture_output=True,
        )
        logger.info(f"Windows ISO downloaded via quickget")
        return output_path
    else:
        logger.warning("quickget not found, downloading Windows ISO manually")
        # Use known Windows 11 eval ISO URL
        # Note: This is the ISO, not a bootable qcow2 — installation via autounattend.xml
        url = "https://software-static.download.prss.microsoft.com/dbazure/88890969-0LVJ-4PQN-87FD-D1BL228A5728/26100.1.240331-1435.release_release_EVAL_en-us.iso"
        if os_type == TargetOS.WINDOWS_10:
            url = "https://software-download.microsoft.com/download/pr/19045.3632.240215-1959.23h2_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso"

        if not output_path.exists():
            logger.info(f"Manual download: {url}")
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    resp.raise_for_status()
                    with open(output_path, "wb") as f:
                        while True:
                            chunk = await resp.content.read(8192)
                            if not chunk:
                                break
                            f.write(chunk)

        # Download VirtIO ISO
        if not virtio_path.exists():
            logger.info(f"Downloading VirtIO ISO -> {virtio_path}")
            async with aiohttp.ClientSession() as session:
                async with session.get(VIRTIO_WIN_ISO["url"]) as resp:
                    resp.raise_for_status()
                    with open(virtio_path, "wb") as f:
                        while True:
                            chunk = await resp.content.read(8192)
                            if not chunk:
                                break
                            f.write(chunk)

        return output_path
