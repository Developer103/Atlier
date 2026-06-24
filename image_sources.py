"""
Image sourcing for VM provisioning.

Linux:
  Ubuntu cloud images are downloaded automatically from Canonical's CDN.
  These are pre-built .img files that boot straight into a running OS.

Windows:
  ISOs must be placed manually in the ISO directory before running the
  pipeline. The framework never downloads Windows ISOs automatically.

  Default ISO directory:  ~/llm_vault/isos/
  Override with env var:  ISO_DIR=/path/to/dir

  Expected filenames (case-insensitive):
    Windows 11  →  windows-11.iso   (or any .iso > 2 GB in the directory)
    Windows 10  →  windows-10.iso   (or any .iso > 2 GB in the directory)

  Where to get a Windows ISO:
    https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise

VirtIO drivers (for Windows VMs) are downloaded automatically from the
Fedora project CDN, same as before.
"""

import logging
import os
import shutil
from pathlib import Path

import aiohttp

from .config_models import TargetOS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default folder where the user places Windows ISOs manually.
_DEFAULT_ISO_DIR = Path.home() / "llm_vault" / "isos"

# Minimum file size to accept as a real Windows installer ISO.
# Genuine Windows ISOs are 4-6 GB; helper files are much smaller.
_MIN_WINDOWS_ISO_BYTES = 2 * 1024 ** 3  # 2 GB

# Ubuntu cloud image URLs — Canonical keeps these paths stable.
CLOUD_IMAGES = {
    TargetOS.UBUNTU_24_04: "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
    TargetOS.UBUNTU_22_04: "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img",
}

VIRTIO_WIN_ISO_URL = (
    "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/virtio-win.iso"
)

# Canonical filename for each Windows version inside the ISO directory.
_WIN_ISO_NAMES = {
    TargetOS.WINDOWS_11: "windows-11.iso",
    TargetOS.WINDOWS_10: "windows-10.iso",
}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def get_iso_dir() -> Path:
    """Return the ISO directory, preferring the ISO_DIR env var if set."""
    env = os.environ.get("ISO_DIR")
    return Path(env) if env else _DEFAULT_ISO_DIR


# ---------------------------------------------------------------------------
# Linux
# ---------------------------------------------------------------------------

async def ensure_linux_image(os_type: TargetOS, output_path: Path) -> Path:
    """Return path to the Ubuntu cloud image, downloading it if needed."""
    if output_path.exists():
        logger.info("Image already exists: %s", output_path)
        return output_path

    output_path.parent.mkdir(parents=True, exist_ok=True)

    url = CLOUD_IMAGES.get(os_type)
    if not url:
        raise ValueError(f"No cloud image URL defined for {os_type.value}")

    logger.info("Downloading cloud image: %s", url)
    await _download(url, output_path)
    logger.info("Cloud image ready: %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# Windows
# ---------------------------------------------------------------------------

async def ensure_windows_iso(os_type: TargetOS, output_path: Path, virtio_path: Path) -> Path:
    """Locate the manually placed Windows ISO and copy it to the provisioning directory.

    Searches the ISO directory (~/llm_vault/isos/ by default, or $ISO_DIR) for:
      1. A file named exactly  windows-11.iso  /  windows-10.iso
      2. Any .iso file in the directory larger than 2 GB (fallback if renamed)

    Raises RuntimeError with clear instructions if no suitable ISO is found.
    """
    # If a previous run left a valid ISO in place, reuse it.
    if output_path.exists() and output_path.stat().st_size >= _MIN_WINDOWS_ISO_BYTES:
        logger.info("Using cached Windows ISO: %s", output_path)
    else:
        # Discard any stale/broken file first.
        if output_path.exists():
            logger.warning(
                "Removing %s — too small (%d bytes) to be a valid Windows ISO",
                output_path, output_path.stat().st_size,
            )
            output_path.unlink()

        src = _locate_windows_iso(os_type)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info("Copying Windows ISO: %s → %s", src, output_path)
        shutil.copy2(src, output_path)
        logger.info("Windows ISO ready: %s (%.1f GB)", output_path, output_path.stat().st_size / 1024**3)

    # VirtIO drivers are always downloaded automatically — they are a small
    # driver pack from Fedora, not a full OS installer.
    if not virtio_path.exists():
        virtio_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info("Downloading VirtIO drivers…")
        await _download(VIRTIO_WIN_ISO_URL, virtio_path)
        logger.info("VirtIO ISO ready: %s", virtio_path)

    return output_path


def _locate_windows_iso(os_type: TargetOS) -> Path:
    """Find the Windows ISO in the ISO directory or raise a clear error."""
    iso_dir = get_iso_dir()
    canonical_name = _WIN_ISO_NAMES.get(os_type, "windows-11.iso")

    # 1. Exact canonical filename.
    candidate = iso_dir / canonical_name
    if candidate.exists() and candidate.stat().st_size >= _MIN_WINDOWS_ISO_BYTES:
        return candidate

    # 2. Any .iso file in the directory that is large enough.
    if iso_dir.exists():
        matches = [
            f for f in iso_dir.glob("*.iso")
            if f.stat().st_size >= _MIN_WINDOWS_ISO_BYTES
        ]
        if matches:
            best = max(matches, key=lambda f: f.stat().st_size)
            logger.info(
                "No file named %r found — using largest ISO in directory: %s (%.1f GB)",
                canonical_name, best.name, best.stat().st_size / 1024**3,
            )
            return best

    # Nothing found — give the user clear instructions.
    raise RuntimeError(
        f"Windows ISO not found for {os_type.value}.\n\n"
        f"Place your ISO in:  {iso_dir}/\n"
        f"Expected filename:  {canonical_name}\n\n"
        "Download a Windows 11 evaluation ISO from:\n"
        "  https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise\n\n"
        "Or set ISO_DIR=/path/to/your/iso/folder before running.\n"
        f"The ISO must be larger than {_MIN_WINDOWS_ISO_BYTES // 1024**3} GB."
    )


# ---------------------------------------------------------------------------
# Download helper (used for Linux cloud images and VirtIO)
# ---------------------------------------------------------------------------

async def _download(url: str, dest: Path) -> None:
    """Stream-download *url* to *dest*, writing in 64 KB chunks."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=3600)) as resp:
            resp.raise_for_status()
            with open(dest, "wb") as f:
                async for chunk in resp.content.iter_chunked(65536):
                    f.write(chunk)
