"""
YAML / JSON / CLI input parser with validation and auto-completion.

Reads a target environment spec from disk (YAML/JSON) or constructs one
from keyword arguments, then fills in sensible defaults.
"""

import json
import platform as _platform
import sys
from pathlib import Path
from typing import Optional, Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from .target_spec import (
    TargetEnvironmentSpec,
    OSPlatform,
    KNOWN_EDRS,
    KNOWN_COMPILER_TOOLS,
)


# ---------------------------------------------------------------------------
# Defaults / auto-completion maps
# ---------------------------------------------------------------------------

# When a user specifies an EDR name we can't recognise, suggest closest known.
_EDR_ALIASES: dict[str, str] = {
    "crowdstrike": "crowdstrike",
    "cs": "crowdstrike",
    "sentinelone": "sentinel_one",
    "s1": "sentinel_one",
    "windows_defender": "defender",
    "defender": "defender",
    "carbonblack": "carbon_black",
    "cb": "carbon_black",
    "trendmicro": "trend_micro",
    "tm": "trend_micro",
    "elastic": "elastic_security",
}


# ---------------------------------------------------------------------------
# Core parser
# ---------------------------------------------------------------------------

def parse_target_spec(
    spec_path: Optional[str] = None,
    **overrides: Any,
) -> TargetEnvironmentSpec:
    """Load or build a ``TargetEnvironmentSpec``.

    Parameters are resolved in this priority order (highest first):
      1. *overrides* keyword args passed here
      2. file at *spec_path* (YAML / JSON)
      3. sensible defaults from the model + completion logic below

    Returns a validated ``TargetEnvironmentSpec`` ready for consumption by
    every downstream phase.
    """
    raw: dict[str, Any] = {}

    # -- load file -----------------------------------------------------------
    if spec_path and Path(spec_path).exists():
        path = Path(spec_path)
        content = path.read_text()
        if path.suffix in (".yaml", ".yml"):
            if yaml is None:
                raise RuntimeError(
                    "PyYAML not installed; ``pip install pyyaml`` required for YAML specs"
                )
            raw.update(yaml.safe_load(content) or {})  # type: ignore[union-attr]
        elif path.suffix == ".json":
            raw.update(json.loads(content))
        else:
            raise ValueError(f"Unsupported spec file extension: {path.suffix}")

    # -- merge overrides -----------------------------------------------------
    for key, value in overrides.items():
        if value is not None:
            raw[key] = value

    # -- auto-complete -------------------------------------------------------
    _auto_complete(raw)

    return TargetEnvironmentSpec(**raw)


# ---------------------------------------------------------------------------
# Auto-completion helpers
# ---------------------------------------------------------------------------

def _auto_complete(data: dict[str, Any]) -> None:
    """Fill in missing fields and normalise values."""

    # -- OS platform deduction -----------------------------------------------
    os_version = data.get("os_version", "").lower() if data.get("os_version") else ""
    if not data.get("os_platform"):
        if any(kw in os_version for kw in ("ubuntu", "debian", "linux")):
            data["os_platform"] = "linux"
        elif any(kw in os_version for kw in ("windows", "win")):
            data["os_platform"] = "windows"
        elif not os_version:
            # No os_version and no os_platform — fall back to host OS detection.
            _host = _platform.system().lower()
            if "linux" in _host:
                data["os_platform"] = "linux"
                data["os_version"] = _platform.platform(terse=True)
            elif "darwin" in _host:
                data["os_platform"] = "macos"
                data["os_version"] = _platform.mac_ver()[0] or ""
            elif "windows" in _host:
                data["os_platform"] = "windows"
                data["os_version"] = f"{_platform.win32_edition()}_{'.'.join(str(p) for p in sys.version_info)}"
            else:
                # Unrecognised platform string — default to linux as the most common target for this framework.
                data["os_platform"] = "linux"
                try:
                    data["os_version"] = _platform.platform(terse=True) or f"host-{_host}"
                except Exception:
                    data["os_version"] = f"host-{_host}"
        else:
            raise ValueError(
                f"Cannot infer OS platform from '{data.get('os_version')}'. "
                "Set 'os_platform' explicitly or use a version string like 'ubuntu-24.04'"
            )

    # -- Fill in missing os_version when platform is explicit ------------------
    if data.get("os_platform") and not data.get("os_version"):
        plat = str(data["os_platform"]).lower()
        if "linux" == plat or any(kw in plat for kw in ("ubuntu", "debian")):
            data["os_version"] = _platform.platform(terse=True)
        elif "windows" == plat:
            data["os_version"] = f"{_platform.win32_edition()}_{'.'.join(str(p) for p in sys.version_info)}"
        elif "macos" == plat or "darwin" == plat:
            data["os_version"] = _platform.mac_ver()[0] or ""

    # -- EDR normalisation ---------------------------------------------------
    edrs = data.get("edrs", [])
    if isinstance(edrs, str):
        edrs = [edrs]
    normalised: list[str] = []
    for e in edrs:
        key = e.lower().replace(" ", "_")
        resolved = _EDR_ALIASES.get(key, key)
        normalised.append(resolved)
    data["edrs"] = normalised

    # -- compiler / tool defaults --------------------------------------------
    if not data.get("installed_compilers"):
        platform = data.get("os_platform", "linux")
        if platform == "windows":
            data["installed_compilers"] = ["gcc", "mingw-w64", "python3"]
        else:
            data["installed_compilers"] = ["gcc", "python3"]

    # -- sandbox detectors default -------------------------------------------
    if not data.get("sandbox_detectors"):
        data["sandbox_detectors"] = []

    # -- malware type default ------------------------------------------------
    if not data.get("malware_type"):
        platform = data.get("os_platform", "linux")
        if platform == "windows":
            data["malware_type"] = "exe"
        else:
            data["malware_type"] = "elf"


# ---------------------------------------------------------------------------
# Serialise back out (for --output in the CLI)
# ---------------------------------------------------------------------------

def spec_to_yaml(spec: TargetEnvironmentSpec) -> str:
    """Return a YAML string of the spec."""
    if yaml is None:
        raise RuntimeError("PyYAML required for serialisation")
    return yaml.safe_dump(spec.model_dump(), sort_keys=False, default_flow_style=False)  # type: ignore[union-attr]
