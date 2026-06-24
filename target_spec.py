"""
Target environment specification — Pydantic model for the full target env schema.

This is the canonical input to every phase after provisioning: generation,
selection, verification all consume a TargetEnvironmentSpec.
"""

import enum
from typing import List, Optional, Dict, Any, Set

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums / constants
# ---------------------------------------------------------------------------

class OSPlatform(str, enum.Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"


class LinuxDistro(str, enum.Enum):
    UBUNTU_24_04 = "ubuntu-24.04"
    UBUNTU_22_04 = "ubuntu-22.04"
    DEBIAN_BOOKWORM = "debian-bookworm"


class WindowsVersion(str, enum.Enum):
    WINDOWS_11 = "windows-11"
    WINDOWS_10 = "windows-10"


# Malware type — freeform description of behaviour/purpose (e.g. "info stealer",
# "ransomware", "spyware", "backdoor"). The LLM reads this and decides the
# payload format, runtime actions, and which DB techniques/exploits to pull in.
MALWARE_TYPE_OPTIONS = [
    "exe",       # Standalone executable (PE/ELF binary)
    "dll",       # Dynamic link library / shared object
    "service",   # Windows service or systemd unit
    "script",    # Script-based (PowerShell, Python, Bash, etc.)
    "driver",    # Kernel-mode driver
    "cpl",       # Control panel applet (Windows)
    "sct",        # XML scriptlet (Windows DDE/COM abuse)
]


KNOWN_EDRS: Set[str] = {
    "crowdstrike",
    "sentinel_one",
    "defender",
    "symantec_endpoint",
    "carbon_black",
    "trend_micro",
    "elastic_security",
    "sysmon",
}

KNOWN_COMPILER_TOOLS: Set[str] = {
    "gcc", "g++", "clang", "clang++", "msvc", "mingw-w64",
    "python3", "nodejs", "rustc", "go", "java", "ruby",
}


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

class TargetEnvironmentSpec(BaseModel):
    """Complete target environment specification.

    Fields map directly to the test-steps doc; validation + auto-completion
    lives in ``spec_parser``.
    """

    # -- platform / OS -------------------------------------------------------
    os_platform: OSPlatform = Field(..., description="linux or windows")
    os_version: str = Field(..., description="e.g. 'ubuntu-24.04', 'windows-11'")

    # -- security stack ------------------------------------------------------
    edrs: List[str] = Field(
        default_factory=list,
        description="EDR names (case-insensitive); e.g. ['sentinel_one', 'crowdstrike']",
    )
    antivirus: Optional[str] = None
    patch_level: Optional[str] = Field(None, description="e.g. 'latest', '2023-Q1'")

    # -- toolchain -----------------------------------------------------------
    installed_compilers: List[str] = Field(
        default_factory=list,
        description="Available compiler / build tools; e.g. ['gcc', 'mingw-w64']",
    )
    common_tools: List[str] = Field(
        default_factory=list,
        description="Commonly installed utilities; e.g. ['python3', 'powershell']",
    )

    # -- network / domain ----------------------------------------------------
    network_config: Optional[Dict[str, Any]] = None
    domain_joined: bool = False
    admin_rights: bool = True  # default to admin for easier malware execution

    # -- sandbox / detection -------------------------------------------------
    sandbox_detectors: List[str] = Field(
        default_factory=list,
        description="Known sandbox/VM detectors in the env; e.g. ['vmware', 'cuckoo', 'virtualbox']",
    )
    custom_gates: List[str] = Field(
        default_factory=list,
        description="Custom detection evasion requirements (free-form); e.g. ['no console window', 'sleep before main']"
    )

    # -- malware type --------------------------------------------------------
    malware_type: str = Field(
        default="info stealer",
        description="Freeform behavioural description of malware (e.g. 'info stealer', 'ransomware', 'spyware'). The LLM reads this and decides payload format, runtime actions, and DB queries.",
    )

    # -- detailed behavior spec ----------------------------------------------
    behavior_spec: Optional[str] = Field(
        default=None,
        description=(
            "Precise behavioral requirements passed verbatim to the LLM. "
            "Use this to specify exact runtime behavior beyond malware_type — "
            "e.g. 'keylogger that sends all keystrokes to 10.0.0.5:9001 over AES-256 "
            "encrypted TCP, persists via HKCU\\\\Run, kills defender.exe on startup'. "
            "The LLM treats this as a binding spec and adjusts every generated function accordingly."
        ),
    )

    # -- extra metadata ------------------------------------------------------
    notes: Optional[str] = None

    @field_validator("edrs", mode="before")
    @classmethod
    def _normalize_edrs(cls, v):
        if isinstance(v, list):
            return [e.lower().replace(" ", "_") for e in v]
        return [v.lower().replace(" ", "_")]

    @field_validator("installed_compilers", "common_tools", mode="before")
    @classmethod
    def _normalize_tool_list(cls, v):
        if isinstance(v, list):
            return [t.lower() for t in v]
        return [v.lower()] if v else []

    @field_validator("sandbox_detectors", mode="before")
    @classmethod
    def _normalize_sandbox(cls, v):
        if isinstance(v, list):
            return [s.lower().replace(" ", "_") for s in v]
        return [v.lower().replace(" ", "_")] if v else []

    @field_validator("malware_type", mode="before")
    @classmethod
    def _normalize_malware_type(cls, v):
        if isinstance(v, str):
            val = v.strip().lower()
            return val
        return "exe"
