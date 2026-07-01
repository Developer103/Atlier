"""Pre-deployment static analysis of compiled PE binaries.

Runs BEFORE VM deployment to catch obvious detection triggers early.
Cheaper than a full VM cycle: milliseconds instead of minutes.
"""

import asyncio
import math
import re
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import logging

logger = logging.getLogger(__name__)


SUSPICIOUS_IMPORTS = {
    "VirtualAllocEx", "VirtualAlloc", "VirtualProtect", "VirtualProtectEx",
    "CreateRemoteThread", "CreateThread", "NtCreateThreadEx",
    "WriteProcessMemory", "ReadProcessMemory",
    "OpenProcess", "CreateProcessA", "CreateProcessW",
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
    "NtProtectVirtualMemory", "NtCreateSection", "NtMapViewOfSection",
    "SetWindowsHookExA", "SetWindowsHookExW",
    "AdjustTokenPrivileges", "LookupPrivilegeValueA",
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA",
    "InternetOpenA", "InternetOpenUrlA", "HttpSendRequestA",
    "URLDownloadToFileA", "WinExec", "ShellExecuteA",
    "RegSetValueExA", "RegCreateKeyExA",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
}

SUSPICIOUS_STRINGS = [
    re.compile(r"(?:ransom|decrypt|bitcoin|btc|monero|xmr|\.onion)", re.IGNORECASE),
    re.compile(r"(?:cmd\.exe|powershell|wscript|cscript)", re.IGNORECASE),
    re.compile(r"(?:HKEY_LOCAL_MACHINE|HKLM|CurrentVersion\\Run)", re.IGNORECASE),
    re.compile(r"(?:password|credential|cookie|token)", re.IGNORECASE),
    re.compile(r"(?:mimikatz|lazagne|keylog)", re.IGNORECASE),
    re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\b"),
]


@dataclass
class BinaryAnalysisResult:
    suspicious_imports: list[str] = field(default_factory=list)
    suspicious_strings: list[str] = field(default_factory=list)
    high_entropy_sections: list[dict] = field(default_factory=list)
    yara_matches: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    should_skip_vm: bool = False
    report: str = ""


async def analyze_binary(binary_path: str | Path) -> BinaryAnalysisResult:
    """Analyze a compiled binary for obvious detection triggers."""
    path = Path(binary_path)
    if not path.exists():
        logger.warning("Binary not found: %s", path)
        return BinaryAnalysisResult(report="Binary not found")

    result = BinaryAnalysisResult()
    tasks = []

    tasks.append(_analyze_imports(path, result))
    tasks.append(_analyze_strings(path, result))
    tasks.append(_analyze_entropy(path, result))
    tasks.append(_analyze_yara(path, result))

    await asyncio.gather(*tasks, return_exceptions=True)

    _compute_risk_score(result)
    result.report = _build_report(result, path)
    logger.info("Binary analysis: risk_score=%.1f, imports=%d, strings=%d, entropy_sections=%d, yara=%d",
                result.risk_score, len(result.suspicious_imports),
                len(result.suspicious_strings), len(result.high_entropy_sections),
                len(result.yara_matches))
    return result


async def _analyze_imports(path: Path, result: BinaryAnalysisResult) -> None:
    objdump = shutil.which("objdump") or shutil.which("x86_64-w64-mingw32-objdump")
    if not objdump:
        return
    try:
        proc = await asyncio.create_subprocess_exec(
            objdump, "-p", str(path),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode("utf-8", errors="replace")
        for line in output.splitlines():
            name_match = re.search(r"^\s+\d+\s+(\w+)$", line.strip())
            if name_match:
                func_name = name_match.group(1)
                if func_name in SUSPICIOUS_IMPORTS:
                    result.suspicious_imports.append(func_name)
    except Exception as e:
        logger.debug("Import analysis failed: %s", e)


async def _analyze_strings(path: Path, result: BinaryAnalysisResult) -> None:
    strings_cmd = shutil.which("strings")
    if not strings_cmd:
        return
    try:
        proc = await asyncio.create_subprocess_exec(
            strings_cmd, "-n", "6", str(path),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode("utf-8", errors="replace")
        seen = set()
        for line in output.splitlines():
            for pattern in SUSPICIOUS_STRINGS:
                if pattern.search(line) and line not in seen:
                    result.suspicious_strings.append(line.strip()[:200])
                    seen.add(line)
    except Exception as e:
        logger.debug("String analysis failed: %s", e)


async def _analyze_entropy(path: Path, result: BinaryAnalysisResult) -> None:
    """Check for high-entropy sections (packed/encrypted content)."""
    try:
        data = path.read_bytes()
        chunk_size = 4096
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            if len(chunk) < 256:
                continue
            entropy = _shannon_entropy(chunk)
            if entropy > 7.2:
                result.high_entropy_sections.append({
                    "offset": i,
                    "size": len(chunk),
                    "entropy": round(entropy, 2),
                })
    except Exception as e:
        logger.debug("Entropy analysis failed: %s", e)

    if len(result.high_entropy_sections) > 20:
        result.high_entropy_sections = result.high_entropy_sections[:20]


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


async def _analyze_yara(path: Path, result: BinaryAnalysisResult) -> None:
    """Run YARA rules against binary if yara-python is installed."""
    try:
        import yara
    except ImportError:
        return

    rules_dir = Path(__file__).parent / "yara_rules"
    if not rules_dir.exists():
        return

    try:
        rule_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
        if not rule_files:
            return
        filepaths = {f"rule_{i}": str(r) for i, r in enumerate(rule_files)}
        rules = yara.compile(filepaths=filepaths)
        matches = rules.match(str(path), timeout=30)
        for match in matches:
            result.yara_matches.append(f"{match.rule}: {match.meta.get('description', '')}")
    except Exception as e:
        logger.debug("YARA analysis failed: %s", e)


def _compute_risk_score(result: BinaryAnalysisResult) -> None:
    score = 0.0
    score += len(result.suspicious_imports) * 5
    score += len(result.suspicious_strings) * 3
    score += len(result.high_entropy_sections) * 2
    score += len(result.yara_matches) * 15
    result.risk_score = min(score, 100.0)
    result.should_skip_vm = score >= 80


def _build_report(result: BinaryAnalysisResult, path: Path) -> str:
    lines = [f"Binary Analysis: {path.name}", f"Risk Score: {result.risk_score:.0f}/100", ""]

    if result.suspicious_imports:
        lines.append(f"Suspicious Imports ({len(result.suspicious_imports)}):")
        for imp in sorted(set(result.suspicious_imports)):
            lines.append(f"  - {imp}")
        lines.append("")

    if result.suspicious_strings:
        lines.append(f"Suspicious Strings ({len(result.suspicious_strings)}):")
        for s in result.suspicious_strings[:10]:
            lines.append(f"  - {s}")
        lines.append("")

    if result.high_entropy_sections:
        lines.append(f"High Entropy Sections ({len(result.high_entropy_sections)}):")
        for sec in result.high_entropy_sections[:5]:
            lines.append(f"  - offset=0x{sec['offset']:x} size={sec['size']} entropy={sec['entropy']}")
        lines.append("")

    if result.yara_matches:
        lines.append(f"YARA Matches ({len(result.yara_matches)}):")
        for m in result.yara_matches:
            lines.append(f"  - {m}")
        lines.append("")

    if result.should_skip_vm:
        lines.append("RECOMMENDATION: Skip VM deployment — binary has too many detection indicators.")
    elif result.risk_score > 40:
        lines.append("WARNING: Moderate risk score — binary may trigger EDR detection.")
    else:
        lines.append("Binary appears clean for initial deployment.")

    return "\n".join(lines)
