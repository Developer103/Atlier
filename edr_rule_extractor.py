"""EDR rule extraction — query EDR engines for detection verdicts and signatures.

Runs MpCmdRun.exe -Scan on the VM for immediate Defender verdicts (faster than
waiting for real-time alerts). Extensible to other EDR products.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    detected: bool = False
    threat_name: str = ""
    threat_type: str = ""
    severity: str = ""
    raw_output: str = ""
    scan_time_sec: float = 0.0

    @property
    def summary(self) -> str:
        if not self.detected:
            return "clean"
        return f"{self.threat_name} ({self.threat_type}, {self.severity})"


@dataclass
class DefenderSignature:
    name: str = ""
    sig_type: str = ""
    category: str = ""
    raw: str = ""


class DefenderRuleExtractor:
    """Extract detection details from Windows Defender on a VM."""

    def __init__(self, vm_instance):
        self._vm = vm_instance

    async def scan_binary(self, binary_path: str, timeout: int = 60) -> ScanResult:
        """Run MpCmdRun.exe -Scan on a specific file for an immediate verdict.

        This is faster and more informative than waiting for real-time protection
        alerts — it gives the exact threat name immediately.
        """
        result = ScanResult()
        cmd = (
            f'powershell -NoProfile -Command "'
            f"& 'C:\\Program Files\\Windows Defender\\MpCmdRun.exe' "
            f"-Scan -ScanType 3 -File '{binary_path}' -DisableRemediation"
            f'"'
        )

        try:
            import time
            start = time.monotonic()
            output = await self._vm.execute_command(cmd, timeout=timeout)
            result.scan_time_sec = time.monotonic() - start
            result.raw_output = output.strip()

            if not output.strip():
                return result

            _lower = output.lower()
            if "found no threats" in _lower or "no threats" in _lower:
                return result

            if "threat" in _lower or "found" in _lower:
                result.detected = True
                nm = re.search(r"Threat\s*:\s*(.+?)(?:\r?\n|$)", output)
                if nm:
                    result.threat_name = nm.group(1).strip()
                else:
                    nm2 = re.search(r"(?:detected|found)\s+(.+?)(?:\r?\n|$)", output, re.IGNORECASE)
                    if nm2:
                        result.threat_name = nm2.group(1).strip()

                tt = re.search(r"(?:Type|Category)\s*:\s*(.+?)(?:\r?\n|$)", output)
                if tt:
                    result.threat_type = tt.group(1).strip()

                sv = re.search(r"Severity\s*:\s*(.+?)(?:\r?\n|$)", output)
                if sv:
                    result.severity = sv.group(1).strip().lower()
                else:
                    result.severity = "high"

        except asyncio.TimeoutError:
            logger.warning("Defender scan timed out after %ds for %s", timeout, binary_path)
            result.raw_output = f"timeout after {timeout}s"
        except Exception as e:
            logger.warning("Defender scan failed for %s: %s", binary_path, e)
            result.raw_output = str(e)

        return result

    async def get_threat_history(self, max_entries: int = 20) -> list[ScanResult]:
        """Query Defender's threat history for recent detections."""
        cmd = (
            'powershell -NoProfile -Command "'
            'Get-MpThreatDetection | Select-Object -First '
            f'{max_entries} | ForEach-Object {{ '
            '$t = Get-MpThreat -ThreatID $_.ThreatID -ErrorAction SilentlyContinue; '
            'if ($t) {{ '
            "Write-Output ('THREAT_ENTRY|' + $t.ThreatName + '|' + $t.CategoryID + '|' + $t.SeverityID + '|' + $_.InitialDetectionTime) "
            '}} }}"'
        )

        results = []
        try:
            output = await self._vm.execute_command(cmd, timeout=30)
            for line in output.strip().splitlines():
                line = line.strip()
                if not line.startswith("THREAT_ENTRY|"):
                    continue
                parts = line.split("|", 4)
                if len(parts) >= 4:
                    results.append(ScanResult(
                        detected=True,
                        threat_name=parts[1],
                        threat_type=parts[2],
                        severity=_severity_id_to_str(parts[3]),
                        raw_output=line,
                    ))
        except Exception as e:
            logger.warning("Failed to query threat history: %s", e)

        return results

    async def extract_dynamic_signatures(self) -> list[DefenderSignature]:
        """Query MpCmdRun.exe -ListAllDynamicSignatures."""
        cmd = (
            'powershell -NoProfile -Command "'
            "& 'C:\\Program Files\\Windows Defender\\MpCmdRun.exe' "
            "-ListAllDynamicSignatures"
            '"'
        )

        sigs = []
        try:
            output = await self._vm.execute_command(cmd, timeout=30)
            current_sig: dict = {}
            for line in output.strip().splitlines():
                line = line.strip()
                if not line:
                    if current_sig.get("name"):
                        sigs.append(DefenderSignature(**current_sig))
                    current_sig = {"name": "", "sig_type": "", "category": "", "raw": ""}
                    continue
                if current_sig.get("raw"):
                    current_sig["raw"] += "\n"
                current_sig["raw"] = current_sig.get("raw", "") + line
                nm = re.match(r"SignatureName\s*:\s*(.+)", line)
                if nm:
                    current_sig["name"] = nm.group(1).strip()
                st = re.match(r"SignatureType\s*:\s*(.+)", line)
                if st:
                    current_sig["sig_type"] = st.group(1).strip()
                ct = re.match(r"Category\s*:\s*(.+)", line)
                if ct:
                    current_sig["category"] = ct.group(1).strip()
            if current_sig.get("name"):
                sigs.append(DefenderSignature(**current_sig))
        except Exception as e:
            logger.warning("Failed to extract dynamic signatures: %s", e)

        return sigs

    async def quick_scan_verdict(self, binary_path: str) -> Optional[str]:
        """Fast convenience method: returns threat name or None if clean."""
        result = await self.scan_binary(binary_path, timeout=45)
        return result.threat_name if result.detected else None


def _severity_id_to_str(sid: str) -> str:
    _MAP = {"1": "low", "2": "medium", "4": "high", "5": "severe"}
    return _MAP.get(sid.strip(), sid.strip().lower())
