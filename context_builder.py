"""
Context builder — merges query results from all 3 DBs with the target spec
into a single, deduplicated, ranked context block ready for prompt injection.

Workflow:
  1. Accept QueryResult + TargetEnvironmentSpec
  2. Rank by relevance score (EDR match boosts malware techniques)
  3. Separate CVE PoCs with usable source code for direct exploit integration
  4. Produce a ``ContextBlock`` that prompt_templates renders into text
"""

import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

from .db_models import MalwareTechnique, PoC, CTIFinding, QueryResult
from .target_spec import TargetEnvironmentSpec


@dataclass
class RankedTechnique:
    """A malware technique ranked for inclusion in the prompt context."""
    technique: MalwareTechnique
    rank_score: float
    match_reasons: List[str] = field(default_factory=list)


@dataclass
class RankedPoC:
    """A PoC ranked for inclusion in the prompt context."""
    poc: PoC
    rank_score: float
    relevance_notes: str = ""


@dataclass
class ExploitablePoC:
    """A PoC with full source code available for direct integration."""
    poc: PoC
    rank_score: float
    integration_notes: str = ""


@dataclass
class ContextBlock:
    """The structured context that gets rendered into a prompt string."""

    target_summary: str
    techniques: List[RankedTechnique]
    pocs: List[RankedPoC]
    cti_findings: List[CTIFinding]
    exploitable_pocs: List[ExploitablePoC] = field(default_factory=list)
    compiler_instructions: str = ""

    @property
    def context_hash(self) -> str:
        raw = ";".join(
            f"T:{t.technique.id}({t.rank_score:.2f})"
            for t in self.techniques
        ) + "|"
        raw += ";".join(f"P:{p.poc.cve}({p.rank_score:.2f})" for p in self.pocs) + "|"
        raw += ";".join(f"E:{e.poc.cve}" for e in self.exploitable_pocs) + "|"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def has_exploitable_cves(self) -> bool:
        return len(self.exploitable_pocs) > 0


class ContextBuilder:
    """Takes DB query results + target spec → constructs prompt-ready context."""

    _EDR_MATCH_BOOST = 3.0
    _SEVERITY_SCORES = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 2,
    }

    def build_context(
        self,
        query_result: QueryResult,
        target_spec: TargetEnvironmentSpec,
        max_techniques: int = 15,
        max_pocs: int = 10,
        max_cti: int = 5,
        max_exploitable: int = 5,
    ) -> ContextBlock:
        """Build the full context block from unified query results."""
        ranked_techs = self._rank_techniques(
            query_result.malware_techniques, target_spec.edrs
        )[:max_techniques]

        ranked_pocs = self._rank_pocs(query_result.all_pocs)[:max_pocs]

        cti_findings = list(query_result.cti_findings)[:max_cti]

        exploitable = self._rank_exploitable(
            query_result.exploitable_cves, target_spec
        )[:max_exploitable]

        return ContextBlock(
            target_summary=self._summarise_target(target_spec),
            techniques=ranked_techs,
            pocs=ranked_pocs,
            cti_findings=cti_findings,
            exploitable_pocs=exploitable,
        )

    # ------------------------------------------------------------------
    # ranking helpers
    # ------------------------------------------------------------------

    def _rank_techniques(
        self,
        techniques: List[MalwareTechnique],
        target_edrs: List[str],
    ) -> List[RankedTechnique]:
        scored = []
        for t in techniques:
            score = 0.0
            reasons: List[str] = []

            if t.detection_rating is not None:
                score += max(0, (5 - t.detection_rating)) * 2

            for edr in target_edrs:
                if edr.lower() in t.name.lower() or edr.lower() in (t.edr_detection or "").lower():
                    score += self._EDR_MATCH_BOOST
                    reasons.append(f"tested_against_{edr}")

            if t.category in ("evasion", "persistence", "lateral_movement", "injection"):
                score += 2.0
                reasons.append("high_value_category")

            if t.similarity > 0.7:
                score += t.similarity * 3

            scored.append((score, t, reasons))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [RankedTechnique(technique=t, rank_score=s, match_reasons=rs) for s, t, rs in scored]

    def _rank_pocs(self, pocs: List[PoC]) -> List[RankedPoC]:
        scored = []
        for p in pocs:
            score = self._SEVERITY_SCORES.get(p.severity.lower(), 0)

            if p.exploit_type.upper() in ("RCE", "PRIVESC"):
                score += 5.0

            if p.has_usable_code:
                score += 3.0

            if p.stars > 10:
                score += min(p.stars / 50.0, 3.0)

            if p.cve_year and p.cve_year >= 2024:
                score += 1.5

            scored.append((score, p))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [RankedPoC(poc=p, rank_score=s) for s, p in scored]

    def _rank_exploitable(
        self,
        pocs: List[PoC],
        target_spec: TargetEnvironmentSpec,
    ) -> List[ExploitablePoC]:
        """Rank PoCs that have full source code for direct integration.

        Only includes PoCs where we can verify applicability to the target:
        - CVE year must be present (so we know the era of the vuln)
        - OS platform must match (windows CVEs for windows targets)
        - If target has a recent patch level, exclude old CVEs that are certainly patched
        """
        os_platform = target_spec.os_platform.value if hasattr(target_spec.os_platform, "value") else str(target_spec.os_platform)
        patch_level = (target_spec.patch_level or "").lower()
        os_version = target_spec.os_version.lower()

        total = len(pocs)
        scored = []
        filtered_out = 0
        for p in pocs:
            if not self._is_applicable(p, os_platform, os_version, patch_level):
                logger.debug("PoC filtered out (not applicable): %s — %s", p.cve, p.title or "untitled")
                filtered_out += 1
                continue

            score = self._SEVERITY_SCORES.get(p.severity.lower(), 0)

            lang_lower = p.language.lower()
            if lang_lower in ("c", "c++", "cpp"):
                score += 4.0
            elif lang_lower in ("python", "powershell"):
                score += 2.0

            if "privilege" in (p.description or "").lower() or "escalat" in (p.description or "").lower():
                score += 3.0

            if p.cve_year and p.cve_year >= 2024:
                score += 2.0

            if p.stars > 5:
                score += min(p.stars / 20.0, 3.0)

            notes = self._generate_integration_notes(p, target_spec)
            scored.append((score, p, notes))

        scored.sort(key=lambda x: x[0], reverse=True)
        logger.info("PoC applicability filter: %d/%d passed (%d filtered out)",
                     len(scored), total, filtered_out)
        return [ExploitablePoC(poc=p, rank_score=s, integration_notes=n) for s, p, n in scored]

    @staticmethod
    def _is_applicable(poc: PoC, os_platform: str, os_version: str, patch_level: str) -> bool:
        """Check whether a PoC has a reasonable chance of working on the target."""
        # Must have a CVE year — otherwise we can't assess applicability
        if not poc.cve_year:
            return False

        desc = (poc.description or "").lower()
        title = (poc.title or "").lower()
        combined = f"{desc} {title} {poc.cve}"

        # OS platform must match — skip linux CVEs for windows targets and vice versa
        if os_platform == "windows":
            if any(kw in combined for kw in ("linux", "ubuntu", "debian", "centos", "kernel")):
                if not any(kw in combined for kw in ("windows", "win32", "win64", "microsoft")):
                    return False
        elif os_platform == "linux":
            if any(kw in combined for kw in ("windows", "win32", "win64", "microsoft", "iis", "exchange")):
                if not any(kw in combined for kw in ("linux", "unix", "posix")):
                    return False

        # If target is "latest" patched, exclude CVEs older than 2 years — almost certainly patched
        if "latest" in patch_level or "2025" in patch_level or "2026" in patch_level:
            if poc.cve_year < 2023:
                return False

        # Windows version specificity: if CVE description mentions a specific version,
        # check it matches the target
        if os_platform == "windows":
            if "windows 10" in combined and "11" in os_version and "windows 11" not in combined:
                return False
            if "windows 7" in combined and ("10" in os_version or "11" in os_version):
                if "windows 10" not in combined and "windows 11" not in combined:
                    return False

        return True

    @staticmethod
    def _generate_integration_notes(poc: PoC, spec: TargetEnvironmentSpec) -> str:
        notes = []
        os_platform = spec.os_platform.value if hasattr(spec.os_platform, "value") else str(spec.os_platform)

        if poc.language.lower() in ("c", "c++") and spec.installed_compilers:
            notes.append(f"Compile with {spec.installed_compilers[0]}")

        if "priv" in (poc.description or "").lower():
            if spec.admin_rights:
                notes.append("Target has admin — use for lateral movement or persistence instead")
            else:
                notes.append("Target is unprivileged — use this to escalate before main payload")

        if poc.cve_year and spec.patch_level:
            if "latest" in spec.patch_level.lower() or "2025" in spec.patch_level:
                notes.append(f"CVE-{poc.cve_year} — verify not patched at current level")
            else:
                notes.append(f"CVE-{poc.cve_year} — likely unpatched")

        return "; ".join(notes) if notes else "Direct integration — review target compatibility"

    # ------------------------------------------------------------------
    # summarisation
    # ------------------------------------------------------------------

    @staticmethod
    def _summarise_target(spec: TargetEnvironmentSpec) -> str:
        parts = [
            f"Platform: {spec.os_platform.value} ({spec.os_version})",
            f"EDRs: {', '.join(spec.edrs) if spec.edrs else 'none detected'}",
            f"AV: {spec.antivirus or 'unknown/none'}",
            f"Patch level: {spec.patch_level or 'unknown'}",
            f"Compilers: {', '.join(spec.installed_compilers) if spec.installed_compilers else 'unknown'}",
            f"Sandbox detectors: {', '.join(spec.sandbox_detectors) if spec.sandbox_detectors else 'none configured'}",
        ]
        return "; ".join(parts)
