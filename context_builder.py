"""
Context builder — merges query results from all 3 DBs with the target spec
into a single, deduplicated, ranked context block ready for prompt injection.

Workflow:
  1. Accept MalwareTechnique / PoC / CTIFinding lists + TargetEnvironmentSpec
  2. Deduplicate by ID / CVE across sources
  3. Rank by relevance score (EDR match boosts malware techniques)
  4. Produce a ``BuildContext`` dataclass that prompt_templates renders into text
"""

import hashlib
from dataclasses import dataclass, field
from typing import List, Optional

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
class ContextBlock:
    """The structured context that gets rendered into a prompt string."""

    target_summary: str  # human-readable summary of the target env
    techniques: List[RankedTechnique]  # ranked malware evasion techniques
    pocs: List[RankedPoC]  # ranked PoCs / exploits
    cti_findings: List[CTIFinding]  # recent CTI intelligence
    compiler_instructions: str = ""  # compiler-specific build guidance (filled later)

    @property
    def context_hash(self) -> str:
        """Stable hash of the context content for change detection."""
        raw = ";".join(
            f"T:{t.technique.id}({t.rank_score:.2f})"
            for t in self.techniques
        ) + "|"
        raw += ";".join(f"P:{p.poc.cve}({p.rank_score:.2f})" for p in self.pocs) + "|"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


class ContextBuilder:
    """Takes DB query results + target spec → constructs prompt-ready context."""

    # Scoring weights — tune these if needed
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
    ) -> ContextBlock:
        """Build the full context block from raw query results.

        Parameters set upper limits on items included to keep prompt size bounded.
        """
        ranked_techs = self._rank_techniques(
            query_result.malware_techniques, target_spec.edrs
        )[:max_techniques]

        ranked_pocs = self._rank_pocs(query_result.poc_results)[:max_pocs]

        cti_findings = list(query_result.cti_findings)[:max_cti]

        return ContextBlock(
            target_summary=self._summarise_target(target_spec),
            techniques=ranked_techs,
            pocs=ranked_pocs,
            cti_findings=cti_findings,
        )

    # ------------------------------------------------------------------
    # ranking helpers
    # ------------------------------------------------------------------

    def _rank_techniques(
        self,
        techniques: List[MalwareTechnique],
        target_edrs: List[str],
    ) -> List[RankedTechnique]:
        """Score and rank malware techniques against the target EDR list."""
        scored: List[tuple[float, MalwareTechnique]] = []

        for t in techniques:
            score = 0.0
            reasons: List[str] = []

            # Base score from detection rating (lower = easier to evade)
            if t.detection_rating is not None:
                score += max(0, (5 - t.detection_rating)) * 2  # max +10 for unrated

            # Boost for EDR match — techniques tested against target EDRs rank higher
            for edr in target_edrs:
                if edr.lower() in t.name.lower() or edr.lower() in (t.edr_detection or "").lower():
                    score += self._EDR_MATCH_BOOST
                    reasons.append(f"tested_against_{edr}")

            # Category bonus — certain categories are more relevant for undetectable malware
            if t.category in ("evasion", "persistence", "lateral_movement"):
                score += 2.0
                reasons.append("high_value_category")

            scored.append((score, t, reasons))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [RankedTechnique(technique=t, rank_score=s, match_reasons=rs) for s, t, rs in scored]

    def _rank_pocs(self, pocs: List[PoC]) -> List[RankedPoC]:
        """Score PoCs by severity and exploit type."""
        scored: List[tuple[float, PoC]] = []

        for p in pocs:
            score = self._SEVERITY_SCORES.get(p.severity.lower(), 0)

            # Privilege escalation and RCE are highest-value exploit types
            if p.exploit_type.upper() in ("RCE", "PRIVESC"):
                score += 5.0

            scored.append((score, p))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [RankedPoC(poc=p, rank_score=s) for s, p in scored]

    # ------------------------------------------------------------------
    # summarisation
    # ------------------------------------------------------------------

    @staticmethod
    def _summarise_target(spec: TargetEnvironmentSpec) -> str:
        """Human-readable one-paragraph summary of the target environment."""
        parts = [
            f"Platform: {spec.os_platform.value} ({spec.os_version})",
            f"EDRs: {', '.join(spec.edrs) if spec.edrs else 'none detected'}",
            f"AV: {spec.antivirus or 'unknown/none'}",
            f"Patch level: {spec.patch_level or 'unknown'}",
            f"Compilers: {', '.join(spec.installed_compilers) if spec.installed_compilers else 'unknown'}",
            f"Sandbox detectors: {', '.join(spec.sandbox_detectors) if spec.sandbox_detectors else 'none configured'}",
        ]
        return "; ".join(parts)
