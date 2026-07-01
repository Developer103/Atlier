"""
Evasion selector — queries the malware_corpus for EDR-specific evasion techniques.

Given a list of target EDRs, returns ranked evasion strategies with concrete
API call sequences and parameter tweaks that have historically evaded those
specific products.
"""

from typing import List, Optional

from .db_query_engine import DBQueryEngine
from .db_models import MalwareTechnique
from .target_spec import TargetEnvironmentSpec


# EDRs known to be weak on process tree / injection detection.
# Process injection gets a rank boost against these.
_WEAK_PROCESS_TREE_EDRS = frozenset({
    "windows_defender",
    "defender",
    "avg",
    "avast",
    "mcafee",
    "norton",
    "eset",
    "kaspersky",  # older versions; recent ones improved
})

# Synthetic technique injected when process injection is selected.
_PROCESS_INJECTION_TECHNIQUE = MalwareTechnique(
    id="synth_process_injection",
    name="process_injection",
    description=(
        "Classic process injection: enumerate processes via CreateToolhelp32Snapshot, "
        "find explorer.exe, OpenProcess + VirtualAllocEx + WriteProcessMemory + "
        "CreateRemoteThread to inject a shellcode stub into the target process."
    ),
    category="evasion",
    os_type="windows",
    detection_rating=6.0,
)


class EvasionSelector:
    """Selects the best evasion techniques for a given target EDR stack."""

    def __init__(self, db_engine: Optional[DBQueryEngine] = None):
        self._db = db_engine or DBQueryEngine()

    def select_evasions(
        self,
        target_spec: TargetEnvironmentSpec,
        max_techniques: int = 10,
    ) -> List[MalwareTechnique]:
        """Return ranked evasion techniques for the target EDRs.

        Queries each EDR individually and merges results, deduplicating by ID.
        """
        if not target_spec.edrs:
            return []

        seen_ids: set[str] = set()
        all_techniques: List[MalwareTechnique] = []

        for edr in target_spec.edrs:
            techniques = self._db.query_malware_by_edr([edr], n_results=max_techniques)
            for t in techniques:
                if t.id not in seen_ids:
                    seen_ids.add(t.id)
                    all_techniques.append(t)

        # Conditionally include process injection
        if self._should_include_process_injection(target_spec):
            pi = MalwareTechnique(
                id=_PROCESS_INJECTION_TECHNIQUE.id,
                name=_PROCESS_INJECTION_TECHNIQUE.name,
                description=_PROCESS_INJECTION_TECHNIQUE.description,
                category=_PROCESS_INJECTION_TECHNIQUE.category,
                os_type=_PROCESS_INJECTION_TECHNIQUE.os_type,
                detection_rating=self._process_injection_rank(target_spec),
            )
            if pi.id not in seen_ids:
                seen_ids.add(pi.id)
                all_techniques.append(pi)

        # Sort by detection_rating ascending (lower = easier to evade)
        all_techniques.sort(key=lambda x: (x.detection_rating or 99))
        return all_techniques[:max_techniques]

    def select_evasions_for_category(
        self,
        target_spec: TargetEnvironmentSpec,
        category: str,
        max_results: int = 5,
    ) -> List[MalwareTechnique]:
        """Return evasion techniques filtered to a specific category."""
        all_evasions = self.select_evasions(target_spec)
        return [t for t in all_evasions if t.category == category][:max_results]

    # -- Process injection helpers -------------------------------------------

    @staticmethod
    def _should_include_process_injection(target_spec: TargetEnvironmentSpec) -> bool:
        """Determine if process injection should be included.

        Disabled by default.  Enabled when:
        1. Explicitly requested via custom_gates (contains 'process_injection')
        2. Explicitly requested via behavior_spec
        3. Any target EDR is in the weak-process-tree set
        """
        # Explicit request via custom_gates
        gates_lower = [g.lower().replace(" ", "_") for g in (target_spec.custom_gates or [])]
        if "process_injection" in gates_lower:
            return True

        # Explicit request via behavior_spec
        bspec = (target_spec.behavior_spec or "").lower()
        if "process_injection" in bspec or "process injection" in bspec:
            return True

        # EDR-based: include if any target EDR is weak on process tree analysis
        edrs_lower = {e.lower().replace(" ", "_") for e in (target_spec.edrs or [])}
        if edrs_lower & _WEAK_PROCESS_TREE_EDRS:
            return True

        return False

    @staticmethod
    def _process_injection_rank(target_spec: TargetEnvironmentSpec) -> float:
        """Compute detection_rating for process injection (lower = better).

        Base rank 6.  Drops to 3 against EDRs weak on process tree analysis.
        """
        base_rank = 6.0
        edrs_lower = {e.lower().replace(" ", "_") for e in (target_spec.edrs or [])}
        if edrs_lower & _WEAK_PROCESS_TREE_EDRS:
            return 3.0  # much easier to evade these
        return base_rank

    def select_evasions_for_retry(
        self,
        target_spec: TargetEnvironmentSpec,
        detection_history: list[dict],
        exhausted_strategies: Optional[list[str]] = None,
        max_techniques: int = 10,
    ) -> List[MalwareTechnique]:
        """Select evasion techniques informed by prior detection history.

        Boosts techniques targeting specific detection categories seen.
        Demotes techniques associated with exhausted strategies.
        """
        base = self.select_evasions(target_spec, max_techniques=max_techniques * 2)
        exhausted = set(exhausted_strategies or [])

        detection_cats = set()
        detection_rules = set()
        for d in detection_history:
            if d.get("category"):
                detection_cats.add(d["category"].lower())
            if d.get("rule_name"):
                detection_rules.add(d["rule_name"].lower())

        _CAT_TO_TECHNIQUE = {
            "trojan": {"string_encryption", "api_obfuscation", "anti_debug"},
            "behavior:": {"sleep_obfuscation", "indirect_syscall", "etw_patch"},
            "heuristic": {"control_flow_obfuscation", "junk_code_insertion"},
            "signature": {"string_encryption", "metamorphic_engine"},
            "ransomware": {"api_unhooking", "etw_patch", "amsi_bypass"},
        }

        boosted_names = set()
        for cat in detection_cats:
            for key, techs in _CAT_TO_TECHNIQUE.items():
                if key in cat:
                    boosted_names |= techs

        def _rank(t: MalwareTechnique) -> float:
            score = t.detection_rating or 5.0
            name_lower = (t.name or "").lower()
            if name_lower in exhausted:
                score += 20
            if name_lower in boosted_names:
                score -= 3
            return score

        base.sort(key=_rank)
        return [t for t in base if (t.name or "").lower() not in exhausted][:max_techniques]
