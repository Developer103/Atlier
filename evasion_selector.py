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
