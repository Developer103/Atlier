"""Knowledge database — records what works per EDR version and failure patterns."""

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

DB_PATH = Path(__file__).parent.parent / "hermes_knowledge.json"


@dataclass
class OperationRecord:
    timestamp: str
    malware_type: str
    format_type: str
    recipe: str
    evasion_layers: list[str]
    edr: str
    edr_version: str
    result: str
    c2_bytes: int
    detection_details: str
    failure_type: str
    notes: str = ""


@dataclass
class KnowledgeDB:
    operations: list[OperationRecord] = field(default_factory=list)
    proven_recipes: dict[str, list[str]] = field(default_factory=dict)
    failed_patterns: dict[str, list[str]] = field(default_factory=dict)
    edr_profiles: dict[str, dict] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "KnowledgeDB":
        p = path or DB_PATH
        if not p.exists():
            return cls()
        try:
            data = json.loads(p.read_text())
            ops = [OperationRecord(**o) for o in data.get("operations", [])]
            return cls(
                operations=ops,
                proven_recipes=data.get("proven_recipes", {}),
                failed_patterns=data.get("failed_patterns", {}),
                edr_profiles=data.get("edr_profiles", {}),
            )
        except Exception as e:
            logger.warning("Failed to load knowledge DB: %s", e)
            return cls()

    def save(self, path: Optional[Path] = None):
        p = path or DB_PATH
        data = {
            "operations": [asdict(o) for o in self.operations],
            "proven_recipes": self.proven_recipes,
            "failed_patterns": self.failed_patterns,
            "edr_profiles": self.edr_profiles,
        }
        p.write_text(json.dumps(data, indent=2))

    def record_operation(self, op: OperationRecord):
        self.operations.append(op)
        key = f"{op.edr}:{op.malware_type}"
        if op.result == "SUCCESS":
            self.proven_recipes.setdefault(key, [])
            entry = f"{op.format_type}:{op.recipe}:{','.join(op.evasion_layers)}"
            if entry not in self.proven_recipes[key]:
                self.proven_recipes[key].append(entry)
        else:
            self.failed_patterns.setdefault(key, [])
            entry = f"{op.failure_type}:{op.format_type}:{op.recipe}"
            if entry not in self.failed_patterns[key]:
                self.failed_patterns[key].append(entry)
        self.save()

    def get_proven_for(self, edr: str, malware_type: str) -> list[str]:
        return self.proven_recipes.get(f"{edr}:{malware_type}", [])

    def get_failed_for(self, edr: str, malware_type: str) -> list[str]:
        return self.failed_patterns.get(f"{edr}:{malware_type}", [])

    def update_edr_profile(self, edr: str, profile: dict):
        self.edr_profiles[edr] = profile
        self.save()

    def get_success_rate(self, edr: str, format_type: str) -> float:
        relevant = [o for o in self.operations if o.edr == edr and o.format_type == format_type]
        if not relevant:
            return 0.0
        successes = sum(1 for o in relevant if o.result == "SUCCESS")
        return successes / len(relevant)

    def summary(self) -> str:
        lines = [f"Operations: {len(self.operations)}"]
        for key, recipes in self.proven_recipes.items():
            lines.append(f"  Proven for {key}: {len(recipes)} recipes")
        for key, patterns in self.failed_patterns.items():
            lines.append(f"  Failed for {key}: {len(patterns)} patterns")
        return "\n".join(lines)
