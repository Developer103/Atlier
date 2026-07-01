"""
Dataclasses for structured query results from databases.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import hashlib
import json

@dataclass
class MalwareTechnique:
    """Represents a malware technique from the corpus."""
    id: str
    name: str
    description: str
    category: str
    os_type: str
    source_code: str = ""
    similarity: float = 0.0
    edr_detection: Optional[str] = None
    detection_rating: Optional[float] = None
    references: List[str] = field(default_factory=list)
    filepath: str = ""


@dataclass
class PoC:
    """Represents a Proof of Concept from the corpus."""
    id: str
    cve: str
    title: str
    description: str
    exploit_type: str
    target_os: str
    severity: str
    source: Optional[str] = None
    code: Optional[str] = None
    full_source: Optional[str] = None
    filepath: str = ""
    language: str = ""
    stars: int = 0
    forks: int = 0
    cve_year: Optional[int] = None
    references: List[str] = field(default_factory=list)

    @property
    def has_usable_code(self) -> bool:
        return bool(self.full_source and len(self.full_source.strip()) > 50)


@dataclass
class CTIFinding:
    """Represents a finding from the CTI knowledge base."""
    id: str
    title: str
    description: str
    severity: str
    similarity: float = 0.0
    threat_actor: Optional[str] = None
    indicators: List[str] = field(default_factory=list)
    related_cves: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    poc_urls: List[str] = field(default_factory=list)
    date: str = ""


@dataclass
class QueryResult:
    """Structured result from all database queries."""
    malware_techniques: List[MalwareTechnique] = field(default_factory=list)
    poc_results: List[PoC] = field(default_factory=list)
    cti_findings: List[CTIFinding] = field(default_factory=list)
    cve_pocs: List[PoC] = field(default_factory=list)

    @property
    def all_pocs(self) -> List[PoC]:
        """Merged PoCs from semantic search + CVE-targeted lookups, deduped."""
        seen: set[str] = set()
        merged: List[PoC] = []
        for p in self.cve_pocs + self.poc_results:
            key = p.cve or p.id
            if key not in seen:
                seen.add(key)
                merged.append(p)
        return merged

    @property
    def exploitable_cves(self) -> List[PoC]:
        """PoCs that have usable source code for direct integration."""
        return [p for p in self.all_pocs if p.has_usable_code]


@dataclass
class TargetEnvironmentSpec:
    """Target environment specification (legacy compat — use target_spec.py)."""
    os_type: str
    os_version: str
    edrs: List[str] = field(default_factory=list)
    antivirus: Optional[str] = None
    patch_level: Optional[str] = None
    installed_compilers: List[str] = field(default_factory=list)
    common_tools: List[str] = field(default_factory=list)
    network_config: Optional[Dict[str, Any]] = None
    domain_joined: bool = False
    admin_rights: bool = False
    sandbox_detectors: List[str] = field(default_factory=list)
    custom_gates: List[str] = field(default_factory=list)