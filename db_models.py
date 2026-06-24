"""
Dataclasses for structured query results from databases.
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
import json

@dataclass
class MalwareTechnique:
    """Represents a malware technique from the corpus."""
    id: str
    name: str
    description: str
    category: str
    os_type: str
    edr_detection: Optional[str] = None
    detection_rating: Optional[float] = None  # 0.0–1.0 similarity-derived score
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []

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
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []

@dataclass
class CTIFinding:
    """Represents a finding from the CTI knowledge base."""
    id: str
    title: str
    description: str
    severity: str  # Critical, High, Medium, Low
    threat_actor: Optional[str] = None
    indicators: List[str] = None
    related_cves: List[str] = None
    references: List[str] = None
    
    def __post_init__(self):
        if self.indicators is None:
            self.indicators = []
        if self.related_cves is None:
            self.related_cves = []

@dataclass
class QueryResult:
    """Structured result from database queries."""
    malware_techniques: List[MalwareTechnique]
    poc_results: List[PoC]
    cti_findings: List[CTIFinding]
    
    def __post_init__(self):
        if self.malware_techniques is None:
            self.malware_techniques = []
        if self.poc_results is None:
            self.poc_results = []
        if self.cti_findings is None:
            self.cti_findings = []

@dataclass
class TargetEnvironmentSpec:
    """Target environment specification."""
    os_type: str  # 'linux', 'windows'
    os_version: str
    edrs: List[str]  # EDR names (e.g., ['sentinel_one', 'crowdstrike'])
    antivirus: Optional[str] = None
    patch_level: Optional[str] = None  # e.g., 'latest', '2023'
    installed_compilers: List[str] = None  # e.g., ['gcc', 'clang']
    common_tools: List[str] = None  # e.g., ['python', 'powershell']
    network_config: Optional[Dict[str, Any]] = None
    domain_joined: bool = False
    admin_rights: bool = False
    sandbox_detectors: List[str] = None  # e.g., ['vmware', 'cuckoo']
    custom_gates: List[str] = None  # Custom detection evasion requirements
    
    def __post_init__(self):
        if self.installed_compilers is None:
            self.installed_compilers = []
        if self.common_tools is None:
            self.common_tools = []
        if self.sandbox_detectors is None:
            self.sandbox_detectors = []
        if self.custom_gates is None:
            self.custom_gates = []