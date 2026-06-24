"""Pydantic models for the component-based pipeline."""

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class ComponentPlan(BaseModel):
    """A single component in the architecture design plan."""
    
    name: str  # e.g., "amsi_bypass", "loader_stub"
    type: str  # "loader" | "payload" | "evasion" | "persistence" | "communication"
    complexity: float = Field(ge=0, le=1)  # 0-1 score for routing decision
    technique_id: Optional[str] = None  # MITRE ATT&CK technique ID from DB
    description: str
    language: str = "python"  # Target language
    dependencies: List[str] = []  # Other component names this depends on
    interface_spec: Dict[str, Any] = {}  # Function signatures / data contract


class DesignPlan(BaseModel):
    """Complete architecture design output from Phase 2a."""
    
    target_architecture: str
    language_choice: str = "python"
    compiler_flags: List[str] = []
    components: List[ComponentPlan]
    
    def get_complex_components(self) -> List[ComponentPlan]:
        """Components that should be routed to cloud LLM."""
        return [c for c in self.components if c.complexity > 0.7]
    
    def get_simple_components(self) -> List[ComponentPlan]:
        """Components that can use local LLM."""
        return [c for c in self.components if c.complexity <= 0.7]


class ComponentState(BaseModel):
    """Tracks verification state of a single component across retry iterations."""
    
    component_name: str
    source_code: Optional[str] = None
    status: str = "pending"  # "pending" | "clean" | "needs_regen" | "failed"
    last_error: Optional[str] = None
    generation_iteration: int = 0
    regeneration_count: int = 0
    
    def mark_clean(self):
        self.status = "clean"
        self.last_error = None
    
    def mark_failed(self, error: str):
        self.status = "needs_regen"
        self.last_error = error
        self.regeneration_count += 1
    
    @property
    def needs_regeneration(self) -> bool:
        return self.status == "needs_regen"
