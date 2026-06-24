"""Phase 2a: Design Engine - Architecture Designer.

Takes target spec + DB query results, produces structured component plan.
Routes to cloud LLM for quality reasoning over full architecture space.
"""

import json
from pathlib import Path
from typing import Optional

from .hybrid_llm_router import HybridLLMRouter
from .models import DesignPlan


SYSTEM_PROMPT = """You are a malware architecture designer specializing in evasion against EDR/AV systems.

Given the target environment and top techniques from vulnerability/exploit databases, design a component-based architecture for a {language} malware binary.

Output ONLY valid JSON matching this schema:
{{
  "target_architecture": "string describing overall approach",
  "language_choice": "{language}",
  "compiler_flags": ["list of flags"],
  "components": [
    {{
      "name": "component_name",
      "type": "loader|payload|evasion|persistence|communication",
      "complexity": 0.5,
      "technique_id": "MITRE-ATTACK-ID or null",
      "description": "what this component does",
      "language": "{language}",
      "dependencies": ["other_component_names"],
      "interface_spec": {{}}
    }}
  ]
}}

Guidelines:
1. Keep components focused and single-purpose (single responsibility)
2. Evasion complexity score: 0.0=simple (registry write), 1.0=complex (API hashing + AMSI bypass chain)
3. Minimize dependencies between components for parallel generation
4. Always include an evasion component targeting the specified EDR
5. Include persistence mechanism matching target OS
6. Consider runtime unpacking if payload is large/encrypted

Be concise in descriptions but thorough in architecture design."""


PROMPT_TEMPLATE = """Target Environment: {spec}

Top Techniques from Database (from {db_source}):
{techniques_text}

Design a component-based architecture for this environment. Focus on bypassing {edr_list}.
"""


class DesignEngine:
    """Phase 2a: Generates structured design plan from target spec."""
    
    def __init__(self, router: Optional[HybridLLMRouter] = None):
        self.router = router or HybridLLMRouter()
    
    def _build_prompt(self, spec: str, techniques_text: str, db_source: str) -> str:
        """Build the design prompt with spec and DB results."""
        
        # Extract EDR list from spec for targeting
        edr_keywords = ["crowdstrike", "sentinelone", "defender", "carbonblack", 
                        "ambrosix", "cylance", "falcon", "endpoint"]
        edr_list = [kw for kw in edr_keywords if kw.lower() in spec.lower()]
        if not edr_list:
            edr_list = ["the target EDR/AV"]
        
        return PROMPT_TEMPLATE.format(
            spec=spec,
            techniques_text=techniques_text,
            db_source=db_source,
            edr_list=", ".join(edr_list),
            language="python",  # TODO: make configurable
        )
    
    def design_architecture(self, spec: str, db_results: dict) -> DesignPlan:
        """Design architecture from target spec and database query results.
        
        Args:
            spec: Target environment specification string
            db_results: Results from DBQueryEngine (techniques, CVEs, etc.)
            
        Returns:
            DesignPlan with structured component list
        """
        
        # Format techniques into readable text for LLM
        techniques_text = self._format_db_results(db_results)
        
        prompt = self._build_prompt(spec, techniques_text, "malware_corpus")
        
        response = self.router.route(
            task_type="design",
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=2048,
        )
        
        # Parse JSON response - extract from markdown code blocks if present
        json_text = self._extract_json(response["response"])
        
        try:
            plan_dict = json.loads(json_text)
            return DesignPlan(**plan_dict)
        except Exception as e:
            raise ValueError(f"Failed to parse design plan JSON: {e}\nResponse:\n{json_text}")
    
    def _format_db_results(self, db_results: dict) -> str:
        """Format database query results into readable text for the LLM."""
        
        lines = []
        
        if "techniques" in db_results:
            lines.append("=== Top Techniques ===")
            for tech in db_results["techniques"][:10]:  # top 10 only to save tokens
                lines.append(f"- {tech.get('technique_id', 'N/A')}: {tech.get('description', '')} "
                           f"(severity: {tech.get('severity', 'N/A')}, "
                           f"language: {tech.get('language', 'N/A')})")
        
        if "cves" in db_results:
            lines.append("\n=== Relevant CVEs ===")
            for cve in db_results["cves"][:5]:  # top 5 only
                lines.append(f"- {cve.get('id', 'N/A')}: {cve.get('description', '')} "
                           f"(CVSS: {cve.get('cvss', 'N/A')})")
        
        if "exploits" in db_results:
            lines.append("\n=== Exploit Templates ===")
            for exp in db_results["exploits"][:5]:
                lines.append(f"- {exp.get('name', 'N/A')} ({exp.get('language', '')}): "
                           f"{exp.get('description', '')}")
        
        return "\n".join(lines) if lines else "No techniques found."
    
    def _extract_json(self, text: str) -> str:
        """Extract JSON from markdown code blocks or raw response."""
        
        # Try to extract from ```json ... ``` block first
        if "```" in text:
            parts = text.split("```")
            for i, part in enumerate(parts):
                if i + 1 < len(parts):
                    next_part = parts[i + 1]
                    if "json" in next_part.lower()[:20]:
                        return parts[i + 2].strip() if i + 2 < len(parts) else next_part.strip()
        
        # Fallback: find JSON object boundaries
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            return text[start:end]
        
        return text
