"""Phase 2c: Assembly Engine - stitches generated components into final binary."""

import subprocess
from pathlib import Path
from typing import List, Dict, Tuple


# Standard entry points and glue patterns
STANDARD_HEADERS = {
    "python": '''#!/usr/bin/env python3
"""Auto-generated malware for target environment."""
import sys
import os\n''',
}

ENTRY_POINT_TEMPLATE = '''
# === AUTO-GENERATED ENTRY POINT ===

def main():
    """Entry point - initializes and runs all components."""
'''


class AssemblyEngine:
    """Phase 2c: Assembles component code into working binary."""
    
    def __init__(self):
        self.generated_files = {}  # name -> source_code
    
    def add_component(self, name: str, source: str):
        """Register a generated component."""
        self.generated_files[name] = source
    
    def assemble(self, design) -> tuple[str, bool]:
        """Assemble all components into final code.
        
        Args:
            design: DesignPlan with component list and structure
            
        Returns:
            (final_code, is_valid) — assembled code string + validation result
        """
        
        lines = [STANDARD_HEADERS["python"]]
        
        # Sort components by dependencies first (topological-ish sort)
        ordered_components = self._topological_sort(design.components)
        
        for comp in ordered_components:
            if comp.name not in self.generated_files:
                continue
                
            source = self.generated_files[comp.name]
            
            # Add component as a module-level import or inline class
            lines.append(f"\n# === COMPONENT: {comp.name} ({comp.type}) ===")
            lines.append(source)
        
        # Add entry point
        lines.append(ENTRY_POINT_TEMPLATE.format(name=design.target_architecture))
        lines.append(self._build_main_body(design))
        
        final_code = "\n".join(lines)
        
        # Validate: syntax check + lint
        is_valid, errors = self._validate_assembly(final_code)
        
        return final_code, is_valid
    
    def _topological_sort(self, components):
        """Sort components respecting dependency order."""
        
        name_to_comp = {c.name: c for c in components}
        visited = set()
        ordered = []
        
        def visit(name):
            if name in visited:
                return
            visited.add(name)
            
            comp = name_to_comp.get(name)
            if not comp:
                return
            
            # Visit dependencies first
            for dep in (comp.dependencies or []):
                visit(dep)
            
            ordered.append(comp)
        
        for comp in components:
            visit(comp.name)
        
        return ordered
    
    def _build_main_body(self, design) -> str:
        """Build the main() function body that wires all components together."""
        
        init_calls = []
        run_calls = []
        
        for comp in design.components:
            if comp.type == "loader":
                init_calls.append(f"    {comp.name}.init()")
                run_calls.append(f"    {comp.name}.run()")
            elif comp.type == "evasion":
                init_calls.append(f"    {comp.name}.init()")
                run_calls.append(f"    if not {comp.name}.bypass():\n        print('Evasion failed, continuing anyway')")
            else:
                run_calls.append(f"    {comp.name}.run()")
        
        body = []
        if init_calls:
            body.extend(init_calls)
            body.append("")  # blank line
        
        body.append("# Execute components")
        body.extend(run_calls)
        body.append("\nif __name__ == '__main__':\n    main()")
        
        return "\n".join(body)
    
    def _validate_assembly(self, code: str) -> Tuple[bool, List[str]]:
        """Validate assembled code."""
        
        errors = []
        
        # Syntax check
        try:
            compile(code, "<assembled>", "exec")
        except SyntaxError as e:
            errors.append(f"Syntax error: {e}")
            return False, errors
        
        # Check for common issues
        if 'import' in code and code.count('import') > 20:
            errors.append("WARNING: High number of imports — may be bloated")
        
        # Look for unresolved references (simple check)
        import re
        undefined_names = set()
        defined_names = set()
        
        # Find all variable/function definitions
        for match in re.finditer(r'(?:def|class)\s+(\w+)', code):
            defined_names.add(match.group(1))
        
        # Check for common stdlib imports that should exist
        expected_imports = ['sys', 'os', 'json', 'subprocess']
        missing = [imp for imp in expected_imports if f'import {imp}' not in code]
        if missing:
            errors.append(f"Missing common imports: {', '.join(missing)}")
        
        return len(errors) == 0, errors
    
    def write_final_file(self, final_code: str, output_path: str):
        """Write assembled code to disk."""
        
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(final_code)
