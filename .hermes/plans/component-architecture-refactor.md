# Component-Based Architecture Refactor + Hybrid LLM Routing

## Problem
Current generation is a single monolithic prompt → whole binary regenerated on any failure. No parallelism. No component-level retry.

## Solution: 5-phase pipeline with cloud/local LLM routing

### Phase 2a: Design (Cloud LLM)
- Input: target spec + top techniques from DB query
- Cloud model (GPT-5/Claude): outputs structured JSON plan
- Plan contains: components list, tech per component, language choice, compiler flags, interface specs between components

### Phase 2b: Component Generation (Hybrid: cloud for complex, local for simple)
- Each component gets a focused prompt with its specific technique from DB
- Complex evasion (AMSI bypass, API hashing): cloud model
- Simple components (loader stub, main function, persistence registry write): local model
- Output: individual .py files per component

### Phase 2c: Assembly (Local LLM)
- Reads all generated components + design plan
- Generates glue code: imports, wiring, entry point
- Validates syntax with py_compile before proceeding

### Phase 2d: Post-generation Optimization (Local LLM)
- Self-modification pass: string encryption, size reduction, anti-analysis tricks per spec

### Phase 4: Verify & Smart Retry (Hybrid)
- Compile in VM → if fails, parse error → regenerate only affected component(s)
- EDR detection > threshold → identify which component's technique triggered it → swap + regenerate that one
- Component state tracking: clean vs needs-regen per iteration

## Hybrid LLM Routing Rules

| Phase | Model | Reason |
|-------|-------|--------|
| 2a Design | Cloud (GPT-5/Claude) | Needs broad reasoning over entire spec + techniques |
| 2b Generation - Complex Evasion | Cloud | AMSI bypass, API hashing need creative code generation |
| 2b Generation - Simple | Local (qwen3.6-35b-a3b) | Template-based, predictable patterns |
| 2c Assembly | Local | Pattern matching between known interfaces |
| 2d Optimization | Local | Self-modification of own codebase |
| 4 Retry - Compilation Error | Local | Parse error → swap specific line/function |
| 4 Retry - EDR Detection | Cloud | Needs reasoning about which technique to swap |

## Config (config.yaml additions)
```yaml
llm:
  cloud_provider: openrouter      # or any provider supporting OpenRouter routing
  cloud_models:
    design: "anthropic/claude-sonnet-4"       # Phase 2a
    complex_evasion: "openai/gpt-5"           # Phase 2b (complex)
    erd_retry: "anthropic/claude-sonnet-4"    # Phase 4 EDR retry
  local_provider: lmstudio
  local_endpoint: http://localhost:1234/v1
  local_model: qwen3.6-35b-a3b-uncensored-hauhaucs-aggressiv
  
  routing:
    strategy: hybrid          # "cloud" | "local" | "hybrid"
```

## File Structure Changes

```
malware_gen_framework/
├── pipeline.py                  # Updated orchestrator (uses new phases)
├── generation_engine.py         # New: ComponentGenerator + AssemblyEngine
│   ├── component_generator.py   # Phase 2b: generates individual components
│   └── assembly_engine.py       # Phase 2c: stitches components together
├── design_engine.py             # NEW: Phase 2a - architecture designer
├── retry_engine.py              # NEW: Phase 4 smart retry logic
├── hybrid_llm_router.py         # NEW: cloud/local model routing
├── db_query_engine.py           # Existing (unchanged)
├── loop_engine.py               # Updated to use new phases internally
└── models/
    ├── design_plan.py           # NEW: Pydantic model for design JSON output
    └── component_state.py       # NEW: tracks per-component verification state
```

## Key Classes

### DesignEngine (Phase 2a)
- `design_architecture(spec, db_results)` → DesignPlan (structured JSON)
- Prompt template: "Given target {spec} and techniques {top_techniques}, design a component plan..."
- Output validated against Pydantic schema before proceeding

### ComponentGenerator (Phase 2b)
- `generate_component(component_def, technique, db_context)` → source_code
- Routes to cloud/local based on complexity classification in DesignPlan
- Each prompt is ~1/4 the size of current monolithic prompt

### AssemblyEngine (Phase 2c)
- `assemble(components: dict[str, str], design_plan)` → combined_source
- Adds imports, wires interfaces, generates entry point
- Validates with py_compile

### SmartRetryEngine (Phase 5b)
- `resolve_failure(failure_type, component_state, db_results)` → updated_component
- failure_types: "compilation_error", "edr_detection", "runtime_crash"
- Tracks which components are clean vs need regeneration per iteration

## Implementation Order

1. **hybrid_llm_router.py** - Foundation, used by everything
2. **models/design_plan.py + models/component_state.py** - Data structures
3. **design_engine.py** - Phase 2a (depends on router)
4. **component_generator.py** - Phase 2b (depends on router + design plan)
5. **assembly_engine.py** - Phase 2c (depends on component generator)
6. **retry_engine.py** - Phase 4 smart retry (depends on all above)
7. Update **loop_engine.py** to use new pipeline internally
8. Update **pipeline.py** orchestrator
9. Add config for LLM routing
10. Test end-to-end with Windows 11 + CrowdStrike spec
