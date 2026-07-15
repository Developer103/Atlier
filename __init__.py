# Malware Gen Framework — complete package exports

# Phase 3: VM Provisioning
from .config_models import VMProvisionConfig, TargetOS, EDRConfig, NetworkConfig, VMResourceSpec
from .provision_engine import ProvisionEngine, QEMUProcess, VMInstance, SSHBridgeException, cleanup_orphan_vms
from .image_sources import ensure_linux_image, ensure_windows_iso
from .linux_provisioner import generate_cloud_init_yaml, create_cloud_init_iso, CloudInitProvisioner
from .windows_provisioner import generate_autounattend_xml, create_autounattend_iso, WindowsProvisioner

# Phase 2: Target Spec Parser
from .target_spec import TargetEnvironmentSpec, OSPlatform, LinuxDistro, WindowsVersion
from .spec_parser import parse_target_spec, spec_to_yaml

# Compiler selector (active — used by chunk assembler path)
from .compiler_selector import CompilerSelector, CompilerInstruction

# Phase 6: CLI
from .cli import build_parser as cli_build_parser, main as cli_main

# Legacy LLM pipeline — optional imports (moved to out-of-order/)
try:
    from .db_models import MalwareTechnique, PoC, CTIFinding, QueryResult, TargetEnvironmentSpec as DBTargetSpec
    from .db_query_engine import DBQueryEngine, QueryPlan
    from .context_builder import ContextBuilder, ContextBlock, RankedTechnique, RankedPoC, ExploitablePoC
    from .prompt_templates import PromptTemplates
    from .generation_engine import GenerationEngine, GenerationResult, SubprocessLLMClient
    from .evasion_selector import EvasionSelector
    from .exploit_selector import ExploitSelector, ExploitSelection
    from .code_processor import (
        source_extension, source_filename, output_filename,
        assemble_source, fixup_source, compile_check_command,
    )
    from .verifier import Verifier, VerificationResult, DetectionLevel, BehaviourCheck, AlertRecord, verify_standalone
    from .loop_controller import LoopController, LoopResult, IterationRecord, FailureMode
    from .checkpoint import CheckpointManager, CheckpointState
    from .edr_rule_extractor import DefenderRuleExtractor, ScanResult, DefenderSignature
    from .pipeline import MalwarePipeline, PipelineResult, PipelineError
except ImportError:
    pass
