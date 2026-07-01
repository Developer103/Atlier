# Malware Gen Framework — complete package exports

# Phase 3: VM Provisioning
from .config_models import VMProvisionConfig, TargetOS, EDRConfig, NetworkConfig, VMResourceSpec
from .provision_engine import ProvisionEngine, QEMUProcess, VMInstance, SSHBridgeException, cleanup_orphan_vms
from .image_sources import ensure_linux_image, ensure_windows_iso
from .linux_provisioner import generate_cloud_init_yaml, create_cloud_init_iso, CloudInitProvisioner
from .windows_provisioner import generate_autounattend_xml, create_autounattend_iso, WindowsProvisioner

# Phase 1: DB Integration Layer
from .db_models import MalwareTechnique, PoC, CTIFinding, QueryResult, TargetEnvironmentSpec as DBTargetSpec
from .db_query_engine import DBQueryEngine, QueryPlan
from .context_builder import ContextBuilder, ContextBlock, RankedTechnique, RankedPoC, ExploitablePoC

# Phase 1 extras: Prompt Templates
from .prompt_templates import PromptTemplates

# Phase 2: Target Spec Parser (note: this is our own model, not the db one)
from .target_spec import TargetEnvironmentSpec, OSPlatform, LinuxDistro, WindowsVersion
from .spec_parser import parse_target_spec, spec_to_yaml

# Phase 4: Generation Engine & Selectors
from .generation_engine import GenerationEngine, GenerationResult, SubprocessLLMClient
from .evasion_selector import EvasionSelector
from .exploit_selector import ExploitSelector, ExploitSelection
from .compiler_selector import CompilerSelector, CompilerInstruction

# Phase 4b: Language-specific code processing
from .code_processor import (
    source_extension, source_filename, output_filename,
    assemble_source, fixup_source, compile_check_command,
)

# Phase 5: Verification Pipeline
from .verifier import Verifier, VerificationResult, DetectionLevel, BehaviourCheck, AlertRecord, verify_standalone
from .loop_controller import LoopController, LoopResult, IterationRecord, FailureMode

# Phase 5b: Checkpoint/Resume
from .checkpoint import CheckpointManager, CheckpointState

# Phase 5c: EDR Rule Extraction
from .edr_rule_extractor import DefenderRuleExtractor, ScanResult, DefenderSignature

# Phase 6: Pipeline & CLI
from .pipeline import MalwarePipeline, PipelineResult, PipelineError
from .cli import build_parser as cli_build_parser, main as cli_main
