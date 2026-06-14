# Malware Gen Framework — complete package exports

# Phase 3: VM Provisioning
from .config_models import VMProvisionConfig, TargetOS, EDRConfig, NetworkConfig, VMResourceSpec
from .provision_engine import ProvisionEngine, QEMUProcess, VMInstance, SSHBridgeException
from .image_sources import ensure_linux_image, ensure_windows_iso
from .linux_provisioner import generate_cloud_init_yaml, create_cloud_init_iso, CloudInitProvisioner
from .windows_provisioner import generate_autounattend_xml, create_autounattend_iso, WindowsProvisioner

# Phase 1: DB Integration Layer
from .db_models import MalwareTechnique, PoC, CTIFinding, QueryResult, TargetEnvironmentSpec as DBTargetSpec
from .db_query_engine import DBQueryEngine
from .context_builder import ContextBuilder, ContextBlock, RankedTechnique, RankedPoC

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

# Phase 5: Verification Pipeline
from .verifier import Verifier, VerificationResult, DetectionLevel, BehaviourCheck, AlertRecord, verify_standalone
from .loop_controller import LoopController, LoopResult, IterationRecord, FailureMode

# Phase 6: Pipeline & CLI
from .pipeline import MalwarePipeline, PipelineResult, PipelineError
from .cli import build_parser as cli_build_parser, main as cli_main
