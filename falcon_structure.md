schema_version: "1.0"
title: "CrowdStrike Falcon — Malware Detection Architecture"
description: >-
  Structured, machine-analyzable model of how the CrowdStrike Falcon EDR detects
  malware, split across the on-host sensor and the CrowdStrike cloud. Compiled from
  CrowdStrike engineering publications and independent technical analyses. Architectural
  level only; simplified for clarity and not exhaustive.
last_updated: "2026-07-03"
disclaimer: >-
  Educational/defensive reference. Describes published, high-level architecture. Does
  not contain evasion procedures or bypass instructions.

# ---------------------------------------------------------------------------
# WHERE THINGS RUN. Every component references one of these ids in `runs_where`.
# ---------------------------------------------------------------------------
layers:
  - id: host_kernel
    name: "Endpoint — kernel mode"
    note: "Kernel-mode driver; loads early (ELAM), runs as PPL, KPP/PatchGuard-compatible."
  - id: host_user
    name: "Endpoint — user mode"
    note: "User-mode sensor components, some sandboxed via PPL AppContainer."
  - id: cloud
    name: "CrowdStrike cloud"
    note: "Threat Graph / Security Cloud; global-scale analysis and model training."

# ---------------------------------------------------------------------------
# COMPONENTS. Nodes in the architecture graph.
#   inputs / outputs = ids of other components (directed edges).
#   runs_where       = a layers[].id
#   offline_capable  = does this still function with no cloud connectivity?
# ---------------------------------------------------------------------------
components:

  # --- OS telemetry taps: where the sensor "listens" -----------------------
  - id: tap_kernel_callbacks
    name: "Kernel callbacks"
    category: telemetry_source
    runs_where: host_kernel
    observes: "Process/thread creation & termination; image (module) load into memory."
    detail: >-
      Registers driver callbacks such as PspLoadImageNotifyRoutine that fire on image
      load; a callback can inject the user-mode DLL into new processes for user-mode
      API hooking.
    inputs: []
    outputs: [sensor_esp]
    offline_capable: true
    refs: [r_kernel_arch, r_bypass_analysis]

  - id: tap_minifilter
    name: "Minifilter driver"
    category: telemetry_source
    runs_where: host_kernel
    observes: "File-system and registry I/O operations."
    detail: "Intercepts I/O requests between applications and the file system via registered callbacks."
    inputs: []
    outputs: [sensor_esp]
    offline_capable: true
    refs: [r_bypass_analysis]

  - id: tap_etw
    name: "ETW (Event Tracing for Windows)"
    category: telemetry_source
    runs_where: host_user
    observes: "Process events, driver load/unload, file & registry access, network connections, authentication."
    detail: >-
      Uses hardened variants: tamper-resistant 'Secure ETW' and the 'Threat Intelligence'
      ETW channel. Kernel presence is used to avoid depending on user-mode-only sources
      an attacker could tamper with.
    inputs: []
    outputs: [sensor_esp]
    offline_capable: true
    refs: [r_kernel_arch]

  - id: tap_amsi
    name: "AMSI (Anti-Malware Scan Interface)"
    category: telemetry_source
    runs_where: host_user
    observes: "Scripts and in-memory code — e.g. PowerShell, macros, documents."
    detail: "Heavy AMSI use removes the need for the sensor to do its own script/macro/document parsing."
    inputs: []
    outputs: [sensor_esp]
    offline_capable: true
    refs: [r_kernel_arch]

  - id: tap_intel_pt
    name: "Intel Processor Trace (Intel PT)"
    category: telemetry_source
    runs_where: host_kernel
    observes: "CPU-level control-flow trace of executing code."
    detail: >-
      Per-thread 32KB trace buffers; kernel-mode callbacks with pre-filtering decide when
      to run the analyzer, which reconstructs control flow to catch code-reuse exploits.
      Backs the 'Hardware Enhanced Exploit Detection' feature (Intel 6th-gen+, Win10 RS4+).
    emits_events: [SuspiciousExecutionTrace, PtTelemetry]
    inputs: []
    outputs: [sensor_esp]
    offline_capable: true
    refs: [r_hw_exploit]

  # --- Sensor processing ---------------------------------------------------
  - id: sensor_esp
    name: "Event Stream Processing (ESP)"
    category: processing
    runs_where: host_kernel
    observes: "Correlates 1,000+ event types in real time on-host."
    detail: >-
      Core of the 'smart sensor' model: processes and decides on-host rather than only
      shipping data to a server, which is what makes on-host prevention possible.
      Behavioral IOA correlation ties low-level events into higher-level detections.
    inputs: [tap_kernel_callbacks, tap_minifilter, tap_etw, tap_amsi, tap_intel_pt]
    outputs: [engine_sensor_ml, engine_ioa, engine_ioc]
    offline_capable: true
    refs: [r_esp_ioa, r_smart_sensor]

  # --- On-host detection engines -------------------------------------------
  - id: engine_sensor_ml
    name: "Sensor ML / NGAV"
    category: detection_engine
    runs_where: host_user
    method: machine_learning
    observes: "Scores files and behavior with an on-host model; instant local verdicts."
    detail: "First third-party product to run an ML NGAV engine in a PPL AppContainer sandbox (2017)."
    inputs: [sensor_esp, cloud_ai_ioa]
    outputs: [prevention]
    offline_capable: true
    refs: [r_kernel_arch, r_ai_ioa]

  - id: engine_ioa
    name: "Behavioral IOAs (Indicators of Attack)"
    category: detection_engine
    runs_where: host_kernel
    method: behavioral_correlation
    observes: "Sequences/chains of behavior indicating an attack in progress; tool- and malware-agnostic."
    detail: >-
      Example capability: detect credential theft from a reflectively injected module in
      PowerShell and prevent it before the attacker observes the result. Correlates
      cloud-delivered AI-IOAs with local events.
    inputs: [sensor_esp, cloud_ai_ioa]
    outputs: [prevention]
    offline_capable: true
    refs: [r_esp_ioa, r_ioa_def, r_ai_ioa]

  - id: engine_ioc
    name: "IOC hash lists (Indicators of Compromise)"
    category: detection_engine
    runs_where: host_user
    method: signature_hash
    observes: "Known-bad / known-good SHA256 hashes; always-block or never-block dispositions."
    detail: "Reactive layer; evidence-based rather than behavior-based."
    inputs: [sensor_esp, cloud_threat_intel]
    outputs: [prevention]
    offline_capable: true
    refs: [r_dell_overview, r_ioa_def]

  # --- Response ------------------------------------------------------------
  - id: prevention
    name: "Local prevention & response"
    category: response
    runs_where: host_kernel
    observes: "Enforcement actions decided on-host."
    actions: [block_process, kill_process, network_isolate_host, quarantine]
    detail: "Decided locally in-line with the offending operation; functions without cloud connectivity."
    inputs: [engine_sensor_ml, engine_ioa, engine_ioc]
    outputs: []
    offline_capable: true
    refs: [r_smart_sensor, r_dell_overview]

  # --- Cloud ---------------------------------------------------------------
  - id: cloud_threat_graph
    name: "Threat Graph / Security Cloud"
    category: cloud_platform
    runs_where: cloud
    observes: "Ingests high-fidelity telemetry from the global sensor fleet (trillions of events/week)."
    detail: "Central data foundation for correlation, hunting, and model training."
    inputs: [sensor_esp]
    outputs: [cloud_ml, cloud_threat_intel, cloud_mitre_map]
    offline_capable: false
    refs: [r_how_it_works, r_ai_ioa]

  - id: cloud_ml
    name: "Cloud ML models"
    category: cloud_detection
    runs_where: cloud
    method: machine_learning
    observes: "Heavier behavioral analysis than the sensor can run locally; generates new detections."
    inputs: [cloud_threat_graph, cloud_overwatch]
    outputs: [cloud_ai_ioa]
    offline_capable: false
    refs: [r_ai_ioa, r_cso_ai_ioa]

  - id: cloud_ai_ioa
    name: "AI-powered IOAs"
    category: cloud_detection
    runs_where: cloud
    method: machine_learning
    observes: "Behavior detections generated in the cloud and pushed to the sensor."
    detail: >-
      Delivered to the agent the same way as sensor ML models; the sensor correlates them
      with local events asynchronously, alongside existing sensor-based defenses.
    inputs: [cloud_ml]
    outputs: [engine_ioa, engine_sensor_ml]
    offline_capable: false
    refs: [r_ai_ioa, r_intro_ai_ioa]

  - id: cloud_threat_intel
    name: "Threat intelligence + OverWatch"
    category: cloud_intel
    runs_where: cloud
    observes: "Human threat hunters build the clean/malicious ground-truth corpus that trains the models."
    detail: "Corpus spans OverWatch (managed hunting), Malware Research Center, and Falcon Complete (MDR)."
    inputs: [cloud_threat_graph]
    outputs: [cloud_ml, engine_ioc]
    offline_capable: false
    refs: [r_cso_ai_ioa, r_ioa_def]
    alias: [cloud_overwatch]

  - id: cloud_mitre_map
    name: "MITRE ATT&CK mapping"
    category: cloud_enrichment
    runs_where: cloud
    observes: "Tags detections to ATT&CK TTPs for analysts, reporting, and incident response."
    inputs: [cloud_threat_graph]
    outputs: []
    offline_capable: false
    refs: [r_how_it_works, r_detection_eng]

# ---------------------------------------------------------------------------
# DATA FLOWS. Explicit directed edges (redundant with inputs/outputs, provided
# for easy graph construction). direction: up = host->cloud, down = cloud->host.
# ---------------------------------------------------------------------------
data_flows:
  - from: [tap_kernel_callbacks, tap_minifilter, tap_etw, tap_amsi, tap_intel_pt]
    to: sensor_esp
    label: "raw events"
    direction: host_internal
  - from: sensor_esp
    to: [engine_sensor_ml, engine_ioa, engine_ioc]
    label: "correlated event stream"
    direction: host_internal
  - from: [engine_sensor_ml, engine_ioa, engine_ioc]
    to: prevention
    label: "verdicts"
    direction: host_internal
  - from: sensor_esp
    to: cloud_threat_graph
    label: "high-fidelity telemetry"
    direction: up
  - from: cloud_ai_ioa
    to: [engine_ioa, engine_sensor_ml]
    label: "AI-generated IOAs, intel, policy"
    direction: down

# ---------------------------------------------------------------------------
# KEY CONCEPTS for reasoning about the model.
# ---------------------------------------------------------------------------
concepts:
  ioa_vs_ioc:
    ioa:
      full: "Indicator of Attack"
      focus: "Signs of an attack in progress (behavior)."
      timing: "Proactive — aims to catch before breach; tool/malware-agnostic."
    ioc:
      full: "Indicator of Compromise"
      focus: "Evidence a breach already occurred (artifacts: hashes, C2 domains, etc.)."
      timing: "Reactive — useful for post-breach forensics."
    ref: r_ioa_def

  ml_tiers:
    on_host:
      component: engine_sensor_ml
      property: "Instant, offline-capable verdicts."
    cloud:
      component: cloud_ml
      property: "Heavier analysis; issues AI-IOAs asynchronously to the sensor."
    ref: r_intro_ai_ioa

  smart_sensor_model:
    claim: "Sensor processes and decides on-host, not just ship-to-server."
    consequence: "Enables on-host prevention and detections impossible in a 'dumb sensor' model."
    ref: r_smart_sensor

  anti_tamper_rationale:
    early_load: "ELAM start before user-mode services prevents pre-tamper of relied-upon components."
    kernel_presence: "Avoids sole reliance on user-mode sources an elevated attacker could disable."
    self_protection: "PPL protection; KPP/PatchGuard compatibility."
    byovd_defense:
      description: "Blocks/loads-control of vulnerable & malicious drivers used to strip EDR callbacks."
      related_toggles: ["Suspicious Processes", "Suspicious Kernel Drivers", "Additional User-Mode Data (AUMD)"]
      note: "Toggles are cloud-controlled; behavior can change without a sensor upgrade."
    refs: [r_kernel_arch, r_byovd, r_kernel_attacks]

# ---------------------------------------------------------------------------
# TELEMETRY EVENT SCHEMA (illustrative).
# ---------------------------------------------------------------------------
telemetry_event_schema:
  note: >-
    Falcon telemetry uses named events keyed by `event_simpleName`. Fields include process
    lineage and timing identifiers. Example families below are illustrative, not complete.
  identifier_field: event_simpleName
  example_event_names: [EndOfProcess, EndOfProcessV15]
  common_fields:
    - aid   # agent (sensor) id
    - cid   # customer id
    - SHA256HashData
    - TargetProcessId
    - ParentProcessId
    - ContextProcessId
    - event_platform
    - timestamp
  ref: r_sekoia_telemetry

# ---------------------------------------------------------------------------
# REFERENCES. Every `refs`/`ref` id resolves here.
# ---------------------------------------------------------------------------
references:
  - id: r_kernel_arch
    title: "Tech Analysis: CrowdStrike's Kernel Access and Security Architecture"
    publisher: "CrowdStrike (Ionescu, Petrbok, O'Brien, Shaw)"
    type: vendor_engineering
    url: "https://www.crowdstrike.com/en-us/blog/tech-analysis-kernel-access-security-architecture/"
  - id: r_hw_exploit
    title: "Introducing Falcon Hardware Enhanced Exploit Detection"
    publisher: "CrowdStrike"
    type: vendor_engineering
    url: "https://www.crowdstrike.com/en-us/blog/introducing-falcon-hardware-enhanced-exploit-detection/"
  - id: r_esp_ioa
    title: "Event Stream Processing & Indicators of Attack"
    publisher: "CrowdStrike"
    type: vendor_engineering
    url: "https://www.crowdstrike.com/en-us/blog/understanding-indicators-attack-ioas-power-event-stream-processing-crowdstrike-falcon/"
  - id: r_smart_sensor
    title: "What Sets Falcon Apart: Intelligent Host Sensors"
    publisher: "CrowdStrike"
    type: vendor_engineering
    url: "https://www.crowdstrike.com/en-us/blog/what-sets-crowdstrike-falcon-apart/"
  - id: r_ai_ioa
    title: "Introducing AI-powered IOAs"
    publisher: "CrowdStrike"
    type: vendor_engineering
    url: "https://www.crowdstrike.com/en-us/blog/introducing-ai-powered-indicators-of-attack-ioas/"
  - id: r_intro_ai_ioa
    title: "CrowdStrike Introduces Industry's First AI-Powered Indicators of Attack"
    publisher: "CrowdStrike"
    type: vendor_press
    url: "https://www.crowdstrike.com/en-us/press-releases/crowdstrike-introduces-industrys-first-ai-powered-indicators-of-attack/"
  - id: r_ioa_def
    title: "What are Indicators of Attack (IOAs)?"
    publisher: "CrowdStrike"
    type: vendor_reference
    url: "https://www.crowdstrike.com/en-us/cybersecurity-101/threat-intelligence/indicators-of-attack-ioa/"
  - id: r_cso_ai_ioa
    title: "CrowdStrike adds AI-powered indicators of attack to Falcon platform"
    publisher: "CSO Online"
    type: press
    url: "https://www.csoonline.com/article/573361/crowdstrike-adds-ai-powered-indicators-of-attack-to-falcon-platform.html"
  - id: r_byovd
    title: "CrowdStrike Falcon Prevents Multiple Vulnerable Driver Attacks in Real-World Intrusion"
    publisher: "CrowdStrike"
    type: vendor_engineering
    url: "https://www.crowdstrike.com/en-us/blog/falcon-prevents-vulnerable-driver-attacks-real-world-intrusion/"
  - id: r_kernel_attacks
    title: "How to Detect and Prevent Kernel Attacks with CrowdStrike"
    publisher: "CrowdStrike"
    type: vendor_engineering
    url: "https://www.crowdstrike.com/en-us/blog/how-to-detect-and-prevent-kernel-attacks-with-crowdstrike/"
  - id: r_how_it_works
    title: "How CrowdStrike Works: AI Threat Protection"
    publisher: "Osmicro Networks"
    type: partner_analysis
    url: "https://osmicro.com.au/insights/how-does-crowdstrike-work-diving-into-ai-powered-threat-neutralisation/"
  - id: r_dell_overview
    title: "What is the CrowdStrike Falcon Platform"
    publisher: "Dell"
    type: vendor_kb
    url: "https://www.dell.com/support/kbdoc/en-us/000126839/what-is-crowdstrike"
  - id: r_detection_eng
    title: "CrowdStrike Falcon — Detection Engineering Best Practices"
    publisher: "Thinkcloudly"
    type: third_party_analysis
    url: "https://thinkcloudly.com/blog/cyber-security/crowdstrike-detection-engineering-best-practices/"
  - id: r_bypass_analysis
    title: "Bypassing CrowdStrike Falcon and MDE (EDR telemetry-source breakdown)"
    publisher: "Eric Esquivel"
    type: third_party_analysis
    note: "Cited for its accurate enumeration of EDR telemetry primitives (callbacks, minifilter, ETW, AMSI)."
    url: "https://ericesquivel.github.io/posts/bypass"
  - id: r_sekoia_telemetry
    title: "CrowdStrike Falcon Telemetry (event schema documentation)"
    publisher: "Sekoia.io"
    type: third_party_docs
    url: "https://docs.sekoia.io/integration/categories/endpoint/crowdstrike_falcon_telemetry/"
