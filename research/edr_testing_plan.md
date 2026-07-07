# Multi-EDR Testing Plan

## Goal
Test generated malware against multiple EDRs without paying for commercial subscriptions. Automate the process so each pipeline run can optionally cycle through all configured EDRs.

---

## 1. Free / Open-Source EDRs

### Wazuh (Recommended — first to integrate)
- **Type**: Open-source SIEM + EDR (GPLv2)
- **Windows agent**: Yes — lightweight (35MB RAM), MSI installer, auto-enrollment
- **Detection capabilities**: File integrity monitoring, Sysmon log analysis, YARA rules, rootkit detection, process monitoring, Windows Defender log forwarding
- **Server**: Self-hosted (Docker or bare metal). Manager + Indexer + Dashboard
- **Detection check method**: REST API (`GET /security/events`, `GET /alerts`), or parse `ossec.log` on the agent VM
- **Install automation**: `wazuh-agent-4.x.msi /q WAZUH_MANAGER=<host_ip> WAZUH_REGISTRATION_SERVER=<host_ip>`
- **Why first**: Fully free, real-time alerts API, closest to commercial EDR behavior, well-documented

### Elastic Security (Free tier)
- **Type**: SIEM + Endpoint Security (Elastic License 2.0 — free self-managed)
- **Windows agent**: Elastic Agent with Endpoint Security integration
- **Detection capabilities**: YARA signatures, behavioral rules (process trees, file access patterns), prebuilt detection rules (800+), ML anomaly detection
- **Server**: Elasticsearch + Kibana + Fleet Server (Docker)
- **Detection check method**: Elasticsearch query: `GET /.alerts-security*/_search?q=host.name:<vm_hostname>`
- **Install automation**: Fleet enrollment token + `elastic-agent install --url=<fleet_url> --enrollment-token=<token>`
- **Note**: Free tier includes all detection rules. Paid tier adds response actions

### OpenEDR (Comodo fork)
- **Type**: Open-source EDR (Apache 2.0)
- **Windows agent**: Yes — kernel-level driver, real telemetry (process creation, file I/O, registry, network)
- **Detection capabilities**: Process tree tracking, file monitoring, network connections, registry changes
- **Server**: Central management server (optional — can run agent-only)
- **Detection check method**: JSON event logs on agent, or central server API
- **Install automation**: MSI installer, config file points to management server
- **Note**: Raw telemetry — you write your own detection rules. Good for understanding what an EDR *sees*

### Velociraptor
- **Type**: DFIR + endpoint monitoring (AGPL)
- **Windows agent**: Yes — Go binary, low overhead
- **Detection capabilities**: VQL-based artifact collection, Sigma rule support, event monitoring, YARA scanning
- **Server**: Self-hosted Go binary
- **Detection check method**: VQL queries via gRPC API: `SELECT * FROM source(artifact="Windows.Detection.Yara.Process")`
- **Install automation**: `velociraptor client install --config client.config.yaml`
- **Note**: More DFIR than real-time EDR, but excellent for understanding what artifacts the malware leaves

### WHIDS (Windows Host IDS)
- **Type**: Open-source host IDS (GPLv3)
- **Windows agent**: Yes — Sysmon-powered, Go binary
- **Detection capabilities**: Sysmon event correlation, Sigma rule matching, process anomaly detection
- **Server**: Optional central manager (WHIDS manager)
- **Detection check method**: Alert log files (JSON), or manager API
- **Note**: Lightweight but depends entirely on Sysmon quality

---

## 2. Commercial EDRs (Free Trials)

| EDR | Trial Length | Agent Type | Notes |
|-----|-------------|------------|-------|
| CrowdStrike Falcon Go | 15 days | Kernel sensor | Most aggressive behavioral detection. Hard to automate (cloud dashboard) |
| Sophos Intercept X | 30 days | Endpoint agent | Good behavioral + ML. Sophos Central API available |
| Carbon Black (VMware) | 14 days | Sensor | Process tree analysis. CB Response API for queries |
| Microsoft Defender for Endpoint | 90 days (E5 trial) | Built-in | Already have base Defender. MDE adds cloud analytics + AMSI telemetry |
| Bitdefender GravityZone | 30 days | Endpoint agent | Strong ML detection. API available |

**Strategy**: Rotate through trials. Set up a fresh VM overlay for each, install the agent, run the test suite, capture results before trial expires.

---

## 3. Framework Architecture Changes

### New: EDRConfig dataclass

```python
@dataclass
class EDRConfig:
    name: str                    # "wazuh", "elastic", "defender", etc.
    vm_overlay: str              # Path to qcow2 overlay with this EDR pre-installed
    agent_type: str              # "wazuh-agent", "elastic-agent", "openedr", etc.
    detection_api: str           # API endpoint or log path for detection checks
    detection_method: str        # "rest_api", "elasticsearch", "log_file", "ssh_command"
    api_auth: dict               # Auth credentials for the detection API
    alert_query: str             # Query template for checking if malware was detected
    severity_threshold: str      # Minimum severity to count as "detected"
    setup_script: Optional[str]  # Script to run on VM before each test (restart agent, etc.)
```

### Changes to pipeline.py

```python
class MalwarePipeline:
    def __init__(self, ..., edr_configs: list[EDRConfig] = None):
        self._edr_configs = edr_configs or [EDRConfig(name="defender", ...)]

    async def run(self, ...):
        # Generate malware once
        source_code = await self._generate(...)

        # Test against each EDR
        results = {}
        for edr in self._edr_configs:
            # Switch VM to this EDR's overlay
            await self._vm.switch_overlay(edr.vm_overlay)
            await self._vm.boot()

            # Deploy and verify
            result = await self._verifier.verify(source_code, edr=edr)
            results[edr.name] = result

            # Snapshot back to clean state
            await self._vm.reset_overlay()

        return results
```

### Changes to verifier.py

```python
class Verifier:
    async def _check_edr_detection(self, edr: EDRConfig) -> bool:
        """Query the EDR's API/logs to check if malware was detected."""
        if edr.detection_method == "rest_api":
            # Wazuh, Sophos, etc.
            resp = await self._http_get(edr.detection_api, auth=edr.api_auth)
            alerts = resp.json().get("data", {}).get("affected_items", [])
            return len(alerts) > 0

        elif edr.detection_method == "elasticsearch":
            # Elastic Security
            resp = await self._http_get(
                f"{edr.detection_api}/.alerts-security*/_search",
                params={"q": f"host.name:{self._vm_hostname}"},
                auth=edr.api_auth,
            )
            return resp.json()["hits"]["total"]["value"] > 0

        elif edr.detection_method == "log_file":
            # OpenEDR, WHIDS — parse JSON log on VM via SSH
            stdout = await self._ssh_exec(f"type {edr.detection_api}")
            return '"alert"' in stdout or '"detection"' in stdout

        elif edr.detection_method == "ssh_command":
            # Custom command (e.g., check Defender via PowerShell)
            stdout = await self._ssh_exec(edr.alert_query)
            return "ThreatDetected" in stdout or "detected" in stdout.lower()
```

### Changes to provision_engine.py

```python
class ProvisionEngine:
    async def create_edr_overlay(self, base_snapshot: str, edr: EDRConfig) -> str:
        """Create a VM overlay with an EDR agent pre-installed."""
        overlay_path = f"{self._vm_dir}/{edr.name}_overlay.qcow2"

        # Create overlay from base
        await self._qemu_img("create", "-f", "qcow2", "-b", base_snapshot,
                             "-F", "qcow2", overlay_path)

        # Boot overlay, install EDR agent via SSH
        await self._vm.boot(overlay=overlay_path)
        await self._vm.wait_ssh()

        if edr.agent_type == "wazuh-agent":
            await self._ssh_exec(
                f'msiexec /i wazuh-agent.msi /q '
                f'WAZUH_MANAGER="{edr.detection_api.split("/")[2]}" '
                f'WAZUH_REGISTRATION_SERVER="{edr.detection_api.split("/")[2]}"'
            )
        elif edr.agent_type == "elastic-agent":
            await self._ssh_exec(
                f'elastic-agent.exe install --url={edr.detection_api} '
                f'--enrollment-token={edr.api_auth.get("token", "")}'
            )

        # Shutdown and snapshot — this overlay is now the "clean with EDR" state
        await self._vm.shutdown()
        return overlay_path
```

---

## 4. VM Snapshot Strategy

Uses blockdev-snapshot-sync overlays (per user preference — never savevm/loadvm):

```
base_windows11.qcow2  (pristine Windows 11 + SSH + canary files)
├── defender_overlay.qcow2   (base Defender only — current default)
├── wazuh_overlay.qcow2      (Wazuh agent enrolled to local manager)
├── elastic_overlay.qcow2    (Elastic Agent enrolled to local Fleet)
├── openedr_overlay.qcow2    (OpenEDR agent + driver installed)
└── velociraptor_overlay.qcow2 (Velociraptor client configured)
```

Each test run:
1. `blockdev-snapshot-sync` from the EDR overlay → creates a throwaway layer
2. Boot, deploy malware, run verification
3. Discard throwaway layer → back to clean EDR overlay

---

## 5. Implementation Priority

| Priority | Task | Effort |
|----------|------|--------|
| P1 | Wazuh server Docker setup + Windows agent overlay | 2-3 hours |
| P2 | EDRConfig dataclass + pipeline multi-EDR loop | 2-3 hours |
| P3 | Wazuh detection check (REST API) in verifier.py | 1-2 hours |
| P4 | Elastic Security Docker setup + agent overlay | 2-3 hours |
| P5 | Elastic detection check (ES query) in verifier.py | 1-2 hours |
| P6 | OpenEDR agent overlay + log-based detection check | 1-2 hours |
| P7 | Pipeline report: per-EDR detection matrix | 1 hour |
| P8 | Commercial trial rotation (CrowdStrike, Sophos) | 3-4 hours each |

**Recommended starting point**: Wazuh (P1-P3). It's fully free, has the best API, and covers the widest range of detection types. Once the multi-EDR framework loop works with Wazuh + Defender, adding more EDRs is incremental.

---

## 6. Expected Detection Surface Coverage

| Detection Type | Defender | Wazuh | Elastic | OpenEDR | Velociraptor |
|----------------|----------|-------|---------|---------|-------------|
| Static signatures | Yes | No | YARA | No | YARA |
| Behavioral (process trees) | Yes | Via Sysmon | Yes | Yes | VQL |
| File integrity | No | Yes | Yes | Yes | Yes |
| Network telemetry | Basic | Yes | Yes | Yes | VQL |
| Memory scanning | Yes (AMSI) | No | No | No | Yes |
| ML/heuristic | Yes | No | Yes (free tier) | No | No |

Testing against all five free EDRs gives coverage of every major detection methodology without spending a cent.
