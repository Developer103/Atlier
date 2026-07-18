"""Hermes configuration defaults."""

from pathlib import Path

_BASE = Path(__file__).parent.parent

DEFAULT_CONFIG = {
    "llm_url": "http://localhost:11235",
    "llm_model": "huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-mtp",
    "vm_host": "localhost",
    "vm_port": 10022,
    "vm_user": "vmuser",
    "vm_pass": "vmuser123",
    "c2_default_port": 9001,
    "assembler_path": str(_BASE / "templates" / "chunks" / "assembler.py"),
    "chunks_dir": str(_BASE / "templates" / "chunks"),
    "recipes_dir": str(_BASE / "templates" / "chunks" / "recipes"),
    "results_dir": str(_BASE / "results"),
    "knowledge_db_path": str(_BASE / "hermes_knowledge.json"),
    "max_rounds": 999999,
    "batch_size": 3,
    "innovation_threshold": 100,
    "c2_listen_host": "0.0.0.0",
    "ssh_timeout": 30,
    "llm_max_tokens": 4096,
    "llm_temperature": 0.7,
    "llm_context_tokens": 65000,
}


def get_config(overrides: dict | None = None) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if overrides:
        cfg.update(overrides)
    return cfg
