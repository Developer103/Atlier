"""Checkpoint/resume support for crash recovery during long pipeline runs."""

import json
import logging
import os
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CheckpointState:
    spec_path: str
    output_dir: str
    created_at: str
    run_mode: str
    llm_url: str
    llm_model: str
    max_iterations: int
    completed_iterations: int
    iteration_history: list[dict] = field(default_factory=list)
    last_analysis: Optional[dict] = None
    failure_history: list[str] = field(default_factory=list)
    current_permissions: str = "user"
    compile_fix_streak: int = 0
    current_source: str = ""
    plan: Optional[dict] = None
    vm_port: int = 10022
    vm_user: str = "vmuser"
    vm_pass: str = "vmuser123"
    validation_plan: Optional[dict] = None
    language: str = "c"
    chunk_cache: dict = field(default_factory=dict)


class CheckpointManager:
    _FILENAME = "checkpoint.json"

    def __init__(self, output_dir: Path):
        self._dir = output_dir
        self._path = output_dir / self._FILENAME

    def has_checkpoint(self) -> bool:
        return self._path.exists()

    def save(self, state: CheckpointState) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)
        data = asdict(state)
        fd, tmp = tempfile.mkstemp(dir=str(self._dir), suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, str(self._path))
            logger.debug("Checkpoint saved (%d iterations completed)", state.completed_iterations)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def load(self) -> CheckpointState:
        data = json.loads(self._path.read_text())
        return CheckpointState(**data)

    def clear(self) -> None:
        if self._path.exists():
            self._path.unlink()
            logger.info("Checkpoint cleared (pipeline completed successfully)")
