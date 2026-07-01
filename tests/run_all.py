#!/usr/bin/env python3
"""Run the complete test suite with colored output and summary.

Usage:
  python3 tests/run_all.py              # all tests
  python3 tests/run_all.py unit         # unit tests only
  python3 tests/run_all.py integration  # integration only
  python3 tests/run_all.py vm           # VM tests only
  python3 tests/run_all.py e2e          # E2E tests only
  python3 tests/run_all.py quick        # unit + integration (no VM/LLM needed)
"""
import os
import subprocess
import sys
from pathlib import Path


def main():
    test_dir = Path(__file__).parent
    project_dir = test_dir.parent
    os.chdir(str(project_dir))

    args = ["python3", "-m", "pytest", str(test_dir), "-v", "--tb=short", "--color=yes"]

    if len(sys.argv) > 1:
        tier = sys.argv[1]
        if tier == "quick":
            args.extend(["-m", "unit or integration"])
        elif tier in ("unit", "integration", "vm", "e2e"):
            args.extend(["-m", tier])
        else:
            args.extend(sys.argv[1:])

    result = subprocess.run(args)
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
