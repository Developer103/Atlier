"""CLI entry point — allows running as ``python -m malware_gen_framework``."""
import sys
from malware_gen_framework.cli import main

sys.exit(main() or 0)
