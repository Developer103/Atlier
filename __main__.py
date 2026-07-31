"""CLI entry point — allows running as ``python -m atelier``."""
import sys
from atelier.cli import main

sys.exit(main() or 0)
