"""Hermes — AI-driven malware campaign orchestrator.

Usage:
    # CLI
    python -m hermes --target-edr crowdstrike --malware-type infostealer

    # Python API
    from hermes import Hermes, run_session

    result = asyncio.run(run_session(
        {"edr": "crowdstrike", "malware_type": "infostealer"},
    ))
"""

from .orchestrator import Hermes, HermesSession, run_session

__all__ = ["Hermes", "HermesSession", "run_session"]
