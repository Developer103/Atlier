#!/usr/bin/env python3
"""Standalone portal launcher."""
import sys
import asyncio
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from portal.app import create_app
from aiohttp import web

async def main():
    host = "0.0.0.0"
    port = 7070

    # Parse simple args
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg in ("--host", "-h") and i + 1 < len(args):
            host = args[i + 1]
        elif arg in ("--port", "-p") and i + 1 < len(args):
            port = int(args[i + 1])

    app = create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()

    print(f"\n  Atelier Portal running at  http://{host}:{port}")
    print("  Press Ctrl-C to stop.\n")

    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        await runner.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
