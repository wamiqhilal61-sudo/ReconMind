"""core/reporting/cli_reporter.py — Base CLI reporting for wamiqsec/ReconMind."""

import sys
from datetime import datetime
from typing import List, Dict, Any

from config.settings import CONFIG
from core.utils.logger import get_logger

log = get_logger(__name__)


class Color:
    RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
    RED, YELLOW, GREEN, CYAN, BLUE, MAGENTA, WHITE, GRAY = (
        "\033[91m", "\033[93m", "\033[92m", "\033[96m",
        "\033[94m", "\033[95m", "\033[97m", "\033[90m",
    )


def _should_use_color() -> bool:
    return CONFIG.reporting.use_color and sys.stdout.isatty()


def _c(text: str, *codes: str) -> str:
    if not _should_use_color():
        return text
    return "".join(codes) + text + Color.RESET


def print_banner() -> None:
    banner = r"""
 __      __                   _                         
 \ \    / /__ _ _ __ ___  (_) __ _  ___  ___ ___  ___ 
  \ \  / / _` | '_ ` _ \ | |/ _` |/ __|/ _ / __|/ __|
   \ \/ / (_| | | | | | || | (_| |\__ \  __/ (__ \__ \
    \__/ \__,_|_| |_| |_|/ |\__, ||___/\___|\___|___/
                        |__/ |___/                    
      ____                     __  __ _           _   
     |  _ \ ___  ___ ___  _ __ |  \/  (_)_ __   __| |  
     | |_) / _ \/ __/ _ \| '_ \| |\/| | | '_ \ / _` |  
     |  _ <  __/ (_| (_) | | | | |  | | | | | | (_| |  
     |_| \_\___|\___\___/|_| |_|_|  |_|_|_| |_|\__,_|  

      by wamiqsec  ·  Phase 5  ·  Context-Aware Exploitability
    """
    print(_c(banner, Color.CYAN, Color.BOLD))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(_c(f"  Session started: {timestamp}", Color.DIM))
    print(_c("  For authorized security testing and educational use only.\n", Color.YELLOW))


def print_scan_summary(targets: List, all_findings: List, elapsed_seconds: float) -> None:
    print(_c(f"\n  {'='*70}", Color.BLUE))
    print(_c("  SCAN COMPLETE", Color.BLUE, Color.BOLD))
    print(_c(f"  {'='*70}\n", Color.BLUE))
    print(f"  Targets scanned: {len(targets)}")
    print(f"  Total findings:  {len(all_findings)}")
    print(f"  Time elapsed:    {elapsed_seconds:.2f}s\n")
