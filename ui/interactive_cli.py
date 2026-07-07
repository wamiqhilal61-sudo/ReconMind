"""
ui/interactive_cli.py
======================
Interactive CLI menu for wamiqsec-ReconMind.

Why this file exists:
    Not every user wants to memorize CLI flags. The interactive mode
    walks the user through a scan configuration with menus, shows
    the available modules, lets them toggle options, enter targets,
    and launch scans — all without consulting the README.

    This is also the UI layer for when ReconMind is used as a learning
    tool: students can see every option explained before enabling it.

Trigger:
    python main.py --interactive
    OR
    python ui/interactive_cli.py

Design:
    Pure stdin/stdout — no curses, no external TUI library.
    Works on any terminal, including Windows CMD, PowerShell, Kali xterm.
"""

import sys
import os
import subprocess
from typing import List, Optional, Dict

# Add parent directory to path so we can import config
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import CONFIG


# ---------------------------------------------------------------------------
# ANSI colors (duplicated here to keep ui/ self-contained)
# ---------------------------------------------------------------------------

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"


def _use_color() -> bool:
    return sys.stdout.isatty()


def c(text: str, *codes: str) -> str:
    if not _use_color():
        return text
    return "".join(codes) + text + C.RESET


def clear():
    """Clear the terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
 __      __                   _                         
 \ \    / /_ _ _ __ ___ (_) __ _  ___  ___ ___  ___ 
  \ \  / / _` | '_ ` _ \| |/ _` |/ __|/ _ / __|/ __|
   \ \/ / (_| | | | | | | | (_| |\__ \  __/ (__ \__ \
    \__/ \__,_|_| |_| |_|_|\__, ||___/\___|\___|___/
                             |___/                    
     ____                     __  __ _           _   
    |  _ \ ___  ___ ___  _ __ |  \/  (_)_ __   __| |  
    | |_) / _ \/ __/ _ \| '_ \| |\/| | | '_ \ / _` |  
    |  _ <  __/ (_| (_) | | | | |  | | | | | | (_| |  
    |_| \_\___|\___\___/|_| |_|_|  |_|_|_| |_|\__,_|  

         by wamiqsec  |  Phase 2  |  Intelligent Bug Hunting
"""


def print_banner():
    print(c(BANNER, C.CYAN, C.BOLD))
    print(c(
        "  ⚠  FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL USE ONLY\n",
        C.YELLOW, C.BOLD
    ))


# ---------------------------------------------------------------------------
# Menu helpers
# ---------------------------------------------------------------------------

def print_section(title: str):
    print(c(f"\n  {'─' * 60}", C.BLUE))
    print(c(f"  {title}", C.BOLD, C.WHITE))
    print(c(f"  {'─' * 60}", C.BLUE))


def prompt(text: str, default: str = "") -> str:
    """Prompt user for input with a default value."""
    default_hint = f" [{c(default, C.CYAN)}]" if default else ""
    try:
        val = input(f"  {c('▶', C.GREEN)} {text}{default_hint}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n  Aborted.")
        sys.exit(0)
    return val if val else default


def confirm(text: str, default: bool = True) -> bool:
    """Yes/No confirmation prompt."""
    hint = c("Y/n", C.GREEN) if default else c("y/N", C.YELLOW)
    try:
        val = input(f"  {c('?', C.YELLOW)} {text} [{hint}]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return default
    if not val:
        return default
    return val in ("y", "yes", "1")


def menu(title: str, options: List[Dict]) -> Optional[Dict]:
    """
    Display a numbered menu and return the selected option dict.

    Args:
        title:   Menu section title.
        options: List of {key, label, description} dicts.

    Returns:
        Selected option dict, or None if user exits.
    """
    print_section(title)
    for i, opt in enumerate(options, 1):
        key_str = c(f"[{i}]", C.CYAN, C.BOLD)
        label_str = c(opt["label"], C.WHITE, C.BOLD)
        desc_str = c(f"  — {opt.get('description', '')}", C.DIM)
        print(f"    {key_str} {label_str}{desc_str}")

    print(c(f"\n    [0] Back / Exit", C.DIM))
    print()

    try:
        choice = input(c("  ▶ Select option: ", C.GREEN)).strip()
    except (EOFError, KeyboardInterrupt):
        return None

    if choice == "0" or not choice:
        return None

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(options):
            return options[idx]
    except ValueError:
        pass

    print(c("  Invalid selection.", C.RED))
    return None


# ---------------------------------------------------------------------------
# Scan configuration builder
# ---------------------------------------------------------------------------

class ScanConfig:
    """Holds all options the user configures through the interactive menu."""

    def __init__(self):
        self.target_url: str = ""
        self.target_file: str = ""
        self.proxy: str = ""
        self.timeout: int = 15
        self.debug: bool = False
        self.no_color: bool = False

        # Module toggles
        self.run_xss: bool = True
        self.run_redirect: bool = True
        self.run_lfi: bool = True
        self.run_ssrf: bool = True
        self.run_idor: bool = True
        self.waf_bypass: bool = False
        self.phase1_only: bool = False

        # Output
        self.save_json: bool = True
        self.save_markdown: bool = True
        self.no_db: bool = False

    def to_cli_args(self) -> List[str]:
        """
        Convert config to a list of CLI arguments for subprocess call.

        Returns:
            List of strings compatible with main.py's argparser.
        """
        args = []

        if self.target_url:
            args += ["-u", self.target_url]
        elif self.target_file:
            args += ["-f", self.target_file]

        if self.proxy:
            args += ["--proxy", self.proxy]

        if self.timeout != 15:
            args += ["--timeout", str(self.timeout)]

        if self.debug:
            args.append("--debug")

        if self.no_color:
            args.append("--no-color")

        if not self.run_xss:
            args.append("--skip-xss")
        if not self.run_redirect:
            args.append("--skip-redirect")
        if not self.run_lfi:
            args.append("--skip-lfi")
        if not self.run_ssrf:
            args.append("--skip-ssrf")
        if not self.run_idor:
            args.append("--skip-idor")

        if self.waf_bypass:
            args.append("--waf-bypass")

        if self.phase1_only:
            args.append("--phase1-only")

        if self.save_json:
            args.append("--save-json")
        if self.save_markdown:
            args.append("--save-markdown")

        if self.no_db:
            args.append("--no-db")

        return args

    def summary(self) -> str:
        """Return a human-readable summary of the current configuration."""
        lines = [
            c("\n  ── Scan Configuration ──────────────────────────────────────", C.BLUE),
            f"  Target:      {c(self.target_url or self.target_file or 'not set', C.YELLOW)}",
            f"  Proxy:       {self.proxy or c('none', C.DIM)}",
            f"  Timeout:     {self.timeout}s",
            f"  Debug:       {c('ON', C.GREEN) if self.debug else c('off', C.DIM)}",
            "",
            c("  Modules:", C.BOLD),
            f"    XSS Payloads:    {c('ON', C.GREEN) if self.run_xss else c('SKIP', C.YELLOW)}",
            f"    Open Redirects:  {c('ON', C.GREEN) if self.run_redirect else c('SKIP', C.YELLOW)}",
            f"    LFI / Traversal: {c('ON', C.GREEN) if self.run_lfi else c('SKIP', C.YELLOW)}",
            f"    SSRF:            {c('ON', C.GREEN) if self.run_ssrf else c('SKIP', C.YELLOW)}",
            f"    IDOR:            {c('ON', C.GREEN) if self.run_idor else c('SKIP', C.YELLOW)}",
            f"    WAF Bypass:      {c('ON', C.YELLOW) if self.waf_bypass else c('off', C.DIM)}",
            f"    Phase 1 Only:    {c('ON', C.CYAN) if self.phase1_only else c('off', C.DIM)}",
            "",
            c("  Output:", C.BOLD),
            f"    JSON Report:     {c('ON', C.GREEN) if self.save_json else c('off', C.DIM)}",
            f"    Markdown Report: {c('ON', C.GREEN) if self.save_markdown else c('off', C.DIM)}",
            f"    Database:        {c('SKIP', C.YELLOW) if self.no_db else c('ON', C.GREEN)}",
        ]
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Interactive menu screens
# ---------------------------------------------------------------------------

def screen_target(cfg: ScanConfig):
    """Screen: choose target type and enter URL or file path."""
    print_section("TARGET CONFIGURATION")

    choice = menu("How do you want to specify the target?", [
        {"label": "Single URL",   "description": "Test one URL directly"},
        {"label": "URL File",     "description": "Load multiple URLs from a .txt file"},
    ])

    if not choice:
        return

    if choice["label"] == "Single URL":
        url = prompt("Enter target URL", "https://example.com/search?q=test")
        if url:
            cfg.target_url = url
            cfg.target_file = ""
            print(c(f"\n  Target set: {url}", C.GREEN))

    elif choice["label"] == "URL File":
        filepath = prompt("Enter path to URL file", "targets.txt")
        if filepath:
            cfg.target_file = filepath
            cfg.target_url = ""
            print(c(f"\n  File set: {filepath}", C.GREEN))


def screen_modules(cfg: ScanConfig):
    """Screen: toggle Phase 2 modules on/off."""
    print_section("MODULE CONFIGURATION")

    print(c("  Phase 1 (always runs):", C.DIM))
    print(f"    {c('✓', C.GREEN)} Parameter Extraction")
    print(f"    {c('✓', C.GREEN)} Reflection Probing")
    print(f"    {c('✓', C.GREEN)} Context Analysis + Risk Scoring")

    print(c("\n  Phase 2 modules (toggle below):", C.BOLD))

    modules = [
        ("XSS Payload Testing",     "run_xss",      "Context-aware XSS payloads (Tier 1-3)"),
        ("Open Redirect Testing",   "run_redirect",  "Detect unvalidated redirects"),
        ("LFI / Path Traversal",    "run_lfi",       "Test file include parameters"),
        ("SSRF Testing",            "run_ssrf",      "Cloud metadata + internal service probes"),
        ("IDOR Detection",          "run_idor",      "Numeric/UUID parameter enumeration"),
        ("WAF Bypass Payloads",     "waf_bypass",    "Tier 3 obfuscated payloads (slower)"),
        ("Phase 1 Only",            "phase1_only",   "Skip all Phase 2 modules"),
    ]

    for name, attr, desc in modules:
        current = getattr(cfg, attr, False)
        status = c("ON ", C.GREEN) if current else c("OFF", C.YELLOW)
        print(f"    [{status}] {c(name, C.WHITE)} — {c(desc, C.DIM)}")

    print()
    toggle = prompt("Toggle a module (enter name or press Enter to continue)", "")
    if not toggle:
        return

    toggle_lower = toggle.lower()
    for name, attr, _ in modules:
        if toggle_lower in name.lower():
            current = getattr(cfg, attr, False)
            setattr(cfg, attr, not current)
            new_val = getattr(cfg, attr)
            print(c(f"\n  {name}: {'ON' if new_val else 'OFF'}", C.GREEN))
            return

    print(c("  Module not recognized.", C.YELLOW))


def screen_network(cfg: ScanConfig):
    """Screen: configure network options."""
    print_section("NETWORK CONFIGURATION")

    print(f"  Current timeout: {c(str(cfg.timeout) + 's', C.CYAN)}")
    print(f"  Current proxy:   {c(cfg.proxy or 'none', C.CYAN)}")
    print()

    timeout_str = prompt("Request timeout (seconds)", str(cfg.timeout))
    try:
        cfg.timeout = int(timeout_str)
    except ValueError:
        pass

    proxy = prompt("Proxy URL (e.g. http://127.0.0.1:8080, leave empty to skip)", cfg.proxy)
    cfg.proxy = proxy

    cfg.debug = confirm("Enable debug logging?", cfg.debug)


def screen_output(cfg: ScanConfig):
    """Screen: configure output and reporting options."""
    print_section("OUTPUT CONFIGURATION")

    print(f"  Reports will be saved to: {c('reports/', C.CYAN)}")
    print()

    cfg.save_json = confirm("Save JSON report?", cfg.save_json)
    cfg.save_markdown = confirm("Save Markdown report?", cfg.save_markdown)
    cfg.no_db = not confirm("Save findings to SQLite database?", not cfg.no_db)
    cfg.no_color = not confirm("Use colored output?", not cfg.no_color)


def screen_query():
    """Screen: query the findings database."""
    print_section("QUERY SAVED FINDINGS")

    severity = prompt("Filter by severity (HIGH/MEDIUM/LOW/CRITICAL, leave empty for all)", "")
    module = prompt("Filter by module (XSS/LFI/SSRF/REDIRECT/IDOR, leave empty for all)", "")
    host = prompt("Filter by host (e.g. example.com, leave empty for all)", "")

    args = [sys.executable, "main.py", "--query"]
    if severity:
        args += ["--query-severity", severity]
    if module:
        args += ["--query-module", module]
    if host:
        args += ["--query-host", host]

    print(c(f"\n  Running: {' '.join(args[2:])}\n", C.DIM))
    try:
        subprocess.run(args)
    except FileNotFoundError:
        print(c("  Error: main.py not found. Run from the ReconMind root directory.", C.RED))


# ---------------------------------------------------------------------------
# Main interactive loop
# ---------------------------------------------------------------------------

def run_interactive():
    """
    Main interactive menu loop for wamiqsec-ReconMind.

    The loop continues until the user chooses to exit or launches a scan.
    """
    clear()
    print_banner()

    cfg = ScanConfig()

    main_options = [
        {"label": "Set Target",          "description": "Enter URL or file path"},
        {"label": "Configure Modules",   "description": "Toggle Phase 2 vulnerability modules"},
        {"label": "Network Settings",    "description": "Proxy, timeout, debug mode"},
        {"label": "Output Settings",     "description": "JSON, Markdown, database options"},
        {"label": "Review Config",       "description": "Show current scan configuration"},
        {"label": "Launch Scan",         "description": "Start the scan with current configuration"},
        {"label": "Query Database",      "description": "Browse previously saved findings"},
        {"label": "Exit",                "description": ""},
    ]

    while True:
        selected = menu("MAIN MENU — wamiqsec ReconMind", main_options)

        if selected is None or selected["label"] == "Exit":
            print(c("\n  Goodbye. Happy hunting.\n", C.CYAN))
            sys.exit(0)

        label = selected["label"]

        if label == "Set Target":
            screen_target(cfg)

        elif label == "Configure Modules":
            screen_modules(cfg)

        elif label == "Network Settings":
            screen_network(cfg)

        elif label == "Output Settings":
            screen_output(cfg)

        elif label == "Review Config":
            print(cfg.summary())
            input(c("\n  Press Enter to continue...", C.DIM))

        elif label == "Launch Scan":
            if not cfg.target_url and not cfg.target_file:
                print(c("\n  No target set. Please configure a target first.", C.RED))
                continue

            print(cfg.summary())
            print()

            if not confirm("Launch scan with this configuration?", True):
                continue

            cli_args = cfg.to_cli_args()
            cmd = [sys.executable, "main.py"] + cli_args

            print(c(f"\n  Executing: python main.py {' '.join(cli_args)}\n", C.DIM))
            print(c("  " + "═" * 68 + "\n", C.BLUE))

            try:
                subprocess.run(cmd)
            except FileNotFoundError:
                print(c("  Error: main.py not found. Run from the ReconMind root directory.", C.RED))
            except KeyboardInterrupt:
                print(c("\n  Scan interrupted.", C.YELLOW))

            input(c("\n  Scan complete. Press Enter to return to menu...", C.DIM))

        elif label == "Query Database":
            screen_query()
            input(c("\n  Press Enter to continue...", C.DIM))


if __name__ == "__main__":
    run_interactive()
