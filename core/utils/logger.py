"""core/utils/logger.py — Centralized logging factory for wamiqsec/ReconMind."""

import logging
import sys
from pathlib import Path

from config.settings import CONFIG


def _configure_root_logger() -> None:
    cfg = CONFIG.logging
    level = getattr(logging, cfg.level.upper(), logging.INFO)
    formatter = logging.Formatter(cfg.log_format)

    root = logging.getLogger("reconmind")
    root.setLevel(level)

    if root.handlers:
        root.setLevel(level)
        return

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)

    if cfg.log_to_file:
        log_path = Path(cfg.log_file_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced child logger under 'reconmind'."""
    _configure_root_logger()
    return logging.getLogger(f"reconmind.{name}")
