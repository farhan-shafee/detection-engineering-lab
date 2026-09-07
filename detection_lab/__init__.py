"""Deterministic, defensive detection engineering lab."""

from .engine import event_valid, match_events
from .evidence import sanitize_event
from .model import load_catalog, load_yaml, repository, safe_path, validate_repository
from .reporting import render_report, run_demo

__all__ = [
    "event_valid",
    "match_events",
    "sanitize_event",
    "load_catalog",
    "load_yaml",
    "repository",
    "safe_path",
    "validate_repository",
    "render_report",
    "run_demo",
]
