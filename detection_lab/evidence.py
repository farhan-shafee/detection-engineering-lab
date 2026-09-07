"""Evidence integrity and deliberately lossy publication sanitization."""

import hashlib
from pathlib import Path, PureWindowsPath

from .engine import CHANNELS
from .io import load_json, repository, safe_path

MANIFEST = "evidence/fixtures/manifest.json"


def build_manifest(root: Path | None = None) -> dict:
    root = repository(root)
    paths = {root / "detections/catalog.json"}
    for pattern in (
        "fixtures/*.json",
        "sigma-rules/*.yml",
        "evidence/investigations/*.json",
        "evidence/investigations/*.md",
        "evidence/tuning/*.yml",
        "evidence/tuning/*.json",
        "evidence/tuning/*.md",
        "logs/**/*.json",
    ):
        paths.update(root.glob(pattern))
    files = []
    for path in sorted(paths, key=lambda p: p.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        data = safe_path(root, relative).read_bytes()
        # Canonical LF hashes survive Git's Windows checkout newline conversion.
        data = data.replace(b"\r\n", b"\n")
        files.append(
            {"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        )
    return {
        "schema_version": 1,
        "provenance": "DETERMINISTIC fixtures and SIMULATED analyst decisions; no live capture",
        "hash_algorithm": "sha256 of UTF-8 file bytes with CRLF normalized to LF",
        "files": files,
    }


def check_manifest(root: Path | None = None) -> None:
    root = repository(root)
    manifest = load_json(safe_path(root, MANIFEST))
    if manifest != build_manifest(root):
        raise ValueError(
            "Evidence manifest integrity mismatch; review source changes before refreshing"
        )


def sanitize_event(event: dict) -> dict:
    """Publication summary only: discard command content, raw XML and unknown fields.

    This intentionally cannot preserve detection semantics. Keep raw evidence locally
    and manually review the summary before publishing; do not treat it as anonymization.
    """
    if not isinstance(event, dict):
        raise ValueError("Expected normalized event object")
    event_id = event.get("EventID")
    if type(event_id) is not int or event_id not in CHANNELS:
        raise ValueError("Unsupported normalized event ID")
    from .engine import event_time

    try:
        timestamp = event_time(event).isoformat()
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise ValueError("Invalid normalized timestamp") from None
    summary = {
        "EventID": event_id,
        "Channel": CHANNELS[event_id],
        "timestamp": timestamp,
        "Computer": "LAB-HOST",
        "record_id": "redacted-record",
        "provenance": "sanitized summary; source authenticity not verified",
    }
    for field in (
        "User",
        "TargetUserName",
        "TargetDomainName",
        "SubjectUserName",
        "MemberSid",
        "TargetSid",
        "TaskName",
    ):
        if field in event:
            summary[field] = "[REDACTED]"
    for field in ("CommandLine", "TaskContent"):
        if field in event:
            summary[field] = "[REDACTED: inspect original locally]"
    if "IpAddress" in event:
        summary["IpAddress"] = "198.51.100.10"
    allowed_images = {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "explorer.exe",
        "winword.exe",
        "excel.exe",
        "outlook.exe",
    }
    for field in ("Image", "ParentImage"):
        if field in event:
            basename = PureWindowsPath(str(event[field])).name.lower()
            summary[field] = basename if basename in allowed_images else "[REDACTED]"
    return summary
