"""Small, explicit repository guardrails; complements Bandit and pip-audit.

This is not a general secret detector or a substitute for reviewing evidence before
publication. Findings print paths and rule names only, never the matched value.
It works from an exported checkout and never invokes a shell or reads Git internals.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {
    ".git",
    ".venv",
    ".lab",
    ".local",
    ".ruff_cache",
    ".pytest_cache",
    "__pycache__",
    "node_modules",
}
TEXT_SUFFIXES = {".md", ".py", ".ps1", ".json", ".yaml", ".yml", ".xml", ".toml", ".txt"}
SECRET_PATTERNS = {
    "private key material": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "GitHub credential": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[\w]{50,})\b"),
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "Slack credential": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"),
}
POWERSHELL_PATTERNS = {
    "dynamic PowerShell evaluation": re.compile(r"(?im)^\s*(?:Invoke-Expression|iex)\b"),
    "Defender disabling or exclusion": re.compile(
        r"(?i)\b(?:Set|Add)-MpPreference\b[^\r\n]*(?:-Disable\w+|-Exclusion\w+)"
    ),
    "download-to-evaluation primitive": re.compile(r"(?i)\bDownloadString\s*\("),
    "unrestricted execution policy mutation": re.compile(r"(?i)\bSet-ExecutionPolicy\b"),
}


def workflow_findings(data: object) -> list[str]:
    """Keep all workflow scopes read-only and third-party actions immutable."""
    findings: list[str] = []
    if not isinstance(data, dict):
        return ["workflow must be a mapping"]
    triggers = data.get("on", data.get(True, {}))  # PyYAML's YAML 1.1 boolean key.
    if isinstance(triggers, str):
        triggers = [triggers]
    if isinstance(triggers, (dict, list)) and "pull_request_target" in triggers:
        findings.append("privileged pull_request_target trigger")
    if data.get("permissions") != {"contents": "read"}:
        findings.append("workflow must declare only contents: read")
    jobs = data.get("jobs", {})
    if not isinstance(jobs, dict):
        return findings + ["workflow jobs must be a mapping"]
    for job in jobs.values():
        if not isinstance(job, dict):
            findings.append("workflow job must be a mapping")
            continue
        permissions = job.get("permissions", {})
        if not isinstance(permissions, dict) or any(
            value != "read" for value in permissions.values()
        ):
            findings.append("job requests elevated permissions")
        for step in job.get("steps", []):
            if not isinstance(step, dict) or "uses" not in step:
                continue
            action = str(step["uses"])
            if not action.startswith("./") and not re.fullmatch(r"[^@]+@[a-f0-9]{40}", action):
                findings.append("action is not pinned to a full commit SHA")
            if (
                action.startswith("actions/checkout@")
                and step.get("with", {}).get("persist-credentials") is not False
            ):
                findings.append("checkout persists credentials")
    return findings


def scan_file(path: Path, relative: Path) -> list[str]:
    """Inspect source/configuration without exposing potential secrets in output."""
    findings: list[str] = []
    if path.is_symlink():
        return ["symlink requires explicit review"]
    if path.suffix.lower() in {".pem", ".key", ".p12", ".pfx", ".evtx"}:
        return ["private material or raw live telemetry must not be published"]
    if path.name == ".env" or (path.name.startswith(".env.") and path.name != ".env.example"):
        return ["local environment file must not be published"]
    if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {".env.example", "Makefile"}:
        return findings
    try:
        content = path.read_text(encoding="utf-8-sig")
    except (UnicodeError, OSError):
        return ["source/configuration file is not readable UTF-8"]
    for name, pattern in SECRET_PATTERNS.items():
        if pattern.search(content):
            findings.append(name)
    if path.suffix.lower() == ".ps1":
        active = "\n".join(
            line for line in content.splitlines() if not line.lstrip().startswith("#")
        )
        for name, pattern in POWERSHELL_PATTERNS.items():
            if pattern.search(active):
                findings.append(name)
    if relative.parts[:2] == (".github", "workflows"):
        try:
            findings.extend(workflow_findings(yaml.safe_load(content)))
        except yaml.YAMLError:
            findings.append("workflow YAML cannot be parsed safely")
    if path.suffix.lower() in {".yml", ".yaml"} and "compose" in path.name.lower():
        for name, pattern in {
            "privileged container": r"(?im)^\s*privileged:\s*true\s*$",
            "host networking": r"(?im)^\s*network_mode:\s*['\"]?host['\"]?\s*$",
            "Docker socket mount": r"/var/run/docker\.sock",
            "all-interface binding": r"0\.0\.0\.0:",
        }.items():
            if re.search(pattern, content):
                findings.append(name)
    return findings


def scan_repository(root: Path) -> tuple[int, list[str]]:
    """Scan publishable files; local Wazuh runtime/private evidence stay excluded."""
    root = root.resolve()
    findings: list[str] = []
    count = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        directory = Path(current)
        allowed_dirs = []
        for name in sorted(dirs):
            child = directory / name
            if name in SKIP_DIRS or child == root / "evidence/live/private":
                continue
            if child.is_symlink():
                findings.append(f"{child.relative_to(root).as_posix()}: symlink requires review")
            else:
                allowed_dirs.append(name)
        dirs[:] = allowed_dirs
        for name in sorted(files):
            path = directory / name
            relative = path.relative_to(root)
            count += 1
            findings.extend(
                f"{relative.as_posix()}: {message}" for message in scan_file(path, relative)
            )
    return count, sorted(findings)


def main() -> int:
    count, findings = scan_repository(ROOT)
    if findings:
        print("Repository security checks failed:")
        for finding in findings:
            print(f"- {finding}")
        return 1
    print(f"Repository security guardrails passed ({count} publishable files inspected).")
    print("Scope: credential patterns, raw evidence/key files, PowerShell guardrails, CI, compose.")
    print("Known limits: pattern-based checks cannot prove absence of secrets or unsafe behavior.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
