from pathlib import Path
import re
import sys
from uuid import UUID

REQUIRED_TOP_LEVEL = {
    "title",
    "id",
    "description",
    "logsource",
    "detection",
    "level",
    "tags",
    "falsepositives",
}

ALLOWED_LEVELS = {"informational", "low", "medium", "high", "critical"}
ATTACK_TAG_PATTERN = re.compile(r"^\s*-\s*attack\.t\d{4}(?:\.\d{3})?\s*$", re.IGNORECASE | re.MULTILINE)
FIELD_PATTERN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*", re.MULTILINE)


def _extract_scalar(text: str, key: str) -> str | None:
    m = re.search(rf"^\s*{re.escape(key)}\s*:\s*(.+?)\s*$", text, re.MULTILINE)
    if not m:
        return None
    return m.group(1).strip().strip("'\"")


def validate_sigma_file(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")

    seen_keys = set(FIELD_PATTERN.findall(text))
    for key in REQUIRED_TOP_LEVEL:
        if key not in seen_keys:
            errors.append(f"{path}: missing required key '{key}'")

    uuid_value = _extract_scalar(text, "id")
    if uuid_value:
        try:
            UUID(uuid_value)
        except ValueError:
            errors.append(f"{path}: id is not a valid UUID")

    level = _extract_scalar(text, "level")
    if level and level.lower() not in ALLOWED_LEVELS:
        errors.append(f"{path}: level '{level}' must be one of {sorted(ALLOWED_LEVELS)}")

    if not re.search(r"^\s*condition\s*:\s*.+$", text, re.MULTILINE):
        errors.append(f"{path}: detection requires a non-empty 'condition'")

    if not ATTACK_TAG_PATTERN.search(text):
        errors.append(f"{path}: missing ATT&CK tag (e.g. attack.t1110 or attack.t1136.001)")

    return errors


def main() -> int:
    rules = sorted(Path("sigma-rules").glob("*.yml"))
    if not rules:
        print("No Sigma rules found in sigma-rules/")
        return 1

    all_errors: list[str] = []
    for rule in rules:
        all_errors.extend(validate_sigma_file(rule))

    if all_errors:
        print("Validation failed:")
        for err in all_errors:
            print(f" - {err}")
        return 1

    print(f"Validated {len(rules)} Sigma rule(s): OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
