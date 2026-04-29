from pathlib import Path
import sys

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


def validate_sigma_file(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")

    for key in REQUIRED_TOP_LEVEL:
        marker = f"{key}:"
        if marker not in text:
            errors.append(f"{path}: missing required key '{key}'")

    if "attack.t" not in text:
        errors.append(f"{path}: missing ATT&CK tag pattern 'attack.t####'")

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
