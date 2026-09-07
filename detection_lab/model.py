"""Validate detection contracts, parsed Sigma rules and their fixture semantics."""

import re
from collections import Counter
from pathlib import Path
from uuid import UUID

from sigma.collection import SigmaCollection

from .engine import CHANNELS, event_valid, match_events, validate_rule_subset
from .io import load_json, load_yaml, read_text, repository, safe_path

TEXT_FIELDS = (
    "id",
    "title",
    "status",
    "owner",
    "version",
    "description",
    "purpose",
    "hypothesis",
    "severity",
    "logic",
    "benign_test",
    "validation",
    "fixtures",
)
LIST_FIELDS = ("sigma", "false_positives", "tuning", "triage", "escalation", "limitations")
TACTICS = {
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
}
CATEGORIES = {"baseline", "positive", "near_miss", "false_positive", "malformed"}
DISPOSITIONS = {
    "true positive / escalated",
    "benign positive",
    "false positive",
    "needs more information",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_catalog(root: Path | None = None) -> list[dict]:
    value = load_json(repository(root) / "detections/catalog.json")
    require(isinstance(value, list) and bool(value), "Catalog must be a nonempty list")
    return value


def fixture_cases(detection: dict, root: Path) -> list[dict]:
    fixture = load_json(safe_path(root, detection["fixtures"]))
    require(isinstance(fixture, dict), "Fixture must be an object")
    require(fixture.get("detection_id") == detection["id"], "Fixture detection ID mismatch")
    cases = fixture.get("cases")
    require(isinstance(cases, list) and bool(cases), "Fixture cases required")
    return cases


def validate_metadata(detection: dict) -> None:
    require(isinstance(detection, dict), "Detection must be an object")
    for field in TEXT_FIELDS:
        require(
            isinstance(detection.get(field), str) and bool(detection[field].strip()),
            f"Missing text field: {field}",
        )
    require(bool(re.fullmatch(r"DET-\d{3}", detection["id"])), "Invalid detection ID")
    require(bool(re.fullmatch(r"\d+\.\d+\.\d+", detection["version"])), "Invalid semantic version")
    require(
        detection["status"] in {"experimental", "test", "stable", "deprecated"}, "Invalid status"
    )
    require(
        detection["severity"] in {"informational", "low", "medium", "high", "critical"},
        "Invalid severity",
    )
    for field in LIST_FIELDS:
        values = detection.get(field)
        require(
            isinstance(values, list)
            and bool(values)
            and all(isinstance(v, str) and v.strip() for v in values),
            f"Missing documented list: {field}",
        )
    source = detection.get("logsource")
    require(
        isinstance(source, dict) and source.get("product") == "windows",
        "Windows logsource required",
    )
    require(source.get("channel") in set(CHANNELS.values()), "Unsupported source channel")
    event_ids = detection.get("event_ids")
    require(isinstance(event_ids, list) and bool(event_ids), "Event IDs required")
    require(
        all(type(i) is int and CHANNELS.get(i) == source["channel"] for i in event_ids),
        "Event ID/channel mismatch",
    )
    attack = detection.get("attack")
    require(isinstance(attack, list) and bool(attack), "ATT&CK mapping required")
    for mapping in attack:
        require(isinstance(mapping, dict), "ATT&CK mapping must be an object")
        require(
            bool(re.fullmatch(r"T\d{4}(?:\.\d{3})?", str(mapping.get("technique", "")))),
            "Invalid ATT&CK technique formatting",
        )
        require(mapping.get("tactic") in TACTICS, "Invalid ATT&CK tactic")
        require(
            isinstance(mapping.get("rationale"), str) and bool(mapping["rationale"].strip()),
            "ATT&CK rationale required",
        )
    wazuh = detection.get("wazuh")
    require(
        isinstance(wazuh, dict)
        and all(key in wazuh for key in ("kind", "rule_ids", "limitations")),
        "Wazuh mapping/limitations required",
    )
    require(wazuh["kind"] in {"custom_rule", "mapping_only"}, "Unsupported Wazuh mapping kind")
    require(
        isinstance(wazuh["rule_ids"], list)
        and all(type(value) is int and 100000 <= value <= 120000 for value in wazuh["rule_ids"]),
        "Invalid Wazuh custom rule IDs",
    )
    require(
        isinstance(wazuh["limitations"], list)
        and bool(wazuh["limitations"])
        and all(isinstance(value, str) and value.strip() for value in wazuh["limitations"]),
        "Wazuh limitations must be documented",
    )


def validate_sigma(path: Path, detection: dict) -> str:
    rule = load_yaml(path)
    for field in (
        "title",
        "id",
        "description",
        "status",
        "author",
        "date",
        "logsource",
        "detection",
        "level",
        "tags",
        "falsepositives",
    ):
        require(bool(rule.get(field)), f"Missing Sigma metadata {field}: {path.name}")
    uuid = str(UUID(str(rule["id"])))
    require(UUID(uuid).int != 0, "Nil Sigma UUID is a placeholder")
    source = rule["logsource"]
    require(
        isinstance(source, dict) and source.get("product") == "windows",
        "Sigma Windows source required",
    )
    expected = (
        {"category": "process_creation"}
        if detection["event_ids"] == [1]
        else {"service": "security"}
    )
    require(
        all(source.get(k) == v for k, v in expected.items()),
        "Sigma logsource differs from contract",
    )
    if detection["id"] != "DET-003":
        require(rule["level"] == detection["severity"], "Sigma severity differs from contract")
    else:
        require(rule["level"] == "low", "Auth component selectors are low; correlation is high")
    require(rule["status"] == detection["status"], "Sigma status differs from contract")
    tags = rule["tags"]
    require(
        isinstance(tags, list) and all(isinstance(tag, str) for tag in tags),
        "Sigma tags must be strings",
    )
    expected_tags = {"attack." + item["technique"].lower() for item in detection["attack"]}
    expected_tags.update("attack." + item["tactic"] for item in detection["attack"])
    require(expected_tags.issubset(set(tags)), "Sigma ATT&CK tags differ from contract")
    for tag in tags:
        if tag.startswith("attack.t"):
            require(
                bool(re.fullmatch(r"attack\.t\d{4}(?:\.\d{3})?", tag)), "Malformed Sigma ATT&CK tag"
            )
    validate_rule_subset(rule)
    parsed = SigmaCollection.from_yaml(read_text(path))
    require(len(parsed.rules) == 1, "Expected one Sigma rule per file")
    for item in parsed.rules:
        for condition in item.detection.parsed_condition:
            _ = condition.parsed  # Force pySigma's lazy condition parser.
    return uuid


def validate_repository(root: Path | None = None) -> dict:
    from .evidence import check_manifest

    root = repository(root)
    catalog = load_catalog(root)
    seen_ids, sigma_ids, sigma_paths, fixture_paths = set(), set(), set(), set()
    totals = Counter()
    tactic_counts = Counter()
    case_index = {}
    for detection in catalog:
        validate_metadata(detection)
        detection_id = detection["id"]
        require(detection_id not in seen_ids, "Duplicate detection ID")
        seen_ids.add(detection_id)
        for path_string in detection["sigma"]:
            require(path_string not in sigma_paths, "Duplicate Sigma artifact reference")
            sigma_paths.add(path_string)
            sigma_id = validate_sigma(safe_path(root, path_string), detection)
            require(sigma_id not in sigma_ids, "Duplicate Sigma UUID")
            sigma_ids.add(sigma_id)
        require(detection["fixtures"] not in fixture_paths, "Duplicate fixture artifact reference")
        fixture_paths.add(detection["fixtures"])
        cases = fixture_cases(detection, root)
        categories, local_ids, outcomes = set(), set(), set()
        for case in cases:
            require(isinstance(case, dict), "Fixture case must be an object")
            case_id = case.get("id")
            require(isinstance(case_id, str) and bool(case_id), "Case ID required")
            require(case_id not in local_ids, "Duplicate fixture case ID")
            local_ids.add(case_id)
            require(case.get("category") in CATEGORIES, "Invalid fixture category")
            require(type(case.get("expected")) is bool, "Expected fixture outcome must be boolean")
            require(
                isinstance(case.get("description"), str) and bool(case["description"]),
                "Fixture description required",
            )
            require(
                isinstance(case.get("events"), list) and bool(case["events"]),
                "Fixture events required",
            )
            if case["category"] != "malformed":
                require(
                    all(event_valid(e) for e in case["events"]),
                    f"Invalid event in {detection_id}/{case_id}",
                )
            elif case["category"] == "malformed":
                require(
                    any(not event_valid(e) for e in case["events"]),
                    "Malformed case must contain invalid input",
                )
                require(not case["expected"], "Malformed fixture must be rejected")
            identities = [
                (e["Computer"], e["Channel"], e["record_id"])
                for e in case["events"]
                if event_valid(e)
            ]
            require(len(identities) == len(set(identities)), "Duplicate event record identity")
            actual = bool(match_events(detection, case["events"], root))
            require(
                actual == case["expected"],
                f"Fixture semantic mismatch {detection_id}/{case_id}: "
                f"expected {case['expected']}, got {actual}",
            )
            categories.add(case["category"])
            outcomes.add(case["expected"])
            totals["fixture_cases"] += 1
            totals["positive_cases" if case["expected"] else "negative_cases"] += 1
            totals["malformed_cases"] += case["category"] == "malformed"
            case_index[(detection_id, case_id)] = case
        require(categories == CATEGORIES, f"Five fixture categories required: {detection_id}")
        require(outcomes == {True, False}, "Positive and negative outcomes required")
        for tactic in {mapping["tactic"] for mapping in detection["attack"]}:
            tactic_counts[tactic] += 1
    require(
        sigma_paths
        == {p.relative_to(root).as_posix() for p in (root / "sigma-rules").glob("*.yml")},
        "Unreferenced or missing Sigma rule",
    )
    require(
        fixture_paths
        == {p.relative_to(root).as_posix() for p in (root / "fixtures").glob("*.json")},
        "Unreferenced or missing fixture file",
    )
    investigation_ids, investigated_cases = set(), set()
    for path in sorted((root / "evidence/investigations").glob("*.json")):
        investigation = load_json(path)
        require(isinstance(investigation, dict), "Investigation must be object")
        require(investigation.get("id") not in investigation_ids, "Duplicate investigation ID")
        require(isinstance(investigation.get("id"), str), "Investigation ID required")
        investigation_ids.add(investigation["id"])
        key = (investigation.get("detection_id"), investigation.get("case_id"))
        require(key in case_index, "Investigation references unknown case")
        require(key not in investigated_cases, "Duplicate investigation for fixture case")
        investigated_cases.add(key)
        require(
            investigation.get("provenance")
            == {
                "telemetry": "deterministic",
                "analyst_decision": "simulated",
                "real_incident": False,
            },
            "Fixture investigation must explicitly declare deterministic/simulated provenance",
        )
        require(investigation.get("disposition") in DISPOSITIONS, "Invalid disposition")
        require(
            isinstance(investigation.get("rationale"), str) and bool(investigation["rationale"]),
            "Disposition rationale required",
        )
        records = {e.get("record_id") for e in case_index[key]["events"] if isinstance(e, dict)}
        refs = investigation.get("evidence_refs")
        require(
            isinstance(refs, list) and bool(refs) and all(ref in records for ref in refs),
            "Investigation evidence reference missing",
        )
        for field in ("observations", "inferences", "next_steps", "scenario_assumptions"):
            require(
                isinstance(investigation.get(field), list)
                and bool(investigation[field])
                and all(isinstance(value, str) and value.strip() for value in investigation[field]),
                f"Investigation {field} required",
            )
        context = investigation.get("context")
        require(
            isinstance(context, dict)
            and all(
                context.get(field)
                for field in (
                    "what",
                    "user",
                    "host",
                    "process",
                    "parent_process",
                    "command_line",
                    "timestamp",
                    "related_activity",
                    "expected",
                )
            ),
            "Full investigation context required; state unavailable fields explicitly",
        )
    check_manifest(root)
    return {
        "detections": len(catalog),
        "sigma_rules": len(sigma_ids),
        "fixture_checks_passed": totals["fixture_cases"],
        **dict(totals),
        "detections_with_positive_and_negative_fixtures": len(catalog),
        "detections_with_triage": len(catalog),
        "investigations": len(investigation_ids),
        "detections_by_attack_tactic": dict(sorted(tactic_counts.items())),
    }
