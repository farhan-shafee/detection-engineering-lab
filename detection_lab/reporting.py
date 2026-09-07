"""Deterministic alert, investigation and tuning reports from repository evidence."""

from collections import Counter
from pathlib import Path

from .engine import event_valid, sigma_matches
from .io import load_json, load_yaml, repository, safe_path
from .model import fixture_cases, load_catalog, match_events, validate_repository


def tuning_result(root: Path) -> dict:
    source = load_json(safe_path(root, "evidence/tuning/DET-001.json"))
    detection = next(item for item in load_catalog(root) if item["id"] == "DET-001")
    before = load_yaml(safe_path(root, "evidence/tuning/DET-001-before.yml"))
    after = load_yaml(safe_path(root, detection["sigma"][0]))
    cases = []
    for case in fixture_cases(detection, root):
        events = [event for event in case["events"] if event_valid(event)]
        original = any(sigma_matches(before, event) for event in events)
        tuned = any(sigma_matches(after, event) for event in events)
        if tuned != case["expected"] or (case["expected"] and not original):
            raise ValueError("Tuning regression or invalid positive fixture")
        cases.append(
            {
                "case_id": case["id"],
                "category": case["category"],
                "before": original,
                "after": tuned,
                "expected_after": case["expected"],
            }
        )
    before_count = sum(case["before"] for case in cases)
    after_count = sum(case["after"] for case in cases)
    expected_evidence = [
        {
            "case_id": case["case_id"],
            "before_expected": case["before"],
            "after_expected": case["after"],
        }
        for case in cases
    ]
    if source.get("validation_cases") != expected_evidence:
        raise ValueError("Tuning source expectations differ from computed behavior")
    if before_count <= after_count:
        raise ValueError("Tuning evidence must demonstrate removal of observed fixture noise")
    return {
        "detection_id": "DET-001",
        "status": "validated against listed fixtures only",
        "before_rule": "evidence/tuning/DET-001-before.yml",
        "after_rule": detection["sigma"][0],
        "before_matches": before_count,
        "after_matches": after_count,
        "removed_noise_cases": before_count - after_count,
        "positive_regressions": 0,
        "cases": cases,
        "risk": (
            "An exact approved command/parent/user allowlist can hide abuse of that approved "
            "context; reassess ownership and expiry before deployment."
        ),
    }


def run_demo(root: Path | None = None) -> dict:
    root = repository(root)
    metrics = validate_repository(root)
    investigations = [
        load_json(path) for path in sorted((root / "evidence/investigations").glob("*.json"))
    ]
    linked = {(item["detection_id"], item["case_id"]): item for item in investigations}
    alerts, validation = [], []
    for detection in load_catalog(root):
        for case in fixture_cases(detection, root):
            matches = match_events(detection, case["events"], root)
            validation.append(
                {
                    "detection_id": detection["id"],
                    "case_id": case["id"],
                    "category": case["category"],
                    "expected": case["expected"],
                    "actual": bool(matches),
                    "passed": bool(matches) == case["expected"],
                }
            )
            for index, records in enumerate(matches, 1):
                investigation = linked.get((detection["id"], case["id"]))
                alerts.append(
                    {
                        "alert_id": f"{detection['id']}:{case['id']}:{index}",
                        "detection_id": detection["id"],
                        "title": detection["title"],
                        "severity": detection["severity"],
                        "attack": detection["attack"],
                        "case_id": case["id"],
                        "fixture_category": case["category"],
                        "timestamp": records[-1]["timestamp"],
                        "host": records[-1]["Computer"],
                        "evidence_refs": [event["record_id"] for event in records],
                        "events": records,
                        "source": "DETERMINISTIC fixture",
                        "investigation_id": investigation["id"] if investigation else None,
                        "disposition": investigation["disposition"]
                        if investigation
                        else "needs more information",
                        "rationale": investigation["rationale"]
                        if investigation
                        else (
                            "Matched a regression fixture; "
                            "no analyst investigation supplied for this case."
                        ),
                        "disposition_provenance": "SIMULATED analyst decision"
                        if investigation
                        else "unreviewed fixture default",
                    }
                )
    tuning = tuning_result(root)
    metrics.update(
        {
            "alerts_in_regression_fixture_set": len(alerts),
            "alert_dispositions": dict(
                sorted(Counter(alert["disposition"] for alert in alerts).items())
            ),
            "investigation_dispositions_including_historical": dict(
                sorted(Counter(item["disposition"] for item in investigations).items())
            ),
            "detections_with_validated_tuning": 1,
            "live_captures": 0,
        }
    )
    return {
        "schema_version": 1,
        "scope": (
            "DETERMINISTIC offline detection and evidence; SIMULATED analyst dispositions. "
            "No captured live telemetry or real incident response."
        ),
        "metrics_note": (
            "Counts describe this authored regression fixture set, not population "
            "precision/recall, SOC throughput, MTTD or MTTR. Historical tuning investigations "
            "can refer to alerts suppressed by the current rule."
        ),
        "metrics": metrics,
        "alerts": alerts,
        "investigations": investigations,
        "fixture_validation": validation,
        "tuning": tuning,
        "evidence_manifest": "evidence/fixtures/manifest.json",
    }


def _cell(value) -> str:
    return (
        str(value)
        .replace("|", "\\|")
        .replace("\n", " ")
        .replace("\r", " ")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def render_report(report: dict) -> str:
    metrics = report["metrics"]
    lines = [
        "# Deterministic detection lab report",
        "",
        report["scope"],
        "",
        "Generated by `python -m detection_lab demo`. Inputs are integrity-checked against",
        "[the evidence manifest](../evidence/fixtures/manifest.json). "
        "No wall-clock values or machine identities are inserted.",
        "",
        "## Validation and scope",
        "",
        f"- {metrics['detections']} detections; {metrics['sigma_rules']} parsed Sigma rules.",
        f"- {metrics['fixture_checks_passed']}/{metrics['fixture_cases']} "
        "fixture assertions passed: "
        f"{metrics['positive_cases']} expected matches and "
        f"{metrics['negative_cases']} expected nonmatches.",
        f"- {metrics['detections_with_triage']} detections have triage; "
        f"{metrics['investigations']} worked investigations; "
        f"{metrics['detections_with_validated_tuning']} validated tuning lifecycle.",
        "- Live captures: 0. Live deployment and decoder parity remain unverified.",
        "",
        report["metrics_note"],
        "",
        "## Alert queue from regression fixtures",
        "",
        "| Alert | Host | Severity | Disposition | Investigation |",
        "|---|---|---|---|---|",
    ]
    for alert in report["alerts"]:
        lines.append(
            "| "
            + " | ".join(
                _cell(alert[key])
                for key in ("alert_id", "host", "severity", "disposition", "investigation_id")
            )
            + " |"
        )
    lines.extend(["", "## Worked investigations", ""])
    for item in report["investigations"]:
        lines.extend(
            [
                f"### {_cell(item['id'])}: {_cell(item['detection_id'])}",
                "",
                f"Case: `{_cell(item['case_id'])}`. "
                f"**SIMULATED disposition: {_cell(item['disposition'])}.**",
                "",
                _cell(item["rationale"]),
                "",
                "| Question | Evidence / explicit gap |",
                "|---|---|",
            ]
        )
        for key, value in item["context"].items():
            lines.append(f"| {_cell(key)} | {_cell(value)} |")
        lines.extend(
            [
                "",
                "Evidence record IDs: "
                + ", ".join(f"`{_cell(ref)}`" for ref in item["evidence_refs"])
                + ".",
                "",
                "Observed:",
                "",
            ]
        )
        lines.extend("- " + _cell(value) for value in item["observations"])
        lines.extend(["", "Inferred:", ""])
        lines.extend("- " + _cell(value) for value in item["inferences"])
        lines.extend(["", "Simulated scenario assumptions (not captured evidence):", ""])
        lines.extend("- " + _cell(value) for value in item["scenario_assumptions"])
        lines.extend(["", "Next steps (proposed; not executed):", ""])
        lines.extend("- " + _cell(value) for value in item["next_steps"])
        lines.append("")
    tuning = report["tuning"]
    lines.extend(
        [
            "## DET-001 tuning regression",
            "",
            f"Fixture matches: {tuning['before_matches']} before → "
            f"{tuning['after_matches']} after; "
            f"{tuning['removed_noise_cases']} known-noise case removed; "
            f"{tuning['positive_regressions']} positive regressions.",
            "",
            tuning["risk"],
            "",
            "| Case | Before | After | Expected after |",
            "|---|---|---|---|",
        ]
    )
    for case in tuning["cases"]:
        lines.append(
            f"| {_cell(case['case_id'])} | {case['before']} | {case['after']} | "
            f"{case['expected_after']} |"
        )
    lines.extend(
        [
            "",
            "See [source investigations](../evidence/investigations/) "
            "and [tuning record](../evidence/tuning/).",
            "",
        ]
    )
    return "\n".join(lines)
