"""Behavioral regressions for the offline detection/evidence boundary."""

from __future__ import annotations

import copy
import html
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

from detection_lab import (
    event_valid,
    load_catalog,
    load_yaml,
    match_events,
    render_report,
    run_demo,
    safe_path,
    sanitize_event,
    validate_repository,
)
from detection_lab.__main__ import main as cli_main
from detection_lab.engine import load_authentication_components
from detection_lab.evidence import build_manifest, check_manifest
from detection_lab.model import validate_metadata, validate_sigma
from detection_lab.reporting import tuning_result
from scripts.security_check import scan_file, workflow_findings

ROOT = Path(__file__).resolve().parents[1]


def copy_data_checkout(destination: Path) -> None:
    for name in ("detections", "sigma-rules", "fixtures", "evidence", "logs"):
        shutil.copytree(ROOT / name, destination / name, ignore=shutil.ignore_patterns("private"))


class DetectionContractTests(unittest.TestCase):
    def test_metadata_rejects_missing_documentation_and_invalid_mapping(self):
        original = load_catalog(ROOT)[0]
        mutations = [
            ("owner", ""),
            ("version", "latest"),
            ("status", "production-proven"),
            ("severity", "urgent"),
            ("triage", []),
            ("false_positives", "none"),
            ("attack", [{"technique": "T1059.bad", "tactic": "execution", "rationale": "test"}]),
            ("attack", [{"technique": "T1059.001", "tactic": "not_a_tactic", "rationale": "test"}]),
            ("attack", [{"technique": "T1059.001", "tactic": "execution", "rationale": ""}]),
            ("event_ids", [4624]),
        ]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                detection = copy.deepcopy(original)
                detection[field] = value
                with self.assertRaises(ValueError):
                    validate_metadata(detection)

    def test_duplicate_detection_ids_are_rejected_before_manifest_check(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            copy_data_checkout(checkout)
            catalog = load_catalog(checkout)
            catalog[1]["id"] = catalog[0]["id"]
            (checkout / "detections/catalog.json").write_text(json.dumps(catalog), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Duplicate detection ID"):
                validate_repository(checkout)

    def test_duplicate_sigma_uuids_are_rejected_before_manifest_check(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            copy_data_checkout(checkout)
            catalog = load_catalog(checkout)
            first = load_yaml(safe_path(checkout, catalog[0]["sigma"][0]))
            second_path = safe_path(checkout, catalog[1]["sigma"][0])
            second = load_yaml(second_path)
            second["id"] = first["id"]
            second_path.write_text(yaml.safe_dump(second), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Duplicate Sigma UUID"):
                validate_repository(checkout)

    def test_sigma_rejects_wrong_source_tags_and_unsupported_condition(self):
        detection = load_catalog(ROOT)[0]
        original = load_yaml(safe_path(ROOT, detection["sigma"][0]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rule.yml"
            for change in ("source", "tags", "condition", "level", "uuid"):
                with self.subTest(change=change):
                    rule = copy.deepcopy(original)
                    if change == "source":
                        rule["logsource"]["product"] = "linux"
                    elif change == "tags":
                        rule["tags"] = ["attack.t0000"]
                    elif change == "condition":
                        rule["detection"]["condition"] = "missing_selection or ("
                    elif change == "level":
                        rule["level"] = "informational"
                    else:
                        rule["id"] = "00000000-0000-0000-0000-000000000000"
                    path.write_text(yaml.safe_dump(rule), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        validate_sigma(path, detection)

    def test_all_sigma_rules_parse_with_the_official_parser(self):
        for detection in load_catalog(ROOT):
            for relative in detection["sigma"]:
                with self.subTest(rule=relative):
                    self.assertTrue(validate_sigma(safe_path(ROOT, relative), detection))


def authentication_event(number: int, seconds: float, event_id: int = 4625) -> dict:
    timestamp = datetime(2026, 9, 1, tzinfo=UTC) + timedelta(seconds=seconds)
    return {
        "record_id": f"auth-{number}",
        "timestamp": timestamp.isoformat(),
        "EventID": event_id,
        "Channel": "Security",
        "Computer": "LAB-WIN-01",
        "TargetUserName": "lab-user",
        "TargetDomainName": "LAB",
        "IpAddress": "192.0.2.10",
    }


class FixtureBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog(ROOT)

    def test_all_declared_cases_match_the_reviewed_expectations(self):
        required_categories = {"baseline", "positive", "near_miss", "false_positive", "malformed"}
        for detection in self.catalog:
            suite = json.loads(safe_path(ROOT, detection["fixtures"]).read_text(encoding="utf-8"))
            self.assertEqual(suite["detection_id"], detection["id"])
            self.assertTrue(required_categories <= {case["category"] for case in suite["cases"]})
            self.assertIn(True, [case["expected"] for case in suite["cases"]])
            self.assertIn(False, [case["expected"] for case in suite["cases"]])
            for case in suite["cases"]:
                with self.subTest(detection=detection["id"], case=case["id"]):
                    self.assertIs(type(case["expected"]), bool)
                    actual = match_events(detection, case["events"], ROOT)
                    self.assertEqual(bool(actual), case["expected"])
                    self.assertTrue(all(event_valid(event) for match in actual for event in match))

    def test_malformed_records_are_rejected_without_crashing(self):
        valid = authentication_event(1, 0)
        malformed = [None, [], "event", {}, {**valid, "EventID": True}]
        for field in ("timestamp", "record_id", "Computer", "TargetUserName", "IpAddress"):
            missing = dict(valid)
            del missing[field]
            malformed.extend([missing, {**valid, field: None}, {**valid, field: ""}])
        malformed.extend(
            [
                {**valid, "timestamp": "2026-09-01T00:00:00"},
                {**valid, "timestamp": "not-a-timestamp"},
                {**valid, "IpAddress": "not-an-ip"},
                {**valid, "Channel": "Microsoft-Windows-Sysmon/Operational"},
                {**valid, "Computer": "x" * 32769},
            ]
        )
        for record in malformed:
            with self.subTest(record=record if not isinstance(record, dict) else list(record)):
                self.assertFalse(event_valid(record))
                for detection in self.catalog:
                    self.assertEqual(match_events(detection, [record], ROOT), [])


class AuthenticationSequenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detection = next(item for item in load_catalog(ROOT) if item["id"] == "DET-003")

    def setUp(self):
        self.failures = [authentication_event(index, index) for index in range(5)]

    def matches(self, events):
        return match_events(self.detection, events, ROOT)

    def test_five_failures_then_success_include_exact_five_minute_boundary(self):
        events = self.failures + [authentication_event(6, 300, 4624)]
        result = self.matches(events)
        self.assertEqual(len(result), 1)
        self.assertEqual(len(result[0]), 6)
        self.assertEqual(result[0][-1]["EventID"], 4624)
        self.assertEqual(self.matches(list(reversed(events))), result)
        self.assertEqual(self.matches(self.failures + [authentication_event(6, 300.001, 4624)]), [])

    def test_requires_failure_threshold_and_strictly_later_success(self):
        self.assertEqual(self.matches(self.failures[:4] + [authentication_event(6, 10, 4624)]), [])
        self.assertEqual(self.matches(self.failures + [authentication_event(6, -1, 4624)]), [])
        simultaneous = [authentication_event(index, 0) for index in range(5)]
        self.assertEqual(self.matches(simultaneous + [authentication_event(6, 0, 4624)]), [])

    def test_correlation_does_not_cross_host_user_domain_or_source(self):
        for field, other in (
            ("Computer", "LAB-WIN-02"),
            ("TargetUserName", "different-user"),
            ("TargetDomainName", "OTHER-LAB"),
            ("IpAddress", "192.0.2.20"),
        ):
            with self.subTest(field=field):
                success = authentication_event(6, 10, 4624)
                success[field] = other
                self.assertEqual(self.matches(self.failures + [success]), [])

    def test_duplicate_records_do_not_inflate_threshold_or_alert_count(self):
        duplicate_failures = [self.failures[0]] * 5 + [authentication_event(6, 10, 4624)]
        self.assertEqual(self.matches(duplicate_failures), [])
        success = authentication_event(6, 10, 4624)
        self.assertEqual(len(self.matches(self.failures + [success, copy.deepcopy(success)])), 1)

    def test_success_resets_correlation_episode(self):
        events = self.failures + [
            authentication_event(6, 10, 4624),
            authentication_event(7, 11, 4624),
        ]
        self.assertEqual(len(self.matches(events)), 1)
        events += [authentication_event(index + 10, index + 20) for index in range(5)]
        events += [authentication_event(20, 30, 4624)]
        self.assertEqual(len(self.matches(events)), 2)

    def test_tied_success_and_failure_cannot_seed_the_next_episode(self):
        for record_id in ("A-FAIL", "Z-FAIL"):
            with self.subTest(record_id=record_id):
                tied_failure = {**authentication_event(1, 0), "record_id": record_id}
                tied_success = {**authentication_event(2, 0, 4624), "record_id": "M-SUCCESS"}
                later_failures = [authentication_event(index + 10, index) for index in range(1, 5)]
                events = [
                    tied_failure,
                    tied_success,
                    *later_failures,
                    authentication_event(20, 10, 4624),
                ]
                self.assertEqual(self.matches(events), [])
                self.assertEqual(self.matches(list(reversed(events))), [])
                # A simultaneous success from another host cannot reset this host's episode.
                tied_success["Computer"] = "LAB-WIN-02"
                self.assertEqual(len(self.matches(events)), 1)

    def test_correlation_uses_predicates_from_both_sigma_components(self):
        events = self.failures + [authentication_event(6, 10, 4624)]
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            copy_data_checkout(checkout)
            self.assertEqual(len(match_events(self.detection, events, checkout)), 1)
            for relative in self.detection["sigma"]:
                path = safe_path(checkout, relative)
                original = path.read_text(encoding="utf-8")
                rule = load_yaml(path)
                with self.subTest(component=rule["detection"]["selection"]["EventID"]):
                    rule["detection"]["selection"]["TargetUserName"] = "different-user"
                    path.write_text(yaml.safe_dump(rule), encoding="utf-8")
                    self.assertEqual(match_events(self.detection, events, checkout), [])
                    rule["detection"]["selection"]["TargetUserName"] = "lab-user"
                    path.write_text(yaml.safe_dump(rule), encoding="utf-8")
                    self.assertEqual(len(match_events(self.detection, events, checkout)), 1)
                    path.write_text(original, encoding="utf-8")

    def test_authentication_component_roles_are_unambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            copy_data_checkout(checkout)
            path = safe_path(checkout, self.detection["sigma"][0])
            original = load_yaml(path)
            for field, value in (
                ("EventID", [4625, 4624]),
                ("EventID", 4732),
                ("Channel", "Other"),
            ):
                with self.subTest(field=field, value=value):
                    rule = copy.deepcopy(original)
                    rule["detection"]["selection"][field] = value
                    path.write_text(yaml.safe_dump(rule), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "unique 4625/4624"):
                        load_authentication_components(self.detection, checkout)
            rule = copy.deepcopy(original)
            rule["detection"]["selection"]["EventID"] = 4624
            path.write_text(yaml.safe_dump(rule), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unique 4625/4624"):
                load_authentication_components(self.detection, checkout)


class InputBoundaryTests(unittest.TestCase):
    def test_yaml_rejects_duplicate_keys_aliases_and_python_objects(self):
        inputs = [
            "title: original\ntitle: overwritten\n",
            "selection:\n  EventID: 1\n  EventID: 4624\n",
            "selection: &shared {EventID: 1}\nother: *shared\n",
            "!!python/object/apply:builtins.str ['unsafe-type']\n",
            "- a\n- sequence\n",
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rule.yml"
            for content in inputs:
                with self.subTest(content=content):
                    path.write_text(content, encoding="utf-8")
                    with self.assertRaises((ValueError, yaml.YAMLError)):
                        load_yaml(path)

    def test_artifact_paths_reject_cross_platform_escape_forms(self):
        for relative in (
            "../outside.json",
            "nested/../../outside.json",
            "/outside.json",
            "C:/outside.json",
            "C:outside.json",
            "\\\\server\\share\\outside.json",
            "nested\\..\\outside.json",
            "",
        ):
            with self.subTest(path=relative), self.assertRaises(ValueError):
                safe_path(ROOT, relative)
        self.assertEqual(safe_path(ROOT, "reports/demo.json"), ROOT / "reports/demo.json")

    def test_artifact_path_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "checkout"
            root.mkdir()
            outside = parent / "private.json"
            outside.write_text("private", encoding="utf-8")
            link = root / "escape.json"
            try:
                link.symlink_to(outside)
            except OSError as error:
                self.skipTest(f"OS does not permit unprivileged symlink creation: {error}")
            with self.assertRaises(ValueError):
                safe_path(root, "escape.json")

    def test_sanitization_drops_unknown_fields_identity_and_command_payload(self):
        event = {
            **authentication_event(1, 0),
            "Computer": "real-host-sensitive",
            "TargetUserName": "real-user-sensitive",
            "TargetDomainName": "real-domain-sensitive",
            "IpAddress": "10.19.28.37",
            "CommandLine": "powershell.exe -EncodedCommand SENSITIVE-COMMAND-PAYLOAD",
            "TaskContent": "<Arguments>SENSITIVE-TASK-PAYLOAD</Arguments>",
            "UnknownNested": {"token": "SENSITIVE-NESTED-PAYLOAD"},
        }
        original = copy.deepcopy(event)
        sanitized = sanitize_event(event)
        serialized = json.dumps(sanitized)
        for secret in (
            "real-host-sensitive",
            "real-user-sensitive",
            "real-domain-sensitive",
            "10.19.28.37",
            "SENSITIVE-COMMAND-PAYLOAD",
            "SENSITIVE-TASK-PAYLOAD",
            "SENSITIVE-NESTED-PAYLOAD",
        ):
            self.assertNotIn(secret, serialized)
        self.assertNotIn("UnknownNested", sanitized)
        self.assertEqual(event, original)
        self.assertEqual(sanitized, sanitize_event(original))

    def test_sanitizer_cli_does_not_echo_malformed_sensitive_input(self):
        secret = "PRIVATE-INPUT-MUST-NOT-APPEAR"
        inputs = [
            json.dumps({**authentication_event(1, 0), "timestamp": secret}),
            '{"' + secret + '": 1, "' + secret + '": 2}',
        ]
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            source = checkout / "private.json"
            for content in inputs:
                with self.subTest(content=content):
                    source.write_text(content, encoding="utf-8")
                    stderr = io.StringIO()
                    with redirect_stderr(stderr):
                        status = cli_main(
                            ["--root", str(checkout), "sanitize", "private.json", "summary.json"]
                        )
                    self.assertEqual(status, 1)
                    self.assertNotIn(secret, stderr.getvalue())
                    self.assertIn("Sanitization failed", stderr.getvalue())
                    self.assertFalse((checkout / "summary.json").exists())


class SecurityGuardrailTests(unittest.TestCase):
    def test_credential_findings_do_not_echo_the_credential(self):
        credential = "gh" + "p_" + "a" * 36
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"token": credential}), encoding="utf-8")
            findings = scan_file(path, Path("config.json"))
            self.assertIn("GitHub credential", findings)
            self.assertNotIn(credential, str(findings))

    def test_ci_guard_rejects_mutable_actions_and_write_permissions(self):
        findings = workflow_findings(
            {
                "permissions": {"contents": "write"},
                "jobs": {"test": {"steps": [{"uses": "actions/checkout@main"}]}},
            }
        )
        self.assertIn("workflow must declare only contents: read", findings)
        self.assertIn("action is not pinned to a full commit SHA", findings)
        self.assertIn("checkout persists credentials", findings)


class EvidenceAndReportTests(unittest.TestCase):
    def test_manifest_detects_modified_and_missing_source_evidence(self):
        check_manifest(ROOT)
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            copy_data_checkout(checkout)
            fixture = safe_path(checkout, load_catalog(checkout)[0]["fixtures"])
            original = fixture.read_bytes()
            fixture.write_bytes(original + b"\n")
            with self.assertRaisesRegex(ValueError, "integrity mismatch"):
                check_manifest(checkout)
            fixture.unlink()
            with self.assertRaisesRegex(ValueError, "integrity mismatch"):
                check_manifest(checkout)

    def test_manifest_is_stable_across_windows_checkout_newlines(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            copy_data_checkout(checkout)
            fixture = safe_path(checkout, load_catalog(checkout)[0]["fixtures"])
            fixture.write_bytes(
                fixture.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            )
            self.assertEqual(build_manifest(checkout), build_manifest(ROOT))
            check_manifest(checkout)

    def test_demo_is_deterministic_and_matches_reviewed_json_and_markdown(self):
        report = run_demo(ROOT)
        self.assertEqual(run_demo(ROOT), report)
        self.assertEqual(
            json.loads((ROOT / "reports/demo.json").read_text(encoding="utf-8")), report
        )
        self.assertEqual(
            (ROOT / "reports/demo.md").read_text(encoding="utf-8"), render_report(report)
        )
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            copy_data_checkout(checkout)
            self.assertEqual(run_demo(checkout), report)

    def test_report_links_evidence_and_keeps_synthetic_dispositions_explicit(self):
        report = run_demo(ROOT)
        self.assertEqual(report["metrics"]["live_captures"], 0)
        self.assertIn("DETERMINISTIC", report["scope"])
        self.assertIn("SIMULATED", report["scope"])
        self.assertEqual(
            report["metrics"]["fixture_checks_passed"], len(report["fixture_validation"])
        )
        self.assertEqual(
            sum(report["metrics"]["alert_dispositions"].values()), len(report["alerts"])
        )
        for alert in report["alerts"]:
            self.assertEqual(
                alert["evidence_refs"], [event["record_id"] for event in alert["events"]]
            )
            self.assertTrue(alert["rationale"])
        dispositions = {item["disposition"] for item in report["investigations"]}
        self.assertEqual(
            dispositions,
            {
                "true positive / escalated",
                "benign positive",
                "false positive",
                "needs more information",
            },
        )
        rendered = render_report(report)
        decoded = html.unescape(rendered).replace("\\|", "|")
        for investigation in report["investigations"]:
            for assumption in investigation["scenario_assumptions"]:
                self.assertIn(assumption, decoded)
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            copy_data_checkout(checkout)
            path = sorted((checkout / "evidence/investigations").glob("*.json"))[0]
            original = json.loads(path.read_text(encoding="utf-8"))
            for field in ("provenance", "scenario_assumptions"):
                with self.subTest(missing=field):
                    investigation = copy.deepcopy(original)
                    del investigation[field]
                    path.write_text(json.dumps(investigation), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, field):
                        validate_repository(checkout)

    def test_tuning_preserves_positives_and_rejects_fabricated_before_after_claim(self):
        result = tuning_result(ROOT)
        self.assertGreater(result["before_matches"], result["after_matches"])
        self.assertEqual(result["positive_regressions"], 0)
        for case in result["cases"]:
            if case["expected_after"]:
                self.assertTrue(case["before"])
                self.assertTrue(case["after"])
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            copy_data_checkout(checkout)
            path = checkout / "evidence/tuning/DET-001.json"
            source = json.loads(path.read_text(encoding="utf-8"))
            source["validation_cases"][0]["before_expected"] = True
            path.write_text(json.dumps(source), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "expectations differ"):
                tuning_result(checkout)

    def test_report_escapes_event_text_in_markdown_tables(self):
        report = run_demo(ROOT)
        report["alerts"][0]["host"] = "host|<img src=x onerror=alert(1)>\nextra row"
        report["investigations"][0]["scenario_assumptions"] = ["<scenario|assumption>"]
        rendered = render_report(report)
        self.assertNotIn("<img", rendered)
        self.assertIn("host\\|&lt;img", rendered)
        self.assertNotIn(">\nextra row", rendered)
        self.assertIn("&lt;scenario\\|assumption&gt;", rendered)


if __name__ == "__main__":
    unittest.main()
