"""Source-checkout CLI; no live backend or outbound connections."""

import argparse
import sys
from pathlib import Path

import yaml

from .evidence import MANIFEST, build_manifest, sanitize_event
from .io import json_text, load_json, repository, safe_path
from .model import validate_repository
from .reporting import render_report, run_demo


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, help="Repository root (default: this source checkout)")
    sub = parser.add_subparsers(dest="command", required=True)
    demo = sub.add_parser("demo", help="Run deterministic detection, triage, tuning and metrics")
    demo.add_argument(
        "--check", action="store_true", help="Compare tracked reports without writing"
    )
    sub.add_parser("validate", help="Validate metadata, Sigma, fixtures and evidence")
    evidence = sub.add_parser(
        "manifest", help="Refresh evidence hashes after reviewing intended source changes"
    )
    evidence.add_argument("--refresh", required=True, action="store_true")
    sanitize = sub.add_parser(
        "sanitize", help="Create a lossy publication summary from normalized JSON"
    )
    sanitize.add_argument(
        "input", help="Repository-relative source JSON path; keep raw inputs in .local/"
    )
    sanitize.add_argument(
        "output", help="New repository-relative output JSON path; manually review before publishing"
    )
    args = parser.parse_args(argv)
    root = repository(args.root)
    try:
        if args.command == "manifest":
            path = safe_path(root, MANIFEST)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json_text(build_manifest(root)), encoding="utf-8", newline="\n")
            print(
                "Refreshed deterministic evidence manifest; "
                "review this diff with the source changes."
            )
        elif args.command == "validate":
            print(json_text(validate_repository(root)), end="")
        elif args.command == "sanitize":
            source = load_json(safe_path(root, args.input))
            output = safe_path(root, args.output)
            if output.exists():
                raise ValueError("Sanitization output already exists; choose a new path")
            events = source if isinstance(source, list) else [source]
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json_text([sanitize_event(event) for event in events]),
                encoding="utf-8",
                newline="\n",
            )
            print(
                "Created lossy publication summary. "
                "Manually review it; no source authenticity is asserted."
            )
        else:
            report = run_demo(root)
            outputs = {
                "reports/demo.json": json_text(report),
                "reports/demo.md": render_report(report),
            }
            for relative, content in outputs.items():
                path = safe_path(root, relative)
                if args.check:
                    if not path.is_file() or path.read_text(encoding="utf-8") != content:
                        raise ValueError(f"Deterministic report differs: {relative}")
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(content, encoding="utf-8", newline="\n")
            metrics = report["metrics"]
            print("DETERMINISTIC detection lab | live captures: 0 | analyst decisions: SIMULATED")
            print(
                f"Validated {metrics['detections']} detections, "
                f"{metrics['sigma_rules']} Sigma rules, "
                f"{metrics['fixture_checks_passed']}/{metrics['fixture_cases']} fixture cases."
            )
            print(
                f"Regression fixture alerts: {len(report['alerts'])}; "
                f"worked investigations: {len(report['investigations'])}."
            )
            first = next(alert for alert in report["alerts"] if alert["investigation_id"])
            print(f"Alert: {first['alert_id']} | {first['title']} | {first['disposition']}")
            print("Evidence: " + ", ".join(first["evidence_refs"]))
            print(
                "Tuning: "
                + str(report["tuning"]["removed_noise_cases"])
                + " known-noise case removed; 0 positive regressions."
            )
            print(
                "Reports: reports/demo.md and reports/demo.json"
                + (" (golden comparison passed)" if args.check else "")
            )
        return 0
    except (ValueError, OSError, KeyError, TypeError, yaml.YAMLError) as error:
        if args.command == "sanitize":
            # JSON/YAML/date exceptions may embed the raw value or identifying path.
            print(
                "Sanitization failed: invalid input or unavailable output. "
                "Original values and paths omitted.",
                file=sys.stderr,
            )
        else:
            print(f"Validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
