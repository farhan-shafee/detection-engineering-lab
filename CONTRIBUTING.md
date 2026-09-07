# Contributing

Preserve the distinction between deterministic telemetry, simulated decisions and verified live captures. Keep activity confined to controlled local systems. No harmful payloads or unrelated endpoint configuration changes.

1. Describe the hypothesis and telemetry contract before changing a rule.
2. Update `detections/catalog.json`, the Sigma implementation, fixture cases and the corresponding triage/writeup. For a behavior change, increment the contract version and preserve before/after tuning evidence where relevant.
3. Add positive, baseline, near-miss, common false-positive and malformed cases with explicit expected outcomes. Test meaningful boundaries and neighboring cases; a single positive is insufficient.
4. Run `python -m unittest discover -s tests -v`, lint/format and `python -m detection_lab validate`. If intended source changes alter the evidence manifest, review those source diffs first, then run `python -m detection_lab manifest --refresh`.
5. Run `python -m detection_lab demo`, review both report diffs, then `python -m detection_lab demo --check`. Never refresh a golden file merely to hide a failing expectation.
6. Run the security checks listed in the README and require CI before merging. Keep detection, evidence and documentation in the same reviewed change.

The source checkout is the supported distribution; no installation as a Python wheel is required. The small Sigma evaluator deliberately rejects unsupported conditions and modifiers. Add semantics and negative tests before broadening its accepted language. DET-003's Python sequence is authoritative; the component Sigma selectors are not an equivalent SIEM correlation.

Treat live logs and screenshots as sensitive. Store raw material only in ignored `.local/` or `evidence/live/private/`; publish manually reviewed summaries with provenance. Do not commit credentials, installer binaries, private keys, raw event logs, real host/user information or unreviewed command lines. The sanitizer discards content and is not proof of anonymity or source authenticity.
