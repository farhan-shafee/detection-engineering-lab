# DET-001 tuning lifecycle

**Evidence class: DETERMINISTIC matching; SIMULATED authorization and analyst decisions.** This is a measured regression example on a small hand-authored dataset, not a production noise-rate estimate.

1. **Initial rule:** [DET-001-before.yml](DET-001-before.yml) matches encoded PowerShell switches for both interactive use and recurring lab automation.
2. **Observed noise in the fixture:** `D1-F1`, case `approved-automation`, is the exact harmless marker under the specified PowerShell parent and `LAB\automation` identity.
3. **Investigation:** [INV-001](../investigations/INV-001.md) safely decodes the text and explicitly supplies fictional approval `LAB-CHANGE-001`. This is not real owner confirmation.
4. **Controlled change:** [current Sigma rule](../../sigma-rules/windows_powershell_encoded.yml) filters only the conjunction of exact whole command, approved parent and approved user. Command comparison is case sensitive because base64 casing changes decoded bytes. Whole-string anchors also prevent a trailing newline from inheriting approval.
5. **Validation:** [DET-001.json](DET-001.json) lists all 16 case-level before/after expectations. The same original fixtures are evaluated against both rules.
6. **Result:** the direct local check on 2026-09-07 passed all 16 before/after comparisons. Matching cases changed from 10 to 9: only approved automation was suppressed. All nine intended matching regressions remain visible. Re-run the demo to regenerate current results.

The changed-parent, changed-user, changed-payload, changed-base64-case, appended-argument and trailing-newline cases are important: copying a marker or account name alone must not grant the exception. Ordinary activity, wrong executable, near-miss arguments and malformed records remain nonmatches.

An exception scoped to command/path/account is still a policy choice, not proof that a process or identity is trustworthy. A mature deployment would require an owner, independently verified approval, protected paths, expiration/review, peer review and deployment regression evidence. The source records a fictional review date and reopening criteria. No Wazuh exception has been applied; its experimental candidate remains at the initial broad signal until native runtime behavior is tested.

The before rule is historical evidence outside the active rule directory. It intentionally retains DET-001's rule UUID to show the previous version of the same analytic. Do not load both versions as concurrent active detections or inflate active detection counts with the historical file.
