# DET-001: Encoded PowerShell process requiring review

**Evidence class: DETERMINISTIC telemetry fixtures; SIMULATED analyst decisions.** No live execution, Wazuh alert, compromise or incident is established by this document.

Status: **experimental** | Severity: **medium** | Version: **1.1.0** | Owner: Detection Engineering Lab maintainer

## Purpose and hypothesis

Identify a reviewable PowerShell execution signal while showing how investigated automation noise informs controlled tuning.

An encoded command from an unapproved context merits review because command content is hidden from a casual command-line reading. Encoding alone does not establish maliciousness.

## Required telemetry

Channel: `Microsoft-Windows-Sysmon/Operational`. Event IDs: 1.

Optional Sysmon installed and configured to record process creation including full CommandLine, ParentImage and User.

## Logic

Valid Sysmon Event ID 1, Image ends with \powershell.exe or \pwsh.exe, and CommandLine contains the whitespace-delimited -enc or -encodedcommand switch (case insensitive). Exclude only the exact case-sensitive safe encoded command together with approved parent image and LAB\automation user. The Sigma file supplies matching predicates.

Sigma: [`sigma-rules/windows_powershell_encoded.yml`](../../sigma-rules/windows_powershell_encoded.yml).

Wazuh mapping: `custom_rule`; rule IDs: 110001.

- Experimental candidate; not verified against a running Wazuh manager or captured events.
- Native win.eventdata field casing and channel decoding must be confirmed in the deployed version.
- The Wazuh candidate implements the initial signal; the offline scoped automation exception is intentionally not ported. Do not claim identical before/after alert counts.

## ATT&CK association

- [T1059.001](https://attack.mitre.org/techniques/T1059/001/), `execution`: PowerShell process execution directly supports an execution behavior association; benign fixtures demonstrate matching only, not malicious technique execution.

## Common benign explanations

- Packaging and remote-management tools legitimately encode PowerShell arguments.
- A harmless interactive test is a positive behavioral match with benign intent.

## Tuning decisions

- The before rule matched the exact known lab marker under approved automation; INV-001 records simulated authorization context.
- The after rule suppresses only whole CommandLine plus parent plus user; base64 payload comparison is case sensitive.
- Changed user, parent, payload, base64 case, appended argument and trailing newline remain regression positives.
- A scoped exception is a policy choice, not a trust boundary: review expiry, command content, identity ownership and protected binary paths before using in production.

## Analyst triage

1. Read the original record and confirm channel, host, user, child image, parent image and complete command line.
2. Extract the encoded argument and decode as UTF-16LE text without executing it; retain the original string for evidence.
3. Compare decoded content and parent/user combination with an approved change record; do not treat the rule match as an incident verdict.
4. Request process ancestry, script-block telemetry if enabled, binary signatures and related endpoint/network events when purpose is unknown.

## Escalation criteria

- Escalate for investigation if content or context is unexplained, the initiating identity denies the action, or independent telemetry corroborates abuse.
- Any actual containment needs a verified incident process; this demo does not execute response actions.

## Limitations

- Only explicitly supported -enc and -encodedcommand switch forms are covered; alternate abbreviations and in-process PowerShell are outside scope.
- Sysmon must exist and retain full fields. Security 4688 and PowerShell 4104 are supplementary context, not interchangeable fixture inputs.
- Payload text is not decoded by the detector, and the process name alone does not authenticate the executable.
- The case-sensitive regex filter and canonical field names need backend-specific translation testing.

## Benign test and validation

The local safe generator can print DETECTION-LAB-SAFE through encoded PowerShell. The deterministic positive fixture uses a fictional analyst context and remains a match. The approved automation fixture is separately synthetic.

Run python -m detection_lab validate and python -m detection_lab demo. Fixtures cover positive, baseline, boundary near miss, known noise, changed-context regression and malformed records. evidence/tuning/DET-001-before.yml preserves initial logic.

Fixture source: [`fixtures/DET-001.json`](../../fixtures/DET-001.json). The `expected` field is a detection expectation, not an incident label. A common false-positive scenario can still match and receive a benign-positive disposition.

## Sources

Official references reviewed on 2026-09-07. ATT&CK association describes observable behavior and review intent; it is not a claim of complete technique coverage.

- [Official reference 1](https://attack.mitre.org/techniques/T1059/001/)
- [Official reference 2](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
