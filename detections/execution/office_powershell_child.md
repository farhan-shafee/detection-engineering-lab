# DET-005: Office application spawning PowerShell

**Evidence class: DETERMINISTIC telemetry fixtures; SIMULATED analyst decisions.** No live execution, Wazuh alert, compromise or incident is established by this document.

Status: **experimental** | Severity: **high** | Version: **1.0.0** | Owner: Detection Engineering Lab maintainer

## Purpose and hypothesis

Demonstrate process-lineage investigation with clearly stated visibility limits and approved automation context.

Office applications do not normally need PowerShell for ordinary document viewing; a recorded Office-to-PowerShell relationship warrants checking the initiating document or add-in.

## Required telemetry

Channel: `Microsoft-Windows-Sysmon/Operational`. Event IDs: 1.

Optional Sysmon process creation Event ID 1 includes full Image, ParentImage, CommandLine and User.

## Logic

Valid Sysmon Event ID 1 with Image ending in \powershell.exe or \pwsh.exe and ParentImage ending in \winword.exe, \excel.exe or \outlook.exe (case insensitive). Command content is collected for triage; encoding is not required.

Sigma: [`sigma-rules/windows_office_powershell_child.yml`](../../sigma-rules/windows_office_powershell_child.yml).

Wazuh mapping: `custom_rule`; rule IDs: 110006.

- Experimental candidate; not verified against a running Wazuh manager or captured events.
- Native win.eventdata field casing and channel decoding must be confirmed in the deployed version.
- An encoded child can also match DET-001. Correlate shared event/process identity during triage instead of counting overlap as two incidents.

## ATT&CK association

- [T1059.001](https://attack.mitre.org/techniques/T1059/001/), `execution`: The child process is PowerShell. The parent relationship increases review priority, but does not itself prove macros, user execution, exploitation or phishing.

## Common benign explanations

- A documented Office add-in or line-of-business workflow invokes PowerShell.
- An approved local document automation tool launches a helper process.

## Tuning decisions

- Request signed add-in/package and owner context before a narrow exception; retain parent-child evidence.
- Do not broadly exclude Office, PowerShell, a user account, or a folder path.
- Review DET-001 overlap and merge related alerts at the investigation layer.

## Analyst triage

1. Confirm parent and child paths, command line, user, host and timestamp from the original event.
2. Request parent/child ProcessGuid and ancestor records when available; compare executable signatures and package provenance.
3. Identify the document or add-in involved using authorized endpoint context; document absence when the fixture does not contain it.
4. Check the decoded command if encoding is present, related network/file activity and owner confirmation before setting disposition.

## Escalation criteria

- Escalate an unknown document or add-in combined with owner denial or corroborating abnormal process/content evidence.
- Use benign positive only when approval is documented; preserve needs more information if document or initiating context is unavailable.

## Limitations

- Executable names and parent metadata do not authenticate binaries or establish a specific document, macro, exploit or email source.
- Missing parent telemetry and unrecorded ancestry create blind spots.
- Office lineage is synthetic in this lab; no macro or executable attachment is generated.

## Benign test and validation

Use fictional Office parent records and a child command that only writes a harmless marker. The lab does not fabricate a live parent-child chain.

Word, Excel and Outlook positives; ordinary Explorer parent, wrong child image, deceptive parent-name suffix and missing parent are covered. INV-005 records a simulated benign-positive add-in disposition.

Fixture source: [`fixtures/DET-005.json`](../../fixtures/DET-005.json). The `expected` field is a detection expectation, not an incident label. A common false-positive scenario can still match and receive a benign-positive disposition.

## Sources

Official references reviewed on 2026-09-07. ATT&CK association describes observable behavior and review intent; it is not a claim of complete technique coverage.

- [Official reference 1](https://attack.mitre.org/techniques/T1059/001/)
- [Official reference 2](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
