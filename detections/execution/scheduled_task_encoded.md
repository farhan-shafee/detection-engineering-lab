# DET-004: Scheduled task with encoded PowerShell action

**Evidence class: DETERMINISTIC telemetry fixtures; SIMULATED analyst decisions.** No live execution, Wazuh alert, compromise or incident is established by this document.

Status: **experimental** | Severity: **high** | Version: **1.0.0** | Owner: Detection Engineering Lab maintainer

## Purpose and hypothesis

Show task-registration triage from action content without creating persistent behavior on the demonstration host.

A scheduled task configured to invoke encoded PowerShell is a useful review signal; task registration alone does not prove execution or malicious persistence.

## Required telemetry

Channel: `Security`. Event IDs: 4698.

Audit Other Object Access Events success auditing enabled; Security 4698 includes TaskName, TaskContent and SubjectUserName.

## Logic

Valid Security Event ID 4698 with TaskContent containing powershell and a -enc or -encodedcommand switch. The switch must be preceded by beginning of text, whitespace or XML closing angle bracket, and followed by whitespace or end of text. Both predicates inspect the same captured TaskContent string.

Sigma: [`sigma-rules/windows_scheduled_task_encoded.yml`](../../sigma-rules/windows_scheduled_task_encoded.yml).

Wazuh mapping: `custom_rule`; rule IDs: 110005.

- Experimental candidate; not verified against a running Wazuh manager or captured events.
- Native win.eventdata field casing and channel decoding must be confirmed in the deployed version.
- Raw TaskContent XML escaping and field availability must be verified with actual 4698 decoder output.

## ATT&CK association

- [T1053.005](https://attack.mitre.org/techniques/T1053/005/), `execution`: The registered task action relates to Windows scheduled task execution capability; the fixture proves registration text only, not that it ran or persisted.

## Common benign explanations

- Approved software deployment tasks use encoded PowerShell to avoid quoting errors.
- Administrator-created diagnostics tasks can exhibit the same action text.

## Tuning decisions

- Review full task action, principal, trigger and change record before approving a scoped task exception.
- Do not allowlist every task under a familiar folder name.
- Preserve original XML and compare task content changes across registrations.

## Analyst triage

1. Read TaskName, SubjectUserName, host, timestamp and the original TaskContent.
2. Extract actions, arguments, run-as principal and triggers as text without executing the task or any decoded payload.
3. Confirm owner and maintenance/change authorization; distinguish task creation from actual launch.
4. Request task scheduler operational history, subsequent process events and task update/deletion events if live data exists.

## Escalation criteria

- Escalate an unexplained task principal or action, an owner-denied registration, or independent evidence of harmful execution.
- Do not assert persistence or execute/delete a real task based only on this fixture-driven signal.

## Limitations

- The detector matches raw content substrings rather than parsing XML action structure; PowerShell and the switch could occur in different text nodes.
- Only 4698 creation is covered; task updates and alternate interpreters are not.
- Task registration does not prove task execution, account compromise or attacker intent.

## Benign test and validation

Use deterministic task XML fixtures that encode a harmless Write-Output marker. No task is registered by the offline demo or default safe generator.

Encoded action and a switch immediately following the Arguments opening tag match; ordinary PowerShell and non-PowerShell tasks do not; missing TaskContent is rejected.

Fixture source: [`fixtures/DET-004.json`](../../fixtures/DET-004.json). The `expected` field is a detection expectation, not an incident label. A common false-positive scenario can still match and receive a benign-positive disposition.

## Sources

Official references reviewed on 2026-09-07. ATT&CK association describes observable behavior and review intent; it is not a claim of complete technique coverage.

- [Official reference 1](https://attack.mitre.org/techniques/T1053/005/)
- [Official reference 2](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698)
