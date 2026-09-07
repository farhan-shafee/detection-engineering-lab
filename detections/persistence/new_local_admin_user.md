# DET-002: Member added to local Administrators

**Evidence class: DETERMINISTIC telemetry fixtures; SIMULATED analyst decisions.** No live execution, Wazuh alert, compromise or incident is established by this document.

Status: **experimental** | Severity: **high** | Version: **2.0.0** | Owner: Detection Engineering Lab maintainer

## Purpose and hypothesis

Make a privileged membership change visible for authorization review without inventing account-creation evidence.

An unexpected addition to local Administrators can grant elevated access; authorization and subsequent activity determine whether to escalate.

## Required telemetry

Channel: `Security`. Event IDs: 4732.

Audit Security Group Management success auditing enabled; access to Security Event ID 4732 with TargetSid, MemberSid and SubjectUserName.

## Logic

Valid Security Event ID 4732 whose TargetSid equals S-1-5-32-544 exactly. Group names may be localized. SubjectUserName is the actor; MemberSid is the account added; TargetSid identifies the group. No 4720 account creation is required or inferred.

Sigma: [`sigma-rules/windows_new_local_admin.yml`](../../sigma-rules/windows_new_local_admin.yml).

Wazuh mapping: `custom_rule`; rule IDs: 110002.

- Experimental candidate; not verified against a running Wazuh manager or captured events.
- Native win.eventdata field casing and channel decoding must be confirmed in the deployed version.
- This is a single-event membership signal, not an account-creation or 4720-to-4732 sequence rule.

## ATT&CK association

- [T1098.007](https://attack.mitre.org/techniques/T1098/007/), `persistence`: Adding an account to a privileged local group is directly consistent with this technique, but persistence intent is not observable from one event.
- [T1098.007](https://attack.mitre.org/techniques/T1098/007/), `privilege_escalation`: The destination Administrators group grants a privileged membership; successful privilege use is not proven by the event.

## Common benign explanations

- Authorized endpoint provisioning and managed administrator assignment.
- Approved, time-bounded support or emergency access.

## Tuning decisions

- Use scoped host, actor, member and change-window context after confirming approval; avoid blanket suppressions for Administrators.
- Use the group SID to avoid localized-name drift.
- Retain membership change evidence even when alert routing is suppressed.

## Analyst triage

1. Identify the actor SubjectUserName, destination TargetSid, member MemberSid, host and time from the original event.
2. Resolve MemberSid using authorized directory/local account context; never confuse group TargetUserName with the new member.
3. Check the approved change record and expected privilege duration with the endpoint owner.
4. Request 4720 only if investigating account creation, 4733 for membership removal, and related 4624/4672 or process events for later privilege use.

## Escalation criteria

- Escalate an unapproved privileged membership change or unexplained member/actor identity to the designated owner.
- Recommend reversible removal only after authorization and evidence preservation; no live accounts are altered by this demo.

## Limitations

- One 4732 event cannot prove a new account was created, malicious persistence occurred, or the added member used privileges.
- Missing audit policy or event loss creates coverage gaps.
- Domain-group membership events and other privileged local group SIDs are outside this narrowly scoped rule.

## Benign test and validation

Use the deterministic 4732 fixtures. The default safe generator does not create accounts or modify local Administrators membership.

Positive and localized-name fixtures match; ordinary Users membership, a similar SID and missing MemberSid do not. INV-002 is a simulated escalation backed by fictional 4732 evidence.

Fixture source: [`fixtures/DET-002.json`](../../fixtures/DET-002.json). The `expected` field is a detection expectation, not an incident label. A common false-positive scenario can still match and receive a benign-positive disposition.

## Sources

Official references reviewed on 2026-09-07. ATT&CK association describes observable behavior and review intent; it is not a claim of complete technique coverage.

- [Official reference 1](https://attack.mitre.org/techniques/T1098/007/)
- [Official reference 2](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732)
