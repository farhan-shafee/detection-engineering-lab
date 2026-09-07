# DET-003: Repeated authentication failures followed by success

**Evidence class: DETERMINISTIC telemetry fixtures; SIMULATED analyst decisions.** No live execution, Wazuh alert, compromise or incident is established by this document.

Status: **experimental** | Severity: **high** | Version: **2.0.0** | Owner: Detection Engineering Lab maintainer

## Purpose and hypothesis

Demonstrate sequence engineering, identity grouping, threshold boundaries and careful authentication triage.

Five failed logons followed by a success in five minutes may justify investigating password guessing; mistypes and stored credentials can produce the same sequence.

## Required telemetry

Channel: `Security`. Event IDs: 4625, 4624.

Audit Logon success and failure enabled. Security 4625 and 4624 require Computer, TargetUserName, TargetDomainName, IpAddress and timezone-aware timestamp.

## Logic

Deduplicate by Computer + Channel + record_id, sort by timestamp, and group by Computer + TargetUserName + TargetDomainName + IpAddress. A success (4624) alerts if at least five failures (4625) are strictly earlier and no more than 300 seconds old (inclusive). Every success clears that group failure history. Equal-timestamp ordering is insufficient. Each fixture case is evaluated as a separate episode.

Sigma: [`sigma-rules/windows_authentication_failure.yml`](../../sigma-rules/windows_authentication_failure.yml), [`sigma-rules/windows_authentication_success.yml`](../../sigma-rules/windows_authentication_success.yml).

Wazuh mapping: `mapping_only`; rule IDs: none.

- Experimental candidate; not verified against a running Wazuh manager or captured events.
- Native win.eventdata field casing and channel decoding must be confirmed in the deployed version.
- No deployed Wazuh sequence implementation is claimed. Use the documented field mapping and explicit Python correlation offline.
- The two Sigma components select event types only; neither represents the complete analytic. A native correlation translation needs separate ordering, cardinality, grouping and window validation.

## ATT&CK association

- [T1110](https://attack.mitre.org/techniques/T1110/), `credential_access`: A repeated-failure pattern is a candidate brute-force signal; evidence does not establish guessing intent or distinguish password spraying across accounts.

## Common benign explanations

- A user repeatedly mistypes a password before a legitimate success.
- An application retries an outdated credential before a valid session is established.
- Shared source addresses can make actor attribution ambiguous even when the grouping key matches.

## Tuning decisions

- Keep host and account domain in the key to prevent cross-system or same-name account mixing.
- Tune thresholds only after observing authentication type, service context, lockout policy and true baseline.
- Investigate common benign episodes with disposition context; do not remove every login by a known source.

## Analyst triage

1. Read the five contributing failures and later success; verify record identities, exact elapsed time, source IP and all grouping fields.
2. Review LogonType, authentication package and failure status/substatus when captured; those fields inform triage but are not predicates in this lab.
3. Confirm with the account owner whether the successful logon and failure series were expected; check password reset and service changes.
4. Request follow-on session/process activity, endpoint history and identity-provider evidence when available; preserve uncertainty if evidence is absent.

## Escalation criteria

- Escalate if the successful logon is denied by its owner, targets a critical identity, or is corroborated by abnormal post-authentication behavior.
- Keep needs more information when the sequence is real in the dataset but authorization and actor intent remain unknown.

## Limitations

- Deterministic correlation operates on supplied records and timestamps; no watermark, ingestion-delay budget or distributed state store exists.
- Only valid IP addresses are accepted; local logons with a dash or absent IpAddress are excluded.
- A source IP is not a reliable human identity, and same-IP grouping does not prove the failures and success had the same actor.
- This per-account analytic does not establish password spraying, successful compromise or Valid Accounts technique use.

## Benign test and validation

Use fixtures only. Do not induce account lockouts, submit password guesses, or contact authentication services for this demonstration.

Fixture suite covers threshold4/5, inclusive300/excluded301 seconds, group-key separation, earlier/equal success, out-of-order input, reset after success, benign retries and missing source identity.

Fixture source: [`fixtures/DET-003.json`](../../fixtures/DET-003.json). The `expected` field is a detection expectation, not an incident label. A common false-positive scenario can still match and receive a benign-positive disposition.

## Sources

Official references reviewed on 2026-09-07. ATT&CK association describes observable behavior and review intent; it is not a claim of complete technique coverage.

- [Official reference 1](https://attack.mitre.org/techniques/T1110/)
- [Official reference 2](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html)
