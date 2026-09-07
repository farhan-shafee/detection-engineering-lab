# Detection model and semantic boundary

[`catalog.json`](catalog.json) is the authoritative metadata list for five experimental detections. Each entry supplies a stable DET ID, purpose and hypothesis, exact channel and event IDs, ATT&CK rationale, owner and version, Sigma and fixture references, Wazuh mapping, benign test, false positives, tuning, triage, escalation, limitations and validation instructions. The individual detection documents explain the same model for an analyst.

| Detection | What the implementation observes | What it does not establish |
| --- | --- | --- |
| DET-001 | Sysmon 1: PowerShell process with an encoded switch, subject to a scoped lab exception | Malicious content or attacker intent |
| DET-002 | Security 4732: member added to group SID S-1-5-32-544 | Account creation, actual privilege use or persistence intent |
| DET-003 | Five 4625 failures then a 4624 success within 300 seconds on one four-field key | Same human actor, brute-force intent or compromise |
| DET-004 | Security 4698: task content includes PowerShell and an encoded switch | Task execution or malicious persistence |
| DET-005 | Sysmon 1: Word, Excel or Outlook recorded as parent of PowerShell | Macro, phishing, exploit or document identity |

## Where the logic lives

Four single-event detections evaluate their actual Sigma predicates against canonical fixtures. The supported subset is field maps with AND semantics, value lists with OR semantics, exact string/integer values, `endswith`, `contains`, `re`, and conditions `selection` or `selection and not filter`. Unsupported conditions/modifiers fail validation rather than silently becoming permissive.

DET-003 is an explicit Python sequence: group by `Computer`, `TargetUserName`, `TargetDomainName`, `IpAddress`; require at least five unique failed logons strictly before the success within an inclusive 300-second lookback; clear the group history after each success. Events are sorted by timestamp and deduplicated by host, channel and record ID. The two Sigma files are event selectors only. A failure AND success conjunction on a single event would be impossible, so no equivalent Sigma correlation deployment is claimed.

Canonical input validation enforces source/channel and required typed fields before matching. Invalid records are rejected, not treated as benign telemetry. Fixtures label those cases `malformed` and expect no match. A missing match cannot distinguish missing telemetry from absent behavior in a live environment; telemetry health is a separate production requirement.

## ATT&CK, Sigma and Wazuh

ATT&CK labels describe defensible behavioral associations with explicit rationale. They do not measure adversary coverage. T1098.007 describes privileged group membership more accurately than the former account-creation claim. T1110 remains a hypothesis rather than proof of password guessing. Office lineage supports PowerShell execution review and does not establish T1204 user execution.

The Sigma files use canonical Windows event fields. Wazuh rules require native decoder fields and deployment verification. DET-001's Wazuh candidate retains the broad signal, while the offline exception demonstrates a controlled tuning lifecycle. DET-003 is a documented mapping, with no live Wazuh sequence implementation. See [Sigma field mapping](../sigma-rules/README.md).

## Evidence and disposition

Every fixture case is an independent evaluation. `expected: true` means the detector should match. `false_positive` is a scenario category for common benign noise; it can legitimately retain a positive match. The analyst selects `benign positive`, `false positive`, `needs more information`, or `true positive / escalated` based on evidence and explicit scenario assumptions. These are simulated case decisions, not real incidents or enterprise escalations.

[Investigation JSON and readable examples](../evidence/investigations/README.md) separate event observations, inference, scenario assumptions and next steps. [Tuning](../evidence/tuning/README.md) preserves before-rule logic, the investigated noise case and regression expectations. Generated report metrics should be obtained by running the demo; these documents are source material, not captured live evidence.

Authentication component selectors are evaluated when assigning failures and successes, so additional reviewed predicates affect the actual correlation. Both component roles must remain unambiguous Security4625/4624 selectors. Failures tied exactly with a same-key success are conservatively excluded from both correlation episodes; record-ID order cannot prove chronology.
