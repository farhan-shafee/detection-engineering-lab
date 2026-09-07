# Sigma representation and backend boundaries

The six active YAML files describe four single-event detectors and two authentication event selectors. They are experimental. Before-rule history lives under `evidence/tuning/` and is not an additional active detector.

The repository validates required metadata, UUIDs, Windows log sources, ATT&CK tags and a deliberately bounded executable Sigma subset. It evaluates actual YAML predicates against fixtures. This is meaningful local validation; it is not certification against every Sigma backend or the complete Sigma language. The [official rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html) and [correlation specification](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html) were reviewed on 2026-09-07.

## Supported semantics

- A selector is a field map: all fields must match.
- A field value can be a scalar or list: a listed value is sufficient.
- Plain strings, `endswith` and `contains` compare case insensitively; integer event IDs remain integers.
- `re` uses Python regular expression behavior, with explicit inline flags in these rules. Encoded-switch selection has `(?i)`; the approved base64 command uses a case-sensitive scope and whole-string anchors.
- The two supported conditions are `selection` and `selection and not filter`.
- Regex syntax, normalization and missing-field handling must be tested when translating to another query language.

Wildcards, aggregation, pipelines, arbitrary conditions, correlation YAML and backend transforms are outside the local evaluator. Unsupported syntax is rejected. A local semantic test does not validate actual Windows event collection, a Wazuh decoder, a search index or a running detection service.

## Required field mapping

| Canonical fixture/Sigma field | Windows event meaning | Wazuh candidate field to confirm |
| --- | --- | --- |
| EventID | System/EventID | win.system.eventID |
| Channel | System/Channel | win.system.channel |
| Computer | System/Computer | win.system.computer |
| timestamp | System/TimeCreated/@SystemTime | win.system.systemTime |
| record_id | System/EventRecordID, preserved with source identity | win.system.eventRecordID |
| Image, ParentImage, CommandLine, User | Sysmon process-create EventData | win.eventdata.image, parentImage, commandLine, user |
| TargetUserName, TargetDomainName, IpAddress | Security logon EventData | win.eventdata.targetUserName, targetDomainName, ipAddress |
| TargetSid, MemberSid, SubjectUserName | Security membership EventData | win.eventdata.targetSid, memberSid, subjectUserName |
| TaskName, TaskContent | Security task-registration EventData | win.eventdata.taskName, taskContent |

These native names are implementation candidates, not captured decoder evidence. Dashboard/index documents may add a `data.` prefix, while manager rules match decoded `win.*` fields. Confirm actual capitalization, scalar types, XML encoding, truncation and timestamps against Wazuh rule testing and searchable records. The detector does not automatically parse raw Windows XML or Wazuh envelopes into canonical JSON.

## Correlation and tuning

`windows_authentication_failure.yml` selects 4625, and `windows_authentication_success.yml` selects 4624. Neither alerts on the complete DET-003 pattern. Python owns ordering, grouping, threshold, deduplication and window semantics. Do not deploy either low-level selector as an incident alert or combine them with a single-event AND and call it correlation.

DET-001's exact safe-command filter is local lab policy. The base64 argument is case sensitive, so a case-insensitive exact-string comparison would unintentionally broaden the exception. This repository uses an anchored case-sensitive regex for the entire command. The regression fixture changes base64 casing and checks that the event remains visible. The Wazuh candidate is intentionally untuned until native field and rule behavior can be verified.
