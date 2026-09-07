# Wazuh backend candidates and field mapping

Use [the complete setup recipe](../../docs/live-lab.md). This directory has four
original custom XML rules, channel collection fragments, a safe Compose overlay,
and a verified upstream source pin. **Wazuh runtime validation is pending.**
XML well-formedness and offline fixture matches do not prove native decoding,
index mappings, installed parent rule IDs, or rule precedence.

| Detection | Wazuh implementation | Evidence needed before claiming a working live rule |
|---|---|---|
| DET-001 | `110001`: Sysmon process image and encoded-command token | Sysmon 1 decoded image/commandLine and logtest positive/negative; this is the untuned candidate, not the fixture-specific suppression |
| DET-002 | `110002`: Security 4732 with targetSid `S-1-5-32-544` | Native group SID, actor and member fields; this proves membership addition, not account creation |
| DET-003 | Mapping only, **no custom Wazuh correlation rule** | Sequence of 4625 then 4624 with Computer, targetUserName, targetDomainName, ipAddress; Python is the implemented reference |
| DET-004 | `110005`: Security 4698 taskContent with PowerShell and encoded token | Non-truncated task XML and exact decoder field spelling; registration does not prove execution |
| DET-005 | `110006`: Sysmon 1 Office parent to PowerShell child | Native parentImage and image, plus parent GUID/document context for triage |

| Canonical fixture/Sigma field | Expected Wazuh rule field | Dashboard JSON field |
|---|---|---|
| `EventID` | `win.system.eventID` | `data.win.system.eventID` |
| `Channel` | `win.system.channel` | `data.win.system.channel` |
| `Computer` | `win.system.computer` | `data.win.system.computer` |
| `Image` | `win.eventdata.image` | `data.win.eventdata.image` |
| `CommandLine` | `win.eventdata.commandLine` | `data.win.eventdata.commandLine` |
| `ParentImage` | `win.eventdata.parentImage` | `data.win.eventdata.parentImage` |
| `User` (Sysmon) | `win.eventdata.user` | `data.win.eventdata.user` |
| `TargetSid` | `win.eventdata.targetSid` | `data.win.eventdata.targetSid` |
| `TargetUserName` | `win.eventdata.targetUserName` | `data.win.eventdata.targetUserName` |
| `TargetDomainName` | `win.eventdata.targetDomainName` | `data.win.eventdata.targetDomainName` |
| `IpAddress` | `win.eventdata.ipAddress` | `data.win.eventdata.ipAddress` |
| `TaskContent` | `win.eventdata.taskContent` | `data.win.eventdata.taskContent` |

These are expected native Windows eventchannel decoder names, not a general
import format. The pinned upstream [Windows base rules](https://github.com/wazuh/wazuh/blob/v4.14.7/ruleset/rules/0575-win-base_rules.xml)
define parent `60001`, and [Sysmon rules](https://github.com/wazuh/wazuh/blob/v4.14.7/ruleset/rules/0595-win-sysmon_rules.xml)
define `sysmon_event1`. Confirm those parents in the deployed version. Provider
names, capitalization, escaped XML, event versions and Windows localization can
affect what is decoded. Field names are case-sensitive. Missing fields must not
be interpreted as a negative result without first verifying collection health.

`wazuh-logtest` input must represent the serialized event the manager actually
receives, using decoder `windows_eventchannel`; an exported alert wrapper with
outer `data` fields, a raw Event Viewer XML document, or a canonical Python
fixture may take a different decoding path. Read its Phase 2 output, preserve
the observed fields, and adapt a separately documented input only if required.
Record any normalization rather than pretending it is raw telemetry.

DET-003 requires at least five **preceding** 4625 events within an inclusive 300s
window before 4624, grouped by all four fields, with deterministic ordering and
missing-field behavior. Wazuh `frequency` rules have different state/counting
and ordering semantics. This repo does not provide or claim an equivalent
Wazuh rule; use indexed events for analyst review or develop and validate a
separate backend correlation implementation. Never put 4624 and 4625 in a
same-event AND condition.

An event satisfying DET-001 and DET-005 may produce one final Wazuh rule rather
than the two matches emitted by the offline engine. Built-in rules may also
win the hierarchy. Confirm the actual final ID with logtest and live data;
engine alert counts are not promised to equal Wazuh alert counts. The offline
DET-001 tuning allowlist is deliberately not deployed: its synthetic `LAB`
identity and exact command are not evidence of trusted real automation. A real
exception needs reviewed identity, parent, full command, owner and expiry.

Sigma describes the detection hypothesis and selected field semantics. It is
not installed by Wazuh, automatically converted here, or certified portable to
arbitrary SIEMs. Native PCRE2 token matching is a reviewed candidate mapping;
validate actual decoder data and both positive and near-miss examples before
deployment. The planned live exercise generates only the DET-001 harmless
process. DET-002–005 remain deterministic demonstrations unless independently
captured and documented on an explicitly controlled system.
