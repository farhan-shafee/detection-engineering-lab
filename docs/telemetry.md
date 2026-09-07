# Windows telemetry design

The checked-in event data is deterministic fixture data. This document and the
collection fragments describe optional collection; neither proves a channel is
enabled, subscribed, or indexed on a real endpoint. See
[live-lab.md](live-lab.md) for the path from source to analyst disposition.

## Source requirements

| Source / channel | Availability | Lab events and purpose | Explicit setup |
|---|---|---|---|
| `Security` | Windows channel normally exists; individual audits depend on effective policy |4624/4625 successful/failed logon (DET-003);4732 membership addition (DET-002);4698 task registration (DET-004) | Inspect audit subcategories; enable only those required in the isolated lab |
| `Microsoft-Windows-PowerShell/Operational` | Windows PowerShell provider is normally present; useful 4103/4104 coverage is policy-dependent |4104 script content and 4103 module activity enrich process triage; these are not the Sysmon-based DET-001 predicate | Script Block Logging and optional module logging deliberately enabled for the capture window |
| `Microsoft-Windows-Sysmon/Operational` | **Optional; absent unless Sysmon installed** |1 process creation with image, command line, parent and process GUIDs for DET-001/DET-005 | Install verified Microsoft Sysmon and review its configuration |
| `Microsoft-Windows-Windows Defender/Operational` | Depends on Windows edition, Defender installation and operating mode |1116 detection,1117 action and 5007 configuration change, for context only | Select an existing enabled provider; no disabling security controls or malware generation |
| `PowerShellCore/Operational` | **Optional PowerShell 7 provider**, separate from Windows PowerShell | Additional 4104 context if separately configured | Not part of the supplied collection fragment or health script |

Windows event IDs are meaningful together with provider and channel. Event 1 in
an unrelated channel is not Sysmon process creation. Wazuh's Windows agent
normally collects System, Application and Security; add the other channels
deliberately and avoid duplicate subscriptions. See the [official eventchannel
collection reference](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html).

Run `demo/verify-telemetry.ps1` to inspect channel enablement and the latest
selected event within a bounded lookback. The script reads the channels and
Wazuh service state; it prints no messages, identities or command lines, writes
no capture, changes no policy and does not contact a SIEM. `UnavailableOrAccessDenied`
is deliberately inconclusive. Inspect permissions separately; Security reads
may require an elevated prompt. `EnabledNoRecentMatchingEvent` is not proof
of broken collection. `EnabledQueryFailed` means the query itself needs review.

## Security auditing: deliberate and reversible

Inspect effective policy locally before changes (`auditpol /get /category:*`).
Do not copy this output into Git; it is host configuration. Record the previous
state of each subcategory privately. In Local Security Policy on a standalone
lab host, navigate to Advanced Audit Policy Configuration and review:

| Subcategory | Setting needed for this lab | What it establishes |
|---|---|---|
| Logon/Logoff → Audit Logon | Success and Failure |4624/4625 events; grouping still requires usable account/domain/source fields |
| Account Management → Audit Security Group Management | Success |4732 addition to a local security group; check `TargetSid` against the built-in Administrators SID |
| Object Access → Audit Other Object Access Events | Success |4698 scheduled task registration with task content when available |

Configure only the selected settings and re-read effective policy. Group Policy
can override local configuration; do not fight organizational policy or change
a work-managed machine for a portfolio exercise. Roll back by restoring the
**recorded prior state** of those exact subcategories using the same interface,
then recheck effective policy. Never run `auditpol /clear`, blanket-disable
auditing, or restore an unrelated full-host policy snapshot. A snapshot/revert
of a dedicated VM is another controlled lab option.

The project does not create users, change administrator membership, register
tasks or exercise repeated bad passwords. Those detections use deterministic
fixtures, avoiding privilege changes, lockouts and leftover tasks. Detection
semantics follow Microsoft's event definitions: [4732](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732),
[4698](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698),
[4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)
and [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625).
4624/4625 come from the system where the logon is processed; these are not a
complete view of domain authentication, and a source address can be absent or
unusable. The offline detector rejects missing correlation keys rather than
joining unrelated identities.

## Optional Sysmon

Download Sysmon only from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
Verify the extracted executable's Authenticode status and Microsoft publisher,
record the actual binary version and SHA-256 privately, and read its license.
No binary is bundled or downloaded by repository scripts. Confirm whether
Sysmon is already managed before doing anything: never replace an existing
organization's Sysmon configuration with this small lab filter.

On a fresh controlled lab endpoint, after reviewing the signed executable and
[sysmon-process-create.xml](../lab/wazuh/sysmon-process-create.xml), an elevated
PowerShell installation is:

```powershell
.\Sysmon64.exe -i 'D:\path-to-repo\lab\wazuh\sysmon-process-create.xml'
```

Replace the example path with your checked-out file. Read and accept the EULA
interactively. Use the ARM64 executable on ARM64 systems. The supplied schema
4.82 configuration selects PowerShell/pwsh process creation and SHA-256 hashing;
it intentionally lacks general endpoint coverage. Inspect the installed
configuration with `Sysmon64.exe -c` and its supported schema with
`Sysmon64.exe -s`. The agent fragment forwards only Sysmon Event 1. Source Sysmon
can emit operational/configuration events independently of this forwarding
filter.

Run the fixed benign generator only after collection is configured. The child
process prints `DETECTION-LAB-SAFE`; no Office automation is used to manufacture
a parent-child relationship. Sysmon records parent information as observed by
the operating system; an unusual parent does not establish document execution
or user intent without related evidence.

Rollback: if this lab installed Sysmon on a previously unmonitored dedicated
endpoint, uninstall with its verified executable's documented `-u` option and
remove only the lab-added Sysmon Wazuh subscription. If you changed an existing
lab configuration instead, restore the retained original using `-c` and verify
it; do not uninstall someone else's monitor. Keep audit records and collected
evidence under the retention plan; do not clear Event Viewer logs as cleanup.

## PowerShell and Defender enrichment

For Windows PowerShell 5.1, record the existing Local Group Policy state at
Computer Configuration → Administrative Templates → Windows Components →
Windows PowerShell. Explicitly enable **Turn on PowerShell Script Block
Logging** for 4104; optional **Turn on Module Logging** can scope module names
such as `Microsoft.PowerShell.Utility` for the benign output command. Start a
new PowerShell session after the reviewed change. This is logging policy;
repository scripts do not change execution policy, bypass controls, modify
registry keys or weaken protections. If the endpoint blocks scripts, follow
its normal approved signing/review workflow or run the offline Python demo.

Script contents can include secrets and must be treated as sensitive. Restrict
collection and retention to the lab window, inspect data before export and
consider protected event logging for longer use. Full script-block text may
span multiple 4104 records, requiring reassembly by ScriptBlockId and message
number for an investigation. Restore only the two logging policies you changed
to their recorded previous values and open a new session to verify rollback.
See [Windows PowerShell logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1)
and [PowerShell 7's separate provider](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.5).

For Defender, collect existing events and leave protection enabled. An idle
healthy endpoint may have no 1116/1117 events. This lab contains no malware
simulation for that provider and defines no flagship Defender detection.
Availability, an empty channel and a detected threat are different observations.

## Telemetry-to-evidence acceptance

For DET-001, keep a single controlled chain: recorded action time → local
Sysmon 1 → active agent and error-free subscription → manager decode → indexed
alert → analyst review of the benign payload → benign-positive disposition.
Distinguish source time from collection/alert time. Use event record IDs and
process GUIDs to join related records; command text alone is weak linkage.

Security events identify the actor in `Subject*` fields and the changed/logged-on
entity in `Target*` fields.4732 also identifies the member. Sysmon `User` is the
process context. Keep those roles separate in the investigation. Source field
names and canonical fixture names differ from Wazuh decoder/index fields; use
[the explicit backend mapping](../lab/wazuh/README.md).

An alert index contains only events that reached an alerting threshold. Verify
quiet channels in an explicitly enabled short archive capture, following the
live setup guide. Monitor dropped events, queue pressure, clock synchronization,
retention and field truncation before treating missing hits as negatives.
Commit only manually reviewed sanitized evidence with the
[live provenance template](../evidence/live/README.md). No future procedure
in this document is a claim that the procedure has already run.
