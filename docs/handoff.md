# Interview-grade lab handoff

## Before and after

Before: 21 files, three brief detection writeups, four structurally checked Sigma files, five incomplete synthetic records, no executable detector or unit tests, and a report containing unsupported volume/response claims. Two Sigma rules incorrectly conjoined mutually exclusive event IDs. The offline nature was already honestly disclosed.

After: five versioned detection contracts, six parsed Sigma rules, a bounded semantic evaluator and actual authentication correlation, 51 deterministic cases, six evidence-linked investigations, four dispositions, a preserved tuning lifecycle, checked source hashes, generated reports and cross-platform CI. Existing Git history and legacy samples remain. Unsupported incident claims and the placeholder rule were removed.

## Exact architecture and capability boundary

**Optional, not demonstrated live:** controlled Windows endpoint → Security / PowerShell / optional Sysmon / Defender Event Channels → Wazuh agent → Wazuh manager decoding and custom/built-in rules → alert JSON → Filebeat → Wazuh indexer → dashboard/search → analyst evidence and triage → disposition/proposed escalation → tuning and validation. The planned single-node stack uses Wazuh 4.14.7, upstream commit `adcc5b57d2f7edfcbe6c399272dc76fbdf12b623`, same-host loopback 1514/1515 and dashboard8443; indexer/API stay unexposed to the host.

**Working deterministic path:** fixture JSON + catalog/Sigma → Python validation and matching → regression alert queue → record-linked investigation → explicit simulated disposition → before/after tuning and positive/negative regression → JSON/Markdown reports. Sigma predicates drive single-event matching and input classification for authentication correlation; Python owns its sequence semantics. Native Wazuh rules are manually mapped experimental candidates, not automatic Sigma compilation.

No real Wazuh events, agent activity, endpoint captures or screenshots are committed. All investigative owner statements, approvals, escalation and response processes are explicitly simulated. Nothing claims production SOC operations, enterprise administration, real attackers or real incident response.

## Detections and evidence

| ID | Behavior | Evidence / limit |
|---|---|---|
| DET-001 | Encoded PowerShell | Sysmon-shaped fixtures and exact automation tuning; encoding is not malicious intent |
| DET-002 | Local Administrators membership addition | Security4732 and group SID; no account-creation claim |
| DET-003 | ≥5 failures strictly before success within300s, same host/account/domain/IP | Security4625/4624 fixtures; cannot prove guessing or the same human actor |
| DET-004 | Encoded PowerShell in registered task content | Security4698 fixtures; no execution claim |
| DET-005 | Office parent spawning PowerShell | Sysmon1 fixtures; no document/macro attribution |

[Generated evidence](../reports/demo.md), [source manifest](../evidence/fixtures/manifest.json), [investigations](../evidence/investigations/) and [tuning history](../evidence/tuning/) provide inspectable artifacts. Fixture metrics are small-sample regression counts, not SOC effectiveness or latency estimates. [Validation](validation.md) records exact test and CI results.

## Adversarial review and material fixes

| Reviewer | Finding / resolution |
|---|---|
| SOC hiring manager | Original response actions lacked evidence; replaced with observations, explicit gaps and simulated next steps. One auth case deliberately remains uncertain. |
| Senior detection engineer | Impossible event conjunctions, misleading membership scope, selector drift and timestamp-tie ordering were corrected. Actual Sigma predicates and temporal edge cases have regression tests. |
| Senior security engineer | Safe bounded parsing, path containment, lossy publication summaries and non-echoing sanitizer failures. Removed a vulnerable transitive dependency; no advisory ignored. Compose merge checked with the real CLI; no all-interface service exposure or Docker socket. |
| Skeptical interviewer | Generated report now includes fictional assumptions separately; hashes described as integrity rather than authenticity; Wazuh live parity and capture remain unverified. |
| Recruiter / ATS | Skills linked to inspectable code and artifacts; live/production Wazuh administration and incident-response claims explicitly excluded. |

Remaining limitations: hand-authored normalized fixtures; a deliberately limited Sigma language; batch in-memory correlation without streaming watermarks or performance guarantees; no raw Windows/Wazuh adapter; no actual decoder/index/runtime proof; no representative production baseline, response integrations or HA. Exact exceptions can still hide abuse of an approved context and require review. See [security review](security-review.md) and [production discussion](production.md).

## Exact pitch and demonstration

**30 seconds:** “I built a detection-as-code lab around five Windows security behaviors. The offline demo validates Sigma rules against deterministic telemetry, produces an alert queue, links analyst investigations and dispositions, and tests a documented tuning change. I can trace each alert to fixture records, separate observations from scenario assumptions, and show cases that must not match. I also documented a version-pinned Windows-to-Wazuh collection path, but have not captured live Wazuh evidence. This demonstrates rule engineering and triage reasoning without claiming production incidents.”

**Three minutes:** 0:00 README architecture and scope; 0:25 run `python -m detection_lab demo`; 0:50 inspect INV-003 in `reports/demo.md`; 1:20 show DET-003 metadata, T1110 hypothesis and actual four-field300-second engine; 1:45 inspect DET-001 before/after rule and10→9 tuning; 2:25 run `python -m detection_lab demo --check`, explain metrics and next live acceptance steps. The [interview guide](interview-demo.md) supplies the exact screens, wording, ten-minute version and twelve challenge questions with evidence-based answers.

Expect challenges on whether Wazuh actually ran, whether Base64 implies an attack, whether Sigma implements the correlation, what4732/4698 establish, identity-isolation and timestamp boundaries, exception abuse, why an older parser is pinned, what hashes prove and what breaks at scale. Answer with the observed evidence and explicitly state gaps.

## Truthful résumé bullets

- Built a Python detection-as-code lab with five Windows behavior detections, six Sigma rules and51 deterministic regression cases covering positive, negative, malformed and temporal-boundary scenarios.
- Developed six evidence-linked analyst investigation examples with explicit dispositions, scenario assumptions and proposed escalation criteria; demonstrated a scoped tuning change that retained all nine intended DET-001 positives.
- Implemented cross-platform validation, deterministic reports, evidence hashing, safe parsing and sanitization; documented a pinned Wazuh/Windows telemetry lab with explicit live-verification requirements.

Avoid “administered enterprise Wazuh,” “responded to real incidents,” “stopped attackers,” “reduced SOC false positives by10%” or invented MTTD/MTTR. The10→9 tuning result is one authored fixture set, not a production reduction.

Suggested repository description: **Windows detection-as-code lab with Sigma, deterministic fixtures, analyst triage, tuning evidence and an optional pinned Wazuh setup.**

Suggested topics: `detection-engineering`, `sigma`, `windows-event-logs`, `sysmon`, `wazuh`, `soc`, `security-operations`, `mitre-attack`, `python`, `powershell`, `security-automation`, `portfolio`.

## Files and Git handoff

Core: `detection_lab/`, `detections/`, `sigma-rules/`, `fixtures/`, `tests/`, `scripts/`, `requirements-dev.txt`, `pyproject.toml`.
Evidence: `evidence/fixtures/manifest.json`, `evidence/investigations/`, `evidence/tuning/`, `reports/demo.json`, `reports/demo.md`; empty live-evidence status/template.
Live path: `lab/wazuh/`, `demo/generate-safe-events.ps1`, `demo/verify-telemetry.ps1`, `docs/live-lab.md`, `docs/telemetry.md`.
Demo/operations: `demo/run-demo.ps1`, README, contribution/security guidance, Makefile, ignore/line-ending rules, CI and the docs linked above. Unrelated existing work was absent and historical logs were retained.

Commit hashes and the final remote CI link are recorded after push in [validation.md](validation.md) and the task's final handoff. No force-push or rewriting remote history is part of this workflow.
