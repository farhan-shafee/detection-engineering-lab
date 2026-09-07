# Interview demo

Prepare once: create the virtual environment and install `requirements-dev.txt`, run the checks in the README, then disconnect networking if desired. Open README, `reports/demo.md`, `sigma-rules/windows_powershell_encoded.yml`, `evidence/investigations/INV-003.json` and `evidence/tuning/README.md` before screen-sharing. Use an ordinary terminal; no Wazuh or elevated prompt is needed. If a script policy blocks the wrapper, invoke `.venv\Scripts\python.exe -m detection_lab demo` directly. Never improvise endpoint auditing changes during an interview.

## Exact 30-second pitch

> I built a detection-as-code lab around five Windows security behaviors. The offline demo validates Sigma rules against deterministic telemetry, produces an alert queue, links analyst investigations and dispositions, and tests a documented tuning change. I can trace each alert to fixture records, separate observations from scenario assumptions, and show cases that must not match. I also documented a version-pinned Windows-to-Wazuh collection path, but have not captured live Wazuh evidence. This demonstrates rule engineering and triage reasoning without claiming production incidents.

## Exact three-minute screen-share sequence

| Time | Screen / action | Say and show |
|---|---|---|
| 0:00–0:25 | README architecture | “The lower path is reproducible offline. The upper Windows → agent → manager → indexer → dashboard path is optional and has not been run here. Detection occurs in the manager before indexing.” |
| 0:25–0:50 | Run `python -m detection_lab demo`, or `.\demo\run-demo.ps1` | Read the **actual** fixture count, zero live captures, and generated report paths. No network or secret is needed after dependency installation. |
| 0:50–1:20 | `reports/demo.md`, INV-003 section | Show five failed logons and the following success using six contributing record IDs. The disposition remains **needs more information** because the data cannot establish guessing or compromise. |
| 1:20–1:45 | `detections/catalog.json`, DET-003, then `detection_lab/engine.py` | Explain ≥5 unique failures, strictly before success, inclusive 300 seconds, same host/account/domain/IP. T1110 is a behavioral hypothesis; the two Sigma selectors do not perform correlation. |
| 1:45–2:25 | `evidence/tuning/README.md`, before YAML and current encoded-PowerShell rule | Show the exact benign automation exception and case-sensitive Base64 comparison. Actual fixture matches fall 10 → 9; nine intended positives remain. Changed user, parent, payload and appended arguments still alert. |
| 2:25–3:00 | `reports/demo.md` metrics; run `python -m detection_lab demo --check` | Golden comparison proves repeatability. Explain false positive versus benign positive, six documented investigations, and the next validation step: captured native Windows/Wazuh fields. |

These are rehearsal timings, not measured detection/response latencies. All owner statements and escalations are fictional scenario context. If an interviewer chooses another alert, its JSON includes the exact records and either a linked investigation or an explicit unreviewed default.

## Ten-minute version

- **0–2 minutes — telemetry:** explain channel availability versus audit enablement, optional Sysmon, 4732 actor/member/group distinctions, and why 4104/Defender are enrichment rather than flagship detector inputs. Use `docs/telemetry.md`.
- **2–4 minutes — architecture and execution:** run the offline demo and inspect one alert's original records. Explain manager decoding/detection, Filebeat forwarding, indexing and dashboard search. Quiet channels need archive capture, not just an alert index.
- **4–6 minutes — rule engineering:** show canonical schema, safe parsing, pySigma validation, executable subset and auth window/grouping tests. State that normalized fixtures are not native Wazuh events. Use `sigma-rules/README.md` for field mappings.
- **6–8 minutes — triage and tuning:** contrast INV-002's simulated escalation with INV-003's uncertainty. Show historical INV-001 and its scoped exception, expiry context, before/after expectations and neighboring regression cases.
- **8–9 minutes — evidence and security:** distinguish fixture hashes from authenticity, read-only comparison from intentional regeneration, redaction from anonymity, and no subprocess execution of log content. Mention the dependency advisory found and removed.
- **9–10 minutes — production:** explain telemetry health, queue/late-event handling, rule ownership, RBAC, retention, deployment review and case management using `docs/production.md`. State which live checks remain undone.

## Likely interviewer challenges and evidence-based answers

| Challenge | Strong, truthful answer |
|---|---|
| “Did you actually deploy Wazuh?” | “No live deployment is evidenced here. I have a verified release pin, a loopback overlay, collection/rule candidates and acceptance instructions. I would show a real enrolled-agent record, native decoded event and matching indexed alert before changing that claim.” |
| “Why does encoded PowerShell imply an attack?” | “It does not. Encoding is a review signal; a fixed benign marker is one of the positives. I need decoded text, ancestry, identity and authorization context to decide.” |
| “Is your Sigma correlation valid?” | “There is no claim that two event selectors are a correlation rule. Python implements and tests the threshold, order, window and four-field grouping. Backend correlation needs its own deployment validation.” |
| “Does 4732 mean a new administrator account was created?” | “It proves membership addition to the specified group. Account creation requires separate 4720 or equivalent evidence; subsequent use needs further records.” |
| “How do you know the task ran?” | “I do not. 4698 is registration. The investigation asks for task execution history, principal/trigger and process evidence.” |
| “What if failures are on another domain, host or IP?” | “The correlation keys isolate them. Tests mutate each key and check that unrelated records cannot satisfy the threshold.” |
| “Could your exception hide malicious activity?” | “Yes, an actor using the approved context could be suppressed. It is an exact command, parent and user exception with review context, not a trust boundary. Changes remain tested positives; production needs governed ownership and expiry.” |
| “Are these precision or recall numbers?” | “No. They are assertion and outcome counts on an authored regression set. I would need labelled representative telemetry and analyst review to estimate those metrics.” |
| “What does the evidence hash prove?” | “The checked source bytes match the reviewed manifest after newline normalization. It does not prove those bytes came from Windows or that an incident occurred.” |
| “Why an older pySigma parser?” | “Newer releases pulled an unresolved diskcache advisory. The compatible parser pin avoids that dependency, passes our bounded syntax/semantic tests and a dependency audit, with no advisory ignored.” |
| “What breaks at scale?” | “Unbounded batch correlation, incomplete identity normalization, event-log epochs, late delivery, field loss and telemetry outages. I would add tested adapters, streaming policies, health controls and measured performance before deployment.” |
| “Did you respond to an incident?” | “No. Dispositions and escalation are tabletop decisions with explicit assumptions. Nothing contacted a real user, altered an account or sent a ticket.” |

## Optional live segment, after actual acceptance

Use `docs/live-lab.md` only when all prerequisites and permissions are already satisfied. The defensible story is one fixed harmless process → local Sysmon record → active Wazuh agent → native decoded manager event → indexed alert → benign-positive analyst disposition. Capture sanitized provenance after execution. If any boundary is unproven, say so and return to the deterministic demo; no screenshots are prebuilt.
