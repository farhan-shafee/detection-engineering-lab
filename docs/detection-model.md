# Detection model and validation contract

The human-readable model is [detections/detection_logic.md](../detections/detection_logic.md), the machine-readable source is [catalog.json](../detections/catalog.json), and validation is implemented in [model.py](../detection_lab/model.py). This is an enforced repository-specific contract, not a claim of full Sigma schema conformance.

`validate` requires unique DET IDs and nonzero unique Sigma UUIDs; semantic versions; owner/title/status/purpose/hypothesis; Windows channel and event IDs; severity; ATT&CK technique formatting, tactic and rationale; documented false positives, triage, escalation and limitations; safe in-repository Sigma/fixture paths; and explicit Wazuh implementation limitations. Every fixture set must include all five scenario categories and positive/negative outcomes. Investigations must reference existing cases and record IDs, choose a supported disposition, and state missing context explicitly.

YAML is parsed with a `SafeLoader` subclass that rejects duplicate keys and aliases, then parsed by pySigma with lazy condition parsing forced. The local matcher deliberately supports only the predicates documented in [sigma-rules/README.md](../sigma-rules/README.md). Unknown conditions, modifiers and wildcards fail closed. Changing a field predicate changes the single-event results; assertions compare those results with authored expectations. The authentication sequence is implemented separately in Python and has dedicated ordering, boundary, identity-isolation and deduplication tests. Its two Sigma files only document/select the input event types.

Records require a timestamp with timezone, source-scoped record ID, host, integer event ID, correct channel and event-specific fields. Logon source addresses must parse as IP addresses; absent values such as `-` cannot correlate. Sorting supports out-of-order fixture input, and duplicate `(Computer, Channel, record_id)` records do not inflate counts. The demo is batch evaluation, not a streaming late-arrival/watermark implementation. Conflicting duplicate records and event-log reset epochs need an adapter policy before live use.

The source contract is intentionally minimal. It does not prove a record's publisher, normalize XML, authenticate a process, reconstruct missing script blocks or guarantee that a real collector supplies the fields. [Wazuh mapping](../lab/wazuh/README.md) and [telemetry health](telemetry.md) are separate validation boundaries.

## Evidence integrity and reports

`evidence/fixtures/manifest.json` records sorted source paths, canonical byte counts and SHA-256 values. CRLF is normalized to LF before hashing to make Windows and Linux checkouts equivalent. This is integrity against a reviewed manifest, not a cryptographic signature or proof of capture origin. Source hashes include current Sigma, fixtures, catalog, investigations, tuning sources and legacy JSON logs. Reports are generated independently and compared with tracked golden files to avoid self-referential hashes.

A normal `demo` run cannot bless changed evidence. After deliberately changing source material, inspect the diff, run `python -m detection_lab manifest --refresh`, then generate and review reports. CI only checks the committed manifest and reports. Fixture cases are independent regression scenarios; their alert/disposition counts are not representative SOC metrics. No MTTD, MTTR, population precision or adversary coverage percentage is calculated.

## Publication sanitization

`python -m detection_lab sanitize .local/input.json .local/review-summary.json` accepts normalized JSON and writes a new, deliberately lossy summary. It drops unknown fields, command lines, task XML, account/SID details and machine paths; replaces host/IP identity; and retains only known process basenames. It never executes or decodes a command. Input reads are bounded to 2 MB and artifact paths must resolve inside the repository, including symlink checks.

The summary loses data needed to rerun detections. Keep originals private, manually review the output, and publish only after the provenance requirements in [evidence/live](../evidence/live/README.md) are met. Timestamps and known executable names remain, so this helper is not a guarantee of anonymity. A sanitized fixture is still a fixture. Repository regex rules are trusted code-like configuration; arbitrary unreviewed regex authoring is not an exposed service.

Equal-time ordering policy: a failure sharing an exact timestamp and correlation key with a selected success is excluded from both episodes. A record ID cannot establish which event happened first. Tests rename tied records and verify that no later alert changes; a different-host success cannot suppress another host's failures.
