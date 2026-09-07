# Deterministic event fixtures

The five DET JSON files contain hand-authored normalized Windows-shaped telemetry. Hosts, account names, SIDs, timestamps and activity are fictional. Source addresses use the RFC 5737 documentation range. None is an exported Windows event, real Wazuh alert, proof of account activity or screenshot.

Each file contains `detection_id`, provenance and independent `cases`. Each case has `id`, `category`, boolean `expected`, `events` and `description`. Cases must not share correlation state. The category describes the scenario; `expected` describes whether the current detector should match.

- `baseline`: ordinary valid activity that does not match.
- `positive`: target behavior or a regression that should remain visible.
- `near_miss`: valid telemetry close to the logic but outside its predicates, grouping, threshold or window.
- `false_positive`: common benign noise context. Most remain matching signals for analyst disposition. DET-001's approved automation stops matching only after the narrowly scoped exception.
- `malformed`: deliberately missing or invalid required fields, including an inconsistent event/channel combination. Reject these records before matching.

All valid records have a UTC `timestamp`, source-scoped string `record_id`, integer `EventID`, `Channel` and `Computer`. Process records add image, parent, command and user. Authentication records add target account, domain and source IP. Membership records distinguish actor, member SID and group SID. Task records retain task name, action text and actor. The minimal schema omits many fields a real analyst would request, such as signed image identity, full process ancestry, auth status codes and complete task trigger/principal configuration; investigation examples explicitly identify those gaps.

Encoded payloads are harmless output markers. The demo only reads data; it never executes an event command, submits passwords, registers a task, creates an account or impersonates an Office parent process. Treat any future untrusted log content as data as well.

Run the repository validation and demo commands to evaluate these fixtures, including time-window boundaries and controlled tuning. The generated evidence manifest hashes source files; a hash establishes file integrity relative to that manifest, not that the data originated on a real endpoint.
