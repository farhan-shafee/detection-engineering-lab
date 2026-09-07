# Security and operability review

Review date: **2026-09-07**. Scope: the Python engine/CLI, loaders, evidence and
report paths, PowerShell wrappers, detection fixtures, Wazuh configuration and
setup instructions, dependency choices and CI. This is a source/configuration
review with local checks. It is not a penetration test or proof of a deployed
SIEM's security.

## Material findings addressed

| Finding | Change and verification |
|---|---|
| Upstream Wazuh Compose publishes unnecessary ports and includes demonstration credentials | Added an overlay replacing complete port lists; require three operator-generated credentials, matching indexer hashes and API configuration before startup; remove unused default demo users in the fresh private clone |
| Ordinary Compose merge could retain wildcard bindings beside loopback bindings | Used `!override`; an actual Compose 5.5.0 render of the pinned upstream source plus overlay confirmed manager loopback 1514/1515, dashboard loopback 8443, and no indexer/API/syslog host bindings |
| A documented optional deployment could be mistaken for a tested live environment | Kept runtime validation pending, separate empty live-evidence status, and acceptance checks for every collection/analysis boundary |
| Indexer certificates could be mistaken for manager API/enrollment trust | Documented their separate TLS configurations and the current private container-network/loopback boundary |
| Malformed raw input could leak through sanitizer error messages | Replaced timestamp-derived exceptions and sanitizer CLI details with generic errors; regression checks cover malformed timestamps, JSON and duplicate keys containing a sensitive marker |
| Latest pySigma dependency chain introduced vulnerable `diskcache` | Selected parser-compatible `pySigma==0.11.23`, removing that dependency instead of suppressing an advisory; dependency audit returned zero known vulnerabilities in the final validated environment |
| Backend labels and implementation scope could be confused | Aligned DET-001 through DET-005 labels, documented four candidate native rules, DET-003 mapping only, and explicit Sigma/offline/Wazuh differences |

The initial `pySigma` 1.5.0 resolution included `diskcache` affected by
**[CVE-2025-69872](https://github.com/advisories/GHSA-w8v5-vhqr-4h9v)**. The lab does not use caching or deserialize cache entries, but
retaining a known vulnerable dependency would weaken an interview artifact.
The compatible parser pin removes the dependency. No vulnerability was ignored
or waived; CI reruns `pip-audit` because advisories and transitive resolutions
can change. A clean audit is a point-in-time result, not a guarantee against
unknown vulnerabilities.

## Checks performed

- **Python input boundaries:** reviewed repository-contained path resolution,
  absolute/drive/UNC/traversal rejection, symlink escape rejection, 2 MB JSON/YAML
  read limits, duplicate mapping rejection, YAML aliases disabled, and the
  loader's inheritance from `yaml.SafeLoader`. No dynamic object constructors,
  `eval`, shell invocation, subprocess execution, network client or pickle
  loader exists in the offline implementation.
- **Evidence and output:** fixture paths are integrity checked; the manifest
  normalizes CRLF to LF explicitly. Sanitization drops unknown fields, raw
  commands, task XML, identities and paths; it is an intentionally lossy summary,
  not an automatic live-event anonymizer. Output paths stay within the selected
  repository, and sanitizer output cannot overwrite an existing file. Markdown
  tables escape HTML and row delimiters.
- **Semantics:** reviewed channel/event gating, required field checks,
  duplicate-record removal, strict preceding-event ordering, inclusive 300-second
  boundary, four-field identity grouping and success resets for DET-003. The
  controlled rule/fixture repository is the trust boundary for regexes; this
  is not a service accepting arbitrary public detection programs.
- **PowerShell:** both live helper scripts passed the Windows PowerShell parser;
  default preview and `-Execute -WhatIf` passed. The generator has one fixed
  UTF-16LE encoded payload that prints `DETECTION-LAB-SAFE`, with no downloaded
  payload, task/user creation, network target, registry mutation, security
  setting change or temporary-resource cleanup. The health helper prints only
  channel availability/event ID/time and service status; it creates no capture.
- **Wazuh XML:** all three supplied XML files parsed. Native decoding and
  hierarchy/precedence still need manager logtest and real endpoint events.
- **Compose:** official tag `v4.14.7` was resolved to commit
  `adcc5b57d2f7edfcbe6c399272dc76fbdf12b623`. Daemon-free rendering confirmed
  three 4.14.7 service images, `restart: no`, the intended port removal, and no
  privileged/host-network configuration. A separate render with missing
  credentials failed before startup. Only dummy process-local values were
  used, and only non-secret fields were printed.
- **Repository guardrails:** the local scan returned zero findings for its
  credential patterns, prohibited key/raw-evidence files, PowerShell primitives,
  workflow permissions/action pins and Compose hazards. These are targeted
  checks, not a general secret scanner.
- **Bandit:** local scan of `detection_lab` and `scripts` returned zero findings,
  with no skipped findings. The final regression run passed **28 tests**,
  including the sanitizer error-output fix and symlink boundary test.
- **CI configuration:** inspected `contents: read`, no private secrets, no
  `pull_request_target`, full action commit pins and checkout credentials
  disabled. Windows and Ubuntu jobs run offline tests/security checks. Remote
  job completion is recorded separately in the final validation report.

## Remaining boundaries and unverified behavior

The live environment was **not started**. No agent was installed, audit policy
changed, Sysmon configured, malicious or encoded payload executed, event
exported, manager logtest run, or live screenshot created. Docker Compose
configuration parsing does not validate certificate generation, password/hash
consistency, image startup, volumes, WSL2 forwarding, enrollment or ingestion.
The optional recipe requires a current patched Docker Desktop engine;
[engines before 28.0.0 had a localhost-port exposure caveat](https://docs.docker.com/engine/network/port-publishing/).
The same-host route follows [Docker's documented forwarding model](https://docs.docker.com/desktop/features/networking/),
but actual acceptance requires its three explicit local port checks and full
telemetry chain. It is not a LAN deployment recipe.

The credential setup intentionally requires operator-generated secrets and
manual matching configuration/hash edits. It is concrete and documented, but
not an unattended installer. The API and enrollment trust path remains a
separate operator validation step. Image tags are version pinned, not digest
pinned; record actual RepoDigests for a live run. Containers and Docker access
remain privileged administrative infrastructure even without `privileged:
true`; protect their persistent volumes and private configuration.

All published analyst decisions are simulated, all current matches use authored
fixtures, and the live capture count remains zero. Windows data can contain
secrets, document paths and personal information. `.gitignore` helps prevent
accidental commits but can be overridden; review staged changes and sanitized
captures manually. The integrity manifest detects changes against the reviewed
state but does not establish authenticity or an external chain of custody.
The lossy sanitizer deliberately cannot preserve detection semantics; do not
relabel its output as a faithful live fixture.

The offline tool assumes a local operator controls the repository. It is not a
multi-user server, a general Sigma engine, a case-management integration, or an
enterprise response platform. Arbitrary regex complexity, very deeply nested
documents, concurrent filesystem races and organizational retention/RBAC are
outside that scope. Keep validation in a bounded CI job and use reviewed
fixtures; reassess those boundaries before accepting untrusted external input
at service scale.

See [the live setup](live-lab.md), [telemetry and rollback](telemetry.md), and
[live evidence status](../evidence/live/README.md) for the precise operating
boundary. Final test/audit and GitHub Actions outcomes belong to
`docs/validation.md`; no unobserved remote result is asserted here.
