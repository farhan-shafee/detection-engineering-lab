# Detection Engineering Portfolio Lab

> **Purpose:** This repository is a **portfolio lab** that demonstrates practical detection engineering workflows for SOC Analyst, Detection Engineer, and Security Analyst roles.
>
> It is intentionally scoped as a learning and showcase environment, **not** a production SOC deployment.

## What this lab demonstrates

- Writing and documenting detections from hypotheses.
- Mapping detections to **MITRE ATT&CK** techniques.
- Authoring and validating **Sigma** rules.
- Investigating alerts using sample logs and analyst playbooks.
- Communicating detection quality, false positives, and triage guidance.

## Repository workflow

1. **Define use case / tactic** (e.g., credential abuse, persistence).
2. **Draft detection metadata** (severity, data source, ATT&CK mapping, FPs, triage).
3. **Create Sigma rule** in `sigma-rules/`.
4. **Validate rule syntax** with local checks (`make test`).
5. **Test against sample logs** in `logs/`.
6. **Document investigation flow** in `reports/examples/`.
7. **Tune and record limitations** before publishing.

## Project structure

```text
.
├── detections/
│   ├── credential_access/
│   ├── execution/
│   ├── persistence/
│   └── detection_logic.md
├── docs/
│   └── detection_methodology.md
├── logs/
│   ├── sample_logs.json
│   └── windows/
├── reports/
│   ├── examples/
│   └── incident_analysis.md
├── scripts/
│   └── validate_rules.py
└── sigma-rules/
```

## Quick start

### Prerequisites

- Python 3.10+
- `make`

### Setup

```bash
git clone <repo-url>
cd detection-engineering-lab
make test
```

### Useful commands

```bash
make lint-rules    # Validate Sigma file structure/metadata
make test-logs     # Validate sample logs are parseable JSON
make test          # Run all checks
```

## Sample output

```text
$ make test
python3 scripts/validate_rules.py
Validated 4 Sigma rule(s): OK
python3 -m json.tool logs/sample_logs.json > /dev/null
python3 -m json.tool logs/windows/windows_security_events.json > /dev/null
All tests passed.
```

## Detection catalog (portfolio)

| Use Case | Rule | ATT&CK | Severity |
|---|---|---|---|
| Credential Access | Brute Force Success After Failures | T1110 (Brute Force) | High |
| Persistence | New Local Admin User Created | T1136.001 (Create Local Account) | High |
| Execution | Suspicious PowerShell Encoded Command | T1059.001 (PowerShell) | Medium |

See detailed metadata in `detections/*/*.md`.

## Limitations

- Synthetic data only; no live SIEM backend.
- Sigma rules are generic and may need backend-specific field mapping.
- Validation is structural (schema-lite), not full semantic conversion testing.
- Investigation reports are lab examples, not claims of production incident response.

## Ethical use

Use detections defensively for monitoring and threat detection improvements.

## License

This project is licensed under the MIT License (`LICENSE`).
