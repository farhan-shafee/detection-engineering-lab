# Security Policy

## Scope

This repository is a portfolio lab and does not operate production services.

## Reporting a vulnerability

Please open a private security advisory or contact the maintainer through repository security reporting features.

Include:
- Affected file(s)
- Proof of concept
- Impact assessment
- Suggested remediation

## Supported versions

Best effort support on the latest `main` branch content.

## Defensive lab boundaries

All activity belongs on controlled local systems. The offline CLI reads fixtures and never executes their commands. The optional generator uses only one fixed harmless output payload and previews by default. No script changes security policies, privileges or accounts, registers tasks, tests passwords, scans targets or automates containment.

Raw live data, secrets, certificates and private runtime configuration belong only in ignored local storage. Manual review of staged files remains required; ignore rules and pattern scans are not a guarantee of sanitization. See [the security review](docs/security-review.md) for implemented checks, dependency decisions and remaining boundaries. Report vulnerabilities privately through GitHub security reporting; do not post credentials, sensitive logs or working harmful payloads in public issues.
