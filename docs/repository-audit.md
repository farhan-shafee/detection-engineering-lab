# Repository audit and implementation plan

Audit performed 2026-09-07 against `4b61aaa`, before changing repository content.
All 21 tracked files were read; the working tree was clean on `main`. There were
no repository or ancestor `AGENTS.md` instructions. Existing history is retained.

| Area | Before | Required change |
|---|---|---|
| Structure / README | Small, clearly labelled synthetic portfolio; Unix `make` entry point | Preserve offline operation; add Python CLI and PowerShell wrapper |
| Rules | Four YAML files, including an example successful-logon rule with unsupported T1078 implication | Five scoped detections; remove placeholder rule |
| Logic | `fail and success` and `create_user and add_admin_group` require mutually exclusive IDs on one event | Explicit sequence engine; membership-only scope; honest Sigma component mapping |
| Validation / tests | Regex-based key presence and JSON parsing only; no tests | Safe YAML parser, pySigma parsing, metadata and semantic fixture checks |
| Logs | Five synthetic records, mixed field names, absent timestamps/parents in some records | Preserve as labelled legacy samples; canonical deterministic fixture contract |
| Reports | Claimed six failures, user interview, password reset and perimeter blocking absent from evidence | Replace with evidence-linked observations and explicitly simulated decisions |
| ATT&CK | Account creation/admin membership and successful login overclaimed technique support | Map observed behavior, document inference and blind spots |
| CI | One Ubuntu/Python job; mutable action tags; implicit token permissions | SHA-pinned actions, Windows/Linux, lint, tests, security and golden report checks |
| Security | No obvious stored secrets or payload execution; regex validator cannot enforce safe semantics | Strict parsers, bounded inputs, path containment, sanitization, ignored live secrets/raw data |
| Live telemetry | No collector, agent, SIEM, enrollment or real evidence | Optional version-pinned Wazuh instructions and safe event preview; no invented capture |
| Interview usability | No executable alerts, fixture counts, dispositions or tuning | One-command repeatable workflow with actual generated evidence |

Implementation order:

1. Build five detection contracts, Sigma rules and balanced fixtures; correct unsupported claims.
2. Implement deterministic matching, investigation linkage, metrics, tuning regression and evidence integrity.
3. Document the controlled Windows → Wazuh path and add reversible safe activity/verification scripts.
4. Add cross-platform checks and a clear README, architecture, interview guide and production discussion.
5. Run local, clean-export and CI checks; review as hiring manager, detection engineer, security engineer,
   interviewer and recruiter; fix material findings before committing and pushing when authentication permits.

Initial environment observations: Python 3.14.7 and PowerShell are available. Docker CLI is installed
but its daemon was unavailable; WSL enumeration was denied in the restricted environment. Initial GitHub
CLI authentication/network checks failed in that environment. These are observations, not proof that
the user has no usable credentials or WSL installation. Live infrastructure is optional and no endpoint
security settings were changed during this audit.
