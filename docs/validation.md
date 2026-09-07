# Local and remote validation record

Validated on 2026-09-07. Environment: Windows, Python 3.14.7, isolated repository virtual environment. The normal demo is fully offline after dependencies are installed. The final GitHub Actions run is linked below after push; local results alone are not described as remote CI results.

| Check | Recorded result |
|---|---|
| Detection metadata and source references | 5 experimental contracts validated |
| Sigma parsing | 6 active rules accepted by safe YAML parsing, pySigma 0.11.23 and supported subset checks |
| Fixture semantics | 51/51 assertions passed: 23 expected matches, 28 expected nonmatches, including 6 malformed cases |
| Positive / negative coverage | 5/5 detections have both; each has all five scenario categories |
| Investigations | 6 worked cases across 5 detections; 4 disposition types, explicit simulated assumptions and evidence references |
| Tuning | DET-001, 16 before/after assertions; 10 → 9 matching cases; 1 known-noise case removed, all 9 intended positives retained |
| Demo regression queue | 23 fixture alerts; not a population alert rate or incident count |
| Unit tests | 28/28 passed locally; clean export also passed all 28, zero skips |
| Lint / formatting | Ruff lint and format checks passed |
| Evidence integrity / golden comparison | Passed in the working checkout and clean source export |
| Security patterns / Bandit | 84 publishable files scanned with no findings; Bandit zero findings and zero suppressions |
| Dependencies | Compatible pySigma pin avoids vulnerable diskcache; pip check and pip-audit passed, no advisory exclusions |
| Windows wrapper | `demo/run-demo.ps1 -Check` passed in PowerShell 7. Windows PowerShell 5.1 execution was blocked by local policy; policy was left unchanged, direct Python fallback passes |
| Safe generator | PowerShell parse, preview and `-Execute -WhatIf` passed; child process was not executed |
| Live configuration | 3 XML files parse; real Docker Compose static merge confirmed loopback bindings, pinned images and missing-credential rejection |
| Live runtime / capture | Not run: Docker daemon unavailable. No agent installed/enrolled, captured event, indexed Wazuh alert or screenshot |

## Commands

```text
python -m unittest discover -s tests -v
python -m ruff check .
python -m ruff format --check .
python -m detection_lab validate
python -m detection_lab demo --check
python scripts/security_check.py
python -m bandit -r detection_lab scripts
python -m pip check
python -m pip_audit
```

The security scan is a targeted repository guardrail, not proof that all secrets or vulnerabilities are impossible. The dependency audit is a point-in-time advisory check. pySigma 0.11.23 emits a pyparsing deprecation warning on this Python environment; it does not affect results. The parser version and accepted subset are explicit.

## Final verification and CI

Clean export: copied only publishable tracked/untracked source files into a new ignored export directory; no `.git` or `.venv` was copied. Using the isolated root interpreter with the export as working directory proved the module imported from the export. All 28 tests passed with no skips, validation passed 51/51, golden report comparison passed and the security scan passed. Local Markdown targets were also checked with no missing files. Windows PowerShell 5.1 policy prevented `-File` execution, so no execution-policy bypass was attempted; the PowerShell 7 wrapper and direct Python route passed.

Remote GitHub Actions: pending push and observed completion. This is not yet a claim of green remote CI. The final run and implementation commit hashes will be added after they are observed.

The exported demo was also run in write mode and reproduced both report files byte-for-byte. Export PowerShell 7.6.5 wrapper validation passed using the interpreter on PATH. Windows PowerShell 5.1.26100.8328 parsed the wrapper with zero syntax errors; its effective Restricted policy blocked execution. Policy was not changed.

Reviewed report SHA-256 values (LF output):

- JSON: `28c6cbbb803176400d4fe736fb3b74528f325cdca12d4ddb348c198c519666db`
- Markdown: `ca9970314411829b904c2e7bbf75b7fe2529e9450a78d560b94c44a174f7a147`
