# Suspicious PowerShell Encoded Command

- **Severity:** Medium
- **Data Source:** Windows PowerShell / Process Creation logs (4688, Script Block logs)
- **ATT&CK Technique:** T1059.001 - Command and Scripting Interpreter: PowerShell
- **Sigma Rule:** `sigma-rules/windows_powershell_encoded.yml`

## Detection hypothesis

Use of `-EncodedCommand` in PowerShell can indicate obfuscation used by offensive tooling.

## False positive notes

- Legitimate automation frameworks using encoded scripts.
- IT packaging/deployment solutions.

## Triage steps

1. Decode command safely in sandbox.
2. Identify parent process and initiating user.
3. Check for outbound network activity and payload staging.
4. Compare behavior against known admin baselines.
