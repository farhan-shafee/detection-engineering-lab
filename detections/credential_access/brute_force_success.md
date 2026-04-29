# Brute Force Success After Failures

- **Severity:** High
- **Data Source:** Windows Security Event Logs (4625, 4624)
- **ATT&CK Technique:** T1110 - Brute Force
- **Sigma Rule:** `sigma-rules/windows_bruteforce_success.yml`

## Detection hypothesis

Multiple failed logons followed by a successful logon for the same account and host may indicate password guessing or spray activity.

## False positive notes

- Users forgetting passwords.
- Service accounts with outdated stored credentials.
- VPN reconnect storms after password reset.

## Triage steps

1. Confirm volume/timing of 4625 events before 4624.
2. Check source IP concentration across accounts.
3. Validate whether account is privileged.
4. Correlate with MFA failures/identity provider telemetry.
5. Contain account if suspicious (password reset, session revocation).
