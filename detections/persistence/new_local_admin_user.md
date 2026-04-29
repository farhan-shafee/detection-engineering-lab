# New Local Admin User Created

- **Severity:** High
- **Data Source:** Windows Security Event Logs (4720, 4732)
- **ATT&CK Technique:** T1136.001 - Create Account: Local Account
- **Sigma Rule:** `sigma-rules/windows_new_local_admin.yml`

## Detection hypothesis

Attackers often create local users and add them to administrators groups to persist after initial access.

## False positive notes

- Planned IT provisioning during device setup.
- Golden image/post-build automation.

## Triage steps

1. Identify actor account that created the user.
2. Review host criticality and recent admin activity.
3. Confirm change ticket/approved request.
4. Verify if user was later used for remote logon.
5. Disable account and investigate lateral movement if unauthorized.
