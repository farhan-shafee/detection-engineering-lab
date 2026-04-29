# Alert Investigation Example: Brute Force Success After Failures

## Alert context

- Rule: `Windows Brute Force Success After Failures`
- Severity: High
- Host: `wkstn-014`
- User: `jdoe`

## Analyst workflow

1. Confirm failed logon burst from same IP.
2. Verify immediate successful logon.
3. Check whether IP appears for other users in same timeframe.
4. Review endpoint telemetry for post-authentication process execution.
5. Escalate if suspicious behavior follows authentication.

## Example finding

Observed 6 failed authentications followed by success from uncommon external source IP. User reported no login attempt at that time.

## Outcome

- Account password reset.
- Sessions revoked.
- Source IP blocked at perimeter controls.
- Case escalated for threat hunt across identity logs.
