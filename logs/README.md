# Retained legacy synthetic examples

These two JSON files are retained from the original portfolio for historical context. They are synthetic, incomplete samples, not captured Windows telemetry and not the inputs to the flagship demo. Mixed legacy fields are not supported by the new normalized event contract.

`sample_logs.json` contains one failure and one success; it cannot prove five or six failures, guessing, owner denial or incident response. `windows/windows_security_events.json` lacks complete timestamps/ancestry and cannot establish a correlated account-creation incident. The encoded string is inert sample text and is never executed by repository code.

Use `fixtures/DET-*.json` for reproducible validation. The evidence manifest also hashes these legacy files, but they are excluded from demo fixture coverage and alert counts.
