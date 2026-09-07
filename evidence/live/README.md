# Live evidence status

**No live Wazuh or endpoint event captures are committed. No screenshots exist.**

The optional setup and XML are implementation artifacts, not evidence that an
agent was enrolled or a live detection fired. The deterministic fixtures and
generated investigations are stored separately. Docker/Wazuh runtime validation
was unavailable during implementation.

After a real controlled run, keep raw exports outside Git under `.local/`.
Manually review sanitized copies before adding them here. Redact user/host names,
SIDs, IPs, tokens, document paths and unrelated command lines consistently; retain
the field meaning, event IDs and timing relationships needed to assess the rule.
Screenshots need the same review. Never store agent keys, private certificates,
authentication headers or password hashes as evidence.

Each future capture must include a sidecar manifest with:

```json
{
  "evidence_kind": "live_sanitized",
  "capture_time_utc": "REQUIRED_ACTUAL_UTC_TIME",
  "event_time_utc": "REQUIRED_ACTUAL_UTC_TIME",
  "environment_alias": "LOCAL-LAB",
  "wazuh_version": "REQUIRED_OBSERVED_VERSION",
  "endpoint_alias": "LAB-WIN01",
  "source_channel": "REQUIRED_OBSERVED_CHANNEL",
  "event_ids": [],
  "event_record_ids": [],
  "wazuh_rule_ids": [],
  "activity": "REQUIRED_EXACT_ACTION",
  "sanitization": "REQUIRED_FIELDS_AND_TRANSFORMATIONS",
  "artifact": "REQUIRED_RELATIVE_SANITIZED_FILENAME",
  "sha256": "REQUIRED_HASH_OF_SANITIZED_ARTIFACT",
  "observation": "REQUIRED_FACTS_SEEN",
  "inference": "REQUIRED_ASSESSMENT_AND_UNCERTAINTY"
}
```

This is an unfilled schema example, **not a capture manifest**. Compute the hash
of the reviewed artifact with `Get-FileHash -Algorithm SHA256`; do not reuse a
fixture hash or invent a successful alert. A source event, manager receipt,
indexed alert and analyst disposition are separate pieces of evidence.
