# Detection Methodology (Portfolio)

## 1) Hypothesis-driven detection

Start from attacker behavior, not a single event code. Define what malicious sequence should look like.

## 2) Data source mapping

List exact telemetry needed (event IDs, process fields, user context, network context).

## 3) ATT&CK mapping

Map each detection to the closest ATT&CK technique and tactic to standardize communication.

## 4) Rule authoring

Implement rule logic in Sigma for portability. Keep rule names action-oriented and specific.

## 5) Validation and tuning

Perform syntax validation, run rule against sample logs, and add false positive suppression notes.

## 6) Investigation readiness

Include triage steps and escalation criteria so analysts can act consistently.
