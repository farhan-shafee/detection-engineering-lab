# Analyst investigation examples

These examples use **DETERMINISTIC** fixture events and **SIMULATED** analyst decisions. They include no real incident, enterprise case-management integration, owner communication or response action. Each JSON source has a readable Markdown companion.

| Case | Detection and fixture | Disposition | Evidence boundary |
| --- | --- | --- | --- |
| [INV-001](INV-001.md) | DET-001 / approved-automation | false positive | Historical before-rule noise; after-rule suppression verified separately |
| [INV-002](INV-002.md) | DET-002 / positive | true positive / escalated | Privileged addition observed; unapproved status comes from fictional owner context |
| [INV-003](INV-003.md) | DET-003 / positive | needs more information | Authentication sequence observed; authorization and intent unknown |
| [INV-004](INV-004.md) | DET-004 / positive | needs more information | Registered task action text observed; execution and approval unknown |
| [INV-005](INV-005.md) | DET-005 / approved-addin | benign positive | Lineage matches; fictional add-in approval explains benign cause |
| [INV-006](INV-006.md) | DET-001 / positive | benign positive | Interactive harmless encoded test remains visible after scoped tuning |

`evidence_refs` resolves to original records in each referenced fixture case. `observations` states what the events contain. `inferences` records interpretation and uncertainty. `scenario_assumptions` makes fictional owner statements and approval records explicit. `next_steps` explains what authorized analysts would request or recommend; those actions have not been performed.

A behavioral match is a signal. A benign positive means the behavior was detected correctly and is approved. In INV-001, false positive is used relative to the refined *unapproved encoded execution context* hypothesis and motivates a narrow suppression. Both terms are analyst decisions, distinct from the fixture category and the detector's boolean result. Historical suppressed noise must not be counted as a current alert.
