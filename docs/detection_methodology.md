# Detection engineering method

1. State a reviewable hypothesis and what the data can actually observe. Map ATT&CK behavior conservatively; an event match is not attacker intent.
2. Specify the source contract: provider/channel, event IDs, required fields, collection enablement and known missing context. Distinguish an unavailable source from a negative result.
3. Author a Sigma predicate or explicitly owned correlation. Record backend mappings and semantic gaps instead of assuming portability.
4. Test positive, baseline, near-miss, known-noise and malformed fixtures. Check boundaries and isolation across identities. Keep deterministic inputs independent from the optional SIEM.
5. Investigate the record, separate observation from inference, identify evidence gaps and choose a reasoned disposition. Record proposed response steps as proposed.
6. Tune from a documented noise case, preserve before/after rules, recheck all intended positives and adjacent cases, and give exceptions a review/expiry context.
7. Validate metadata, evidence hashes, deterministic reports, security and CI. Peer-review logic and generated evidence together before deployment.

See [model and limitations](detection-model.md), [worked investigations](../evidence/investigations/) and [the actual tuning lifecycle](../evidence/tuning/README.md). The production equivalent adds governed telemetry, deployment and response systems described in [production.md](production.md).
