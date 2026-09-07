# Authentication sequence investigation

The current worked case is [INV-003](../../evidence/investigations/INV-003.json), generated in [the demo report](../demo.md). Its deterministic positive fixture contains five 4625 failures followed by one 4624 success within 120 seconds for the same host, domain, account and documentation-range source IP.

**Observation:** the implemented sequence threshold is met. **Inference:** guessing is one possible explanation; mistyped credentials remain plausible. **SIMULATED disposition:** needs more information. Owner confirmation, failure reasons and post-logon activity would determine whether to escalate.

No real user was interviewed, no credentials were reset, no sessions were revoked and no source was blocked. The legacy two-record sample cannot support the older report's six-failure claim.
