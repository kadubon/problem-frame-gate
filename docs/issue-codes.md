# Issue Codes

Checker results use stable issue codes so operators can route failures without
parsing prose messages.

| Code | Meaning | Typical fix |
| --- | --- | --- |
| `incomplete-manifest` | Strict manifest is missing a required safety table. | Start from `pfg init-manifest` and fill capacities, writer authority, protected constructors, certificate families, and risk modes. |
| `protected-writer-authority` | A protected constructor was written by a non-executor writer. | Route `GateCheck`, `OutboxClaim`, `UseCap`, `ConsumeResource`, and `RiskClose` through the executor gate only. |
| `gate-bundle-coherence` | The five gate rows do not bind the same request tuple. | Recreate the bundle from one accepted `GateRequest`. |
| `gate-semantic-transcript` | Embedded `GateCheck` transcript does not replay. | Re-run `ExecutorGate.check()` on the same source prefix and registry/assumption policy. |
| `gate-risk-claim-missing` | Strict gate request has no accepted risk claim. | Add a `RiskClaimRecord` with route witness and declared assumption or registered checker. |
| `risk-claim-eta` | Risk claim spend is not a finite fraction string. | Use values such as `0`, `1/100`, or `3/10`. |
| `risk-alpha-format` | Risk budget is not a finite fraction string. | Use the same fraction format as risk spend values. |
| `risk-alpha-bound` | Finite risk spend exceeds the declared budget. | Lower spend, increase the declared bound, or split the decision. |
| `certificate-family-unregistered` | Strict certificate has no registered checker or declared assumption. | Register a `CertificateFamily` checker or declare the assumption in the manifest. |
| `source-cut-digest` | Source cut digest does not match included rows. | Recompute the source cut from the exact prefix. |
| `patch-affected-completeness` | A touched invariant was not listed for recheck. | Add the invariant to `affected_invariants` and provide a read/touch witness. |
| `join-liveness-repair` | A branch conflict lacks a folded and rechecked repair witness. | Add repair rows and typed repair witnesses for the conflict key. |
| `reach-witness-payload` | Reachability transition is digest-only. | Include a typed witness payload for `patch`, `join`, `gate`, `abort`, or `failClosed`. |
| `reach-transcript-digest` | Reachability witness replay does not match the transcript digest. | Recompute the transition witness with the same checker and manifest. |
| `sensitive-payload` | Log payload contains secret-looking data or a local machine path. | Replace raw secrets and local paths with stable identifiers or digests. |

Commercial deployments should treat every error issue as fail-closed. Warning
issues indicate weaker assumptions and should be reviewed before production use.
