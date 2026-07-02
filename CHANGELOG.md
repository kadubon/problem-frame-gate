# Changelog

## 1.1.0

- Added strict SHA-256 digest validation shared by runtime checkers and schema validation.
- Added append-only `MemoryAppendOnlyStore` and stdlib `SQLiteAppendOnlyStore` with atomic compare-and-append semantics.
- Added `GateCommitter` so accepted gate bundles can be durably appended before any external dispatch.
- Added `OutboxBroker` and dispatcher protocol that dispatch only after durable `OutboxClaim` and `DispatchStarted` rows.
- Added optional clock/watermark providers for gate source cuts.
- Added signature verifier registry hooks for certificate issue rows.
- Added standard finite risk-route registry and production/example profiles.
- Strengthened join liveness repair checks for capabilities, outboxes, resource leases, and risk spends.
- Added `pfg report`, `pfg probe run`, and `pfg reachability verify/explain`.
- Added unsafe fixture probes and a verification benchmark script.

## 1.0.0

- First stable release with strict manifest, gate bundles, source cuts, risk claims, certificate-family checks, patch/join preservation checks, typed reachability, JSON schemas, CLI, docs, CI, and PyPI Trusted Publishing.
