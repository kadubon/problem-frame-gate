# Quickstart

Problem Frame Gate is strict by default.  Start with a manifest:

```bash
pip install problem-frame-gate
pfg init-manifest > horizon.json
```

For a working JSON-only example, use the complete files in `docs/examples/`:

- `docs/examples/horizon.json`
- `docs/examples/log.json`
- `docs/examples/gate-request.json`

Validate the files and replay the log:

```bash
pfg validate-schema horizon docs/examples/horizon.json
pfg validate-schema log docs/examples/log.json
pfg verify-log --horizon docs/examples/horizon.json docs/examples/log.json
pfg fold --horizon docs/examples/horizon.json docs/examples/log.json
```

Before an AI system writes to an external tool, check the gate request and emit
the atomic five-row bundle:

```bash
pfg validate-schema gate-request docs/examples/gate-request.json
pfg check-gate --horizon docs/examples/horizon.json --bundle docs/examples/gate-request.json docs/examples/log.json
```

Only append and dispatch the returned five-row bundle after `ok` is true.

The minimal log contains:

- one active decision frame;
- one evidence row;
- one live certificate with a finite family-check record;
- one risk reserve and spend;
- one live resource lease;
- one unused capability;
- one authorized outbox.

The gate bundle binds:

- a source cut over the exact source prefix;
- a gate record and transcript digest;
- an accepted risk claim and route witness;
- an `OutboxClaim`;
- a `UseCap`;
- a `ConsumeResource`;
- a `RiskClose`.

The JSON files use the assumption route: the manifest declares
`CertificateFamilyChecker` and `StatisticalModel`, and each certificate/risk
witness names the assumption it relies on.  Python deployments that need
stronger local guarantees can register callable certificate-family and risk-mode
checkers; legal-log replay then uses the same registries.

For local development, use:

```bash
uv sync --all-extras
uv run pytest
```
