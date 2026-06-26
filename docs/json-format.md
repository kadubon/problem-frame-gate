# JSON Format

All persistent data is ordinary JSON.  Digests use sorted object keys,
no insignificant whitespace, UTF-8, and SHA-256 with the prefix `sha256:`.

## Horizon

```json
{
  "strict": true,
  "events": ["e0", "e1"],
  "causal_order": [["e0", "e1"]],
  "availability_order": [["e0", "e1"]],
  "audit_order": [["e0", "e1"]],
  "capacities": {"normal": 100, "abort": 10, "failClosed": 1},
  "writer_authority": {
    "*": ["agent", "executor-gate"],
    "OutboxClaim": ["executor-gate"]
  },
  "version_intervals": {"*": [1, 1]},
  "commit_groups": {
    "bundle1": ["bundle1:0", "bundle1:1", "bundle1:2", "bundle1:3", "bundle1:4"]
  },
  "protected_constructors": {
    "GateCheck": ["executor-gate"],
    "OutboxClaim": ["executor-gate"],
    "UseCap": ["executor-gate"],
    "ConsumeResource": ["executor-gate"],
    "RiskClose": ["executor-gate"]
  },
  "gate_bundle_kinds": ["GateCheck", "OutboxClaim", "UseCap", "ConsumeResource", "RiskClose"],
  "executor_writer": "executor-gate",
  "clock_policy": "integer-commit-time",
  "certificate_families": {"risk": ["agent"]},
  "risk_modes": ["fixed", "selectedEvent", "conditionalSelective", "anytime"],
  "codebook": ["fixed", "selectedEvent", "conditionalSelective", "anytime"],
  "allow_local_paths": false
}
```

Empty safety tables are rejected in strict mode.  Use `pfg init-manifest` to
generate a safe starter manifest.

## Envelope

```json
{
  "eid": "e8",
  "event": "e8",
  "slot": "0",
  "commit": 8,
  "writer": "agent",
  "owner": "agent",
  "version": 1,
  "class": "normal",
  "payload": {
    "kind": "MintCap",
    "capability_id": "cap1",
    "frame_id": "p1",
    "action": "run-check"
  },
  "dependencies": [{"eid": "e3"}],
  "commit_group": "optional-group"
}
```

`payload.kind` is required.  Known object identifiers include `frame_id`,
`cert_id`, `capability_id`, `risk_id`, `outbox_id`, `lease_id`, `evidence_id`,
`source_id`, `gate_id`, and `object`.

## CLI

```bash
pfg digest horizon.json
pfg scan log.json
pfg verify-log --horizon horizon.json log.json
pfg fold --horizon horizon.json log.json
```
