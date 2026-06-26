# Schema

The stable JSON schemas are in `schemas/`:

- `horizon.schema.json`: strict manifest.
- `envelope-log.schema.json`: append-only audit log.
- `gate-request.schema.json`: action gate request.
- `gate-bundle.schema.json`: five-row executor bundle.
- `source-cut.schema.json`: finite source prefix witness.
- `replay-certificate.schema.json`: non-canonical replay certificate.
- `risk-claim.schema.json`: risk route witness.
- `patch-proposal.schema.json`: append-only patch witness.
- `join-proposal.schema.json`: branch join witness.
- `reachability.schema.json`: accepted transition transcript.

The CLI `pfg validate-schema` uses the internal validator in
`problem_frame_gate.schema`.  It checks the schema subset used by this project:

- JSON type;
- required fields;
- fixed constants and enum values;
- array item types and bounded prefix items;
- `additionalProperties`;
- string length and numeric minimums.
- project patterns for SHA-256 digests and finite fraction strings.

It is not a general JSON Schema 2020-12 implementation.  This is intentional:
runtime dependencies stay at zero, and the supported schema contract is small
enough to port to other languages.

Use the complete examples first:

```bash
pfg validate-schema horizon docs/examples/horizon.json
pfg validate-schema log docs/examples/log.json
pfg validate-schema gate-request docs/examples/gate-request.json
```

Strict certificate rows should use a finite `family_check` object:

```json
{
  "accepted": true,
  "checker": "example-certificate-family-v1",
  "transcript_digest": "sha256:...",
  "dependency_digest": "sha256:...",
  "revocation_frontier": [],
  "checked_at": 2,
  "assumption": "CertificateFamilyChecker"
}
```

Boolean flags such as `family_check: true` are legacy assumptions and fail
strict v1 checks.

Gate requests must carry an accepted `risk_claim` with a finite route witness.
The checker does not prove the statistical model itself; the manifest must name
that assumption, or the deployment must register a concrete checker.

Digest strings use `sha256:` followed by 64 lowercase hexadecimal characters.
Risk spend and alpha values use finite fraction strings such as `0`, `1/100`,
or `3/10`.
