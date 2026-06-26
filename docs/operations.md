# Operations

Recommended release checks:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
uv run bandit -c pyproject.toml -r src
uv run pip-audit
uv build
uv run python scripts/generate_sbom.py --output sbom.json
uv run python -m json.tool sbom.json
```

Use PyPI trusted publishing.  Avoid long-lived publishing tokens.
Tagged releases should also attest the built `dist/*` artifacts in GitHub
Actions before publishing to PyPI.

Production manifests should pin:

- executor writer id;
- certificate family issuers;
- protected action constructors;
- capacity limits;
- risk modes;
- environment assumptions.

## Operational Boundary

Use the library as an audit and authorization layer.  A production deployment
still needs:

- durable append-only storage;
- service identity and key management for writers and issuers;
- a sandbox or broker for external tools;
- monitoring for actuator failures and missing receipts;
- incident response for rejected, blocked, or fail-closed actions;
- a compatibility policy for JSON schema changes.

For v1.x, avoid changing existing field names or checker issue codes unless the
change closes a safety hole.  Add new optional fields before making a required
field mandatory.
