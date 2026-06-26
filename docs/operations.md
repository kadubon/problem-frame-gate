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
```

Use PyPI trusted publishing.  Avoid long-lived publishing tokens.

Production manifests should pin:

- executor writer id;
- certificate family issuers;
- protected action constructors;
- capacity limits;
- risk modes;
- environment assumptions.
