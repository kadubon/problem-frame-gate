# PyPI Release Preparation

This repository is prepared for PyPI distribution but does not publish by
itself.  Use PyPI trusted publishing from GitHub Actions.

## Local Checks

```bash
uv sync --all-extras
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
uv run bandit -c pyproject.toml -r src
uv run pip-audit
uv build
```

## Versioning

Update both:

- `pyproject.toml`
- `src/problem_frame_gate/_version.py`

Then tag:

```bash
git tag -a v1.1.0 -m "problem-frame-gate v1.1.0"
git push origin v1.1.0
```

The release workflow builds the package and publishes from the GitHub
workflow file `.github/workflows/workflow.yml`.

## Trusted Publishing

Configure a pending PyPI trusted publisher before pushing the tag:

- Owner: `kadubon`
- Repository: `problem-frame-gate`
- Workflow: `workflow.yml`
- Environment: leave blank / Any

The workflow uses GitHub OIDC and does not require a PyPI API token.
