"""Generate a small dependency SBOM without runtime dependencies."""

from __future__ import annotations

import argparse
import json
from importlib import metadata
from pathlib import Path
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a minimal CycloneDX-style SBOM")
    parser.add_argument("--output", required=True, help="Path to write the SBOM JSON")
    args = parser.parse_args()
    Path(args.output).write_text(json.dumps(build_sbom(), indent=2, sort_keys=True), encoding="utf-8")
    return 0


def build_sbom() -> dict[str, Any]:
    components = []
    for dist in sorted(metadata.distributions(), key=lambda item: canonical_name(item.metadata["Name"])):
        name = dist.metadata["Name"]
        components.append(
            {
                "type": "library",
                "name": name,
                "version": dist.version,
                "purl": f"pkg:pypi/{canonical_name(name)}@{dist.version}",
                "licenses": license_entries(dist.metadata.get_all("License", [])),
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {"component": {"type": "library", "name": "problem-frame-gate"}},
        "components": components,
    }


def canonical_name(name: str) -> str:
    return name.lower().replace("_", "-")


def license_entries(values: list[str]) -> list[dict[str, dict[str, str]]]:
    if not values:
        return []
    return [{"license": {"name": value}} for value in values if value]


if __name__ == "__main__":
    raise SystemExit(main())
