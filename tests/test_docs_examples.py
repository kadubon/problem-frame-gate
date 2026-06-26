from __future__ import annotations

import re
from pathlib import Path

from problem_frame_gate.cli import main


def test_readme_python_example_executes() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    match = re.search(r"```python\n(.*?)\n```", readme, flags=re.DOTALL)
    assert match is not None
    namespace: dict[str, object] = {}
    exec(compile(match.group(1), "README.md", "exec"), namespace)  # noqa: S102
    result = namespace["gate"].check(namespace["horizon"], namespace["log"], namespace["request"])
    assert result.ok


def test_quickstart_json_examples_execute() -> None:
    horizon = "docs/examples/horizon.json"
    log = "docs/examples/log.json"
    request = "docs/examples/gate-request.json"

    assert main(["validate-schema", "horizon", horizon]) == 0
    assert main(["validate-schema", "log", log]) == 0
    assert main(["validate-schema", "gate-request", request]) == 0
    assert main(["verify-log", "--horizon", horizon, log]) == 0
    assert main(["check-gate", "--horizon", horizon, "--bundle", request, log]) == 0
