from __future__ import annotations

import re
from pathlib import Path


def test_readme_python_example_executes() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    match = re.search(r"```python\n(.*?)\n```", readme, flags=re.DOTALL)
    assert match is not None
    namespace: dict[str, object] = {}
    exec(compile(match.group(1), "README.md", "exec"), namespace)  # noqa: S102
    result = namespace["gate"].check(namespace["horizon"], namespace["log"], namespace["request"])
    assert result.ok
