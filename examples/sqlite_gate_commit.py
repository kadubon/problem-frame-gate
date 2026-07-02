from __future__ import annotations

import json
import tempfile
from pathlib import Path

from problem_frame_gate import GateCommitter, GateRequest, Horizon, SQLiteAppendOnlyStore
from problem_frame_gate.model import Envelope

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    horizon = Horizon.from_mapping(json.loads((ROOT / "docs/examples/horizon.json").read_text(encoding="utf-8")))
    log = tuple(
        Envelope.from_mapping(item)
        for item in json.loads((ROOT / "docs/examples/log.json").read_text(encoding="utf-8"))
    )
    request = GateRequest.from_mapping(
        json.loads((ROOT / "docs/examples/gate-request.json").read_text(encoding="utf-8"))
    )
    with tempfile.TemporaryDirectory() as tmp:
        store = SQLiteAppendOnlyStore(Path(tmp) / "audit.db")
        try:
            append = store.append_atomic(horizon, store.snapshot().digest, log)
            if not append.ok:
                print(json.dumps(append.to_json(), indent=2, sort_keys=True))
                return 1
            result = GateCommitter(store).commit_gate(horizon, request)
            print(json.dumps(result.to_json(), indent=2, sort_keys=True))
            return 0 if result.ok else 1
        finally:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
