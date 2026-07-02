from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from problem_frame_gate import DispatchResult, GateCommitter, GateRequest, Horizon, MemoryAppendOnlyStore, OutboxBroker
from problem_frame_gate.model import Envelope

ROOT = Path(__file__).resolve().parents[1]


class FakeDispatcher:
    def dispatch(self, request: dict[str, Any]) -> DispatchResult:
        return DispatchResult(True, {"accepted_outbox": request["outbox_id"]})


def main() -> int:
    horizon = Horizon.from_mapping(json.loads((ROOT / "docs/examples/horizon.json").read_text(encoding="utf-8")))
    log = tuple(
        Envelope.from_mapping(item)
        for item in json.loads((ROOT / "docs/examples/log.json").read_text(encoding="utf-8"))
    )
    request = GateRequest.from_mapping(
        json.loads((ROOT / "docs/examples/gate-request.json").read_text(encoding="utf-8"))
    )
    store = MemoryAppendOnlyStore(log)
    commit = GateCommitter(store).commit_gate(horizon, request)
    if not commit.ok:
        print(json.dumps(commit.to_json(), indent=2, sort_keys=True))
        return 1
    dispatched = OutboxBroker(store, FakeDispatcher()).poll_once(horizon)
    print(json.dumps(dispatched.to_json(), indent=2, sort_keys=True))
    return 0 if dispatched.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
