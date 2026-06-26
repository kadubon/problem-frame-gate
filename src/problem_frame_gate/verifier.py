"""Finite legal-log verification and canonical ordering."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from itertools import pairwise

from .digest import digest_json
from .model import DEFAULT_GATE_BUNDLE_KINDS, DependencyRef, Envelope, EnvelopeClass, Horizon, OrderEdge
from .result import CheckBuilder, CheckResult
from .security import scan_for_sensitive_data


def digest_log(envelopes: Iterable[Envelope]) -> str:
    """Digest a log as an unordered finite set of envelopes."""

    return digest_json(sorted((env.to_json() for env in envelopes), key=lambda item: item["eid"]))


class EnvelopeVerifier:
    """Checker for the finite `LegalLog` conditions used by this package."""

    footprint = frozenset({"EnvelopeVerifier", "ClockWatermark"})

    def verify(self, horizon: Horizon, envelopes: Sequence[Envelope]) -> CheckResult:
        builder = CheckBuilder(footprint=set(self.footprint))
        self._check_horizon(horizon, builder)
        self._check_required_manifest(horizon, builder)
        id_map = self._check_unique_ids(envelopes, builder)
        self._check_payload_security(horizon, envelopes, builder)
        self._check_protected_slots(envelopes, builder)
        self._check_event_projection(horizon, envelopes, builder)
        self._check_dependencies(envelopes, id_map, builder)
        self._check_commit_groups(horizon, envelopes, id_map, builder)
        self._check_capacity(horizon, envelopes, builder)
        self._check_writer_authority(horizon, envelopes, builder)
        self._check_protected_constructor_authority(horizon, envelopes, builder)
        self._check_versions(horizon, envelopes, builder)
        self._check_gate_bundles(horizon, envelopes, builder)
        try:
            self.canonical_order(horizon, envelopes)
        except ValueError as exc:
            builder.error("canonical-order", str(exc))
        return builder.result(digest=digest_log(envelopes))

    def canonical_order(self, horizon: Horizon, envelopes: Sequence[Envelope]) -> tuple[Envelope, ...]:
        """Return the deterministic canonical linear extension.

        Ordering constraints are audit-order event edges, explicit dependency
        references, and declared commit-group sequence edges.
        """

        if not envelopes:
            return ()

        id_map = {env.eid: env for env in envelopes}
        env_by_event: dict[str, list[Envelope]] = defaultdict(list)
        for env in envelopes:
            env_by_event[env.event].append(env)

        successors: dict[str, set[str]] = {env.eid: set() for env in envelopes}
        indegree: dict[str, int] = {env.eid: 0 for env in envelopes}

        def add_edge(before: str, after: str) -> None:
            if before == after or after in successors[before]:
                return
            successors[before].add(after)
            indegree[after] += 1

        for edge in horizon.audit_order:
            for before_env in env_by_event.get(edge.before, ()):
                for after_env in env_by_event.get(edge.after, ()):
                    add_edge(before_env.eid, after_env.eid)

        for env in envelopes:
            for dep in env.dependencies:
                for dep_eid in _matching_dependency_eids(dep, envelopes):
                    if dep_eid in id_map:
                        add_edge(dep_eid, env.eid)

        for eids in horizon.commit_groups.values():
            present = [eid for eid in eids if eid in id_map]
            for before, after in pairwise(present):
                add_edge(before, after)

        event_rank = {event: index for index, event in enumerate(horizon.events)}

        def priority(eid: str) -> tuple[int, int, str, str]:
            env = id_map[eid]
            return (env.commit_time, event_rank.get(env.event, len(event_rank)), env.slot, env.eid)

        ready = sorted((eid for eid, degree in indegree.items() if degree == 0), key=priority)
        ordered: list[str] = []
        while ready:
            eid = ready.pop(0)
            ordered.append(eid)
            for child in sorted(successors[eid], key=priority):
                indegree[child] -= 1
                if indegree[child] == 0:
                    ready.append(child)
                    ready.sort(key=priority)

        if len(ordered) != len(envelopes):
            cyclic = sorted(eid for eid, degree in indegree.items() if degree > 0)
            raise ValueError(f"canonical extension does not exist; cyclic constraints: {cyclic}")

        return tuple(id_map[eid] for eid in ordered)

    def _check_horizon(self, horizon: Horizon, builder: CheckBuilder) -> None:
        for name, edges in (
            ("causal_order", horizon.causal_order),
            ("availability_order", horizon.availability_order),
            ("audit_order", horizon.audit_order),
        ):
            _check_acyclic(name, edges, builder)
        if horizon.events and len(set(horizon.events)) != len(horizon.events):
            builder.error("duplicate-events", "horizon event ids must be unique")
        for cls, capacity in horizon.capacities.items():
            if capacity < 0:
                builder.error(
                    "negative-capacity",
                    "capacity must be non-negative",
                    details={"class": cls.value},
                )

    def _check_required_manifest(self, horizon: Horizon, builder: CheckBuilder) -> None:
        if not horizon.strict:
            builder.warning(
                "unsafe-manifest",
                "manifest is marked non-strict; authority guarantees are not production-grade",
            )
            return
        required = {
            "capacities": bool(horizon.capacities),
            "writer_authority": bool(horizon.writer_authority),
            "version_intervals": bool(horizon.version_intervals),
            "protected_constructors": bool(horizon.protected_constructors),
            "gate_bundle_kinds": tuple(horizon.gate_bundle_kinds) == DEFAULT_GATE_BUNDLE_KINDS,
            "clock_policy": bool(horizon.clock_policy),
            "certificate_families": bool(horizon.certificate_families),
            "risk_modes": bool(horizon.risk_modes),
        }
        for field, present in required.items():
            if not present:
                builder.error(
                    "incomplete-manifest",
                    "strict manifest is missing a required safety table",
                    location=field,
                )
        for kind in DEFAULT_GATE_BUNDLE_KINDS:
            allowed = horizon.protected_constructors.get(kind)
            if allowed != (horizon.executor_writer,):
                builder.error(
                    "protected-constructor-policy",
                    "gate bundle constructors must be reserved to the executor writer",
                    location=kind,
                    details={"expected": horizon.executor_writer, "actual": list(allowed or ())},
                )

    def _check_unique_ids(self, envelopes: Sequence[Envelope], builder: CheckBuilder) -> dict[str, Envelope]:
        id_map: dict[str, Envelope] = {}
        for index, env in enumerate(envelopes):
            if not env.eid:
                builder.error("empty-eid", "envelope id must be non-empty", location=f"envelopes[{index}]")
                continue
            if env.eid in id_map:
                builder.error("duplicate-eid", "envelope ids must be unique", location=env.eid)
            id_map[env.eid] = env
        return id_map

    def _check_payload_security(self, horizon: Horizon, envelopes: Sequence[Envelope], builder: CheckBuilder) -> None:
        for env in envelopes:
            for issue in scan_for_sensitive_data(env.payload, allow_local_paths=horizon.allow_local_paths):
                builder.error(
                    "sensitive-payload",
                    "payload contains a secret-looking value or machine-local path",
                    location=f"{env.eid}:{issue.path}",
                    details=issue.to_json(),
                )

    def _check_protected_slots(self, envelopes: Sequence[Envelope], builder: CheckBuilder) -> None:
        seen: dict[tuple[str, str, str, str], str] = {}
        for env in envelopes:
            try:
                slot = env.protected_slot
            except ValueError as exc:
                builder.error("payload-kind", str(exc), location=env.eid)
                continue
            previous = seen.get(slot)
            if previous is not None:
                builder.error(
                    "duplicate-protected-slot",
                    "protected slots must be unique",
                    location=env.eid,
                    details={"previous": previous, "slot": list(slot)},
                )
            else:
                seen[slot] = env.eid

    def _check_event_projection(self, horizon: Horizon, envelopes: Sequence[Envelope], builder: CheckBuilder) -> None:
        if horizon.events:
            event_set = set(horizon.events)
            for env in envelopes:
                if env.event not in event_set:
                    builder.error("unknown-event", "envelope event is not in the horizon", location=env.eid)

        projection = {env.event for env in envelopes}
        for relation_name, edges in (
            ("causal", horizon.causal_order),
            ("availability", horizon.availability_order),
            ("audit", horizon.audit_order),
        ):
            for edge in edges:
                if edge.after in projection and edge.before not in projection:
                    builder.error(
                        "downset-violation",
                        "event projection is not downward closed",
                        details={
                            "relation": relation_name,
                            "missing": edge.before,
                            "required_by": edge.after,
                        },
                    )

    def _check_dependencies(
        self,
        envelopes: Sequence[Envelope],
        id_map: Mapping[str, Envelope],
        builder: CheckBuilder,
    ) -> None:
        for env in envelopes:
            for dep in env.dependencies:
                matches = _matching_dependency_eids(dep, envelopes)
                if dep.eid is not None and dep.eid not in id_map:
                    builder.error("missing-dependency", "dependency envelope id is absent", location=env.eid)
                elif dep.eid is None and not matches:
                    builder.error(
                        "missing-dependency",
                        "dependency event/slot reference is absent",
                        location=env.eid,
                        details=dep.to_json(),
                    )

    def _check_commit_groups(
        self,
        horizon: Horizon,
        envelopes: Sequence[Envelope],
        id_map: Mapping[str, Envelope],
        builder: CheckBuilder,
    ) -> None:
        grouped: dict[str, list[str]] = defaultdict(list)
        for env in envelopes:
            if env.commit_group:
                grouped[env.commit_group].append(env.eid)
        for group, present in grouped.items():
            expected = horizon.commit_groups.get(group)
            if expected is None:
                if horizon.commit_groups:
                    builder.error(
                        "unknown-commit-group",
                        "commit group is not declared by the horizon",
                        location=group,
                    )
                continue
            missing = [eid for eid in expected if eid not in id_map]
            extra = [eid for eid in present if eid not in expected]
            if missing or extra:
                builder.error(
                    "partial-commit-group",
                    "commit group must be fully present or absent",
                    location=group,
                    details={"missing": missing, "extra": extra},
                )

    def _check_capacity(self, horizon: Horizon, envelopes: Sequence[Envelope], builder: CheckBuilder) -> None:
        if not horizon.capacities:
            return
        counts = Counter(env.envelope_class for env in envelopes)
        for cls in EnvelopeClass:
            used = counts.get(cls, 0)
            capacity = horizon.capacities.get(cls)
            if capacity is not None and used > capacity:
                builder.error(
                    "capacity-exceeded",
                    "envelope class capacity is exceeded",
                    details={"class": cls.value, "used": used, "capacity": capacity},
                )

    def _check_writer_authority(self, horizon: Horizon, envelopes: Sequence[Envelope], builder: CheckBuilder) -> None:
        if not horizon.writer_authority:
            return
        for env in envelopes:
            try:
                kind = env.kind
            except ValueError:
                continue
            allowed = horizon.writer_authority.get(kind, horizon.writer_authority.get("*"))
            if allowed is None:
                builder.error(
                    "unknown-writer-family",
                    "payload kind has no writer table entry",
                    location=env.eid,
                )
                continue
            if env.writer not in allowed:
                builder.error(
                    "writer-authority",
                    "writer is not authorized for this payload kind",
                    location=env.eid,
                    details={"kind": kind, "writer": env.writer, "allowed": list(allowed)},
                )

    def _check_protected_constructor_authority(
        self, horizon: Horizon, envelopes: Sequence[Envelope], builder: CheckBuilder
    ) -> None:
        protected = dict(horizon.protected_constructors)
        for env in envelopes:
            try:
                kind = env.kind
            except ValueError:
                continue
            allowed = protected.get(kind)
            if allowed is None:
                continue
            if env.writer not in allowed:
                builder.error(
                    "protected-writer-authority",
                    "protected constructor was not emitted by its reserved writer",
                    location=env.eid,
                    details={"kind": kind, "writer": env.writer, "allowed": list(allowed)},
                )

    def _check_versions(self, horizon: Horizon, envelopes: Sequence[Envelope], builder: CheckBuilder) -> None:
        if not horizon.version_intervals:
            return
        for env in envelopes:
            try:
                kind = env.kind
            except ValueError:
                continue
            interval = horizon.version_intervals.get(kind, horizon.version_intervals.get("*"))
            if interval is None:
                builder.error(
                    "unknown-version-family",
                    "payload kind has no version interval",
                    location=env.eid,
                )
                continue
            if not interval.contains(env.version):
                builder.error(
                    "version-out-of-range",
                    "envelope version is outside the accepted manifest interval",
                    location=env.eid,
                    details={
                        "version": env.version,
                        "minimum": interval.minimum,
                        "maximum": interval.maximum,
                    },
                )

    def _check_gate_bundles(self, horizon: Horizon, envelopes: Sequence[Envelope], builder: CheckBuilder) -> None:
        if not horizon.gate_bundle_kinds:
            return
        bundle_kinds = tuple(horizon.gate_bundle_kinds)
        bundle_kind_set = set(bundle_kinds)
        grouped: dict[str, list[Envelope]] = defaultdict(list)
        for env in envelopes:
            try:
                kind = env.kind
            except ValueError:
                continue
            if kind in bundle_kind_set:
                if not env.commit_group:
                    builder.error(
                        "gate-bundle-missing-group",
                        "gate bundle envelope must belong to an atomic commit group",
                        location=env.eid,
                    )
                    continue
                grouped[env.commit_group].append(env)

        for group, rows in grouped.items():
            self._check_one_gate_bundle(horizon, group, rows, envelopes, builder)

    def _check_one_gate_bundle(
        self,
        horizon: Horizon,
        group: str,
        rows: Sequence[Envelope],
        envelopes: Sequence[Envelope],
        builder: CheckBuilder,
    ) -> None:
        bundle_kinds = tuple(horizon.gate_bundle_kinds)
        if len(rows) != len(bundle_kinds):
            builder.error(
                "gate-bundle-size",
                "gate bundle must contain exactly the required five rows",
                location=group,
                details={"expected": list(bundle_kinds), "actual": [env.kind for env in rows]},
            )
            return

        by_kind: dict[str, Envelope] = {}
        for env in rows:
            if env.kind in by_kind:
                builder.error("gate-bundle-duplicate-kind", "gate bundle kind appears twice", location=env.eid)
            by_kind[env.kind] = env
            if env.writer != horizon.executor_writer:
                builder.error(
                    "gate-bundle-writer",
                    "gate bundle row must be emitted by the executor writer",
                    location=env.eid,
                    details={"writer": env.writer, "expected": horizon.executor_writer},
                )

        missing = [kind for kind in bundle_kinds if kind not in by_kind]
        if missing:
            builder.error(
                "gate-bundle-missing-kind",
                "gate bundle is missing required rows",
                location=group,
                details={"missing": missing},
            )
            return

        commit_times = {env.commit_time for env in rows}
        if len(commit_times) != 1:
            builder.error(
                "gate-bundle-commit-time",
                "gate bundle rows must share one commit time",
                location=group,
                details={"commit_times": sorted(commit_times)},
            )
        commit_time = next(iter(commit_times)) if commit_times else None
        if horizon.strict and commit_time is not None:
            interleaved = [
                env.eid for env in envelopes if env.commit_time == commit_time and env.commit_group not in {group}
            ]
            if interleaved:
                builder.error(
                    "gate-bundle-interleaving",
                    "strict gate bundle commit time cannot contain unrelated visible writes",
                    location=group,
                    details={"interleaved": interleaved},
                )

        ordered = sorted(rows, key=lambda env: (env.commit_time, _slot_rank(env.slot), env.eid))
        actual_order = [env.kind for env in ordered]
        if actual_order != list(bundle_kinds):
            builder.error(
                "gate-bundle-order",
                "gate bundle rows must appear in the required order",
                location=group,
                details={"expected": list(bundle_kinds), "actual": actual_order},
            )

        gate = by_kind["GateCheck"]
        claim = by_kind["OutboxClaim"]
        use = by_kind["UseCap"]
        consume = by_kind["ConsumeResource"]
        close = by_kind["RiskClose"]
        request = gate.payload.get("request")
        if not isinstance(request, Mapping):
            builder.error("gate-bundle-request", "GateCheck row must bind the gate request", location=gate.eid)
            return

        expected_fields = {
            "gate_id": gate.payload.get("gate_id"),
            "bundle_id": gate.payload.get("bundle_id"),
            "frame_id": gate.payload.get("frame_id"),
            "action": gate.payload.get("action"),
            "outbox_id": request.get("outbox_id"),
            "capability_id": request.get("capability_id"),
            "lease_id": request.get("lease_id"),
            "risk_id": request.get("risk_id"),
            "hypothesis_id": request.get("hypothesis_id"),
            "ledger_digest": request.get("ledger_digest"),
            "source_digest": gate.payload.get("source_digest"),
        }
        if expected_fields["bundle_id"] != group:
            builder.error("gate-bundle-id", "GateCheck bundle id must match commit group", location=gate.eid)
        if expected_fields["gate_id"] != request.get("gate_id"):
            builder.error("gate-record-coherence", "GateCheck gate id must match request", location=gate.eid)
        if expected_fields["frame_id"] != request.get("frame_id") or expected_fields["action"] != request.get("action"):
            builder.error("gate-record-coherence", "GateCheck frame/action must match request", location=gate.eid)

        checks = (
            (
                claim,
                {
                    "gate_id": "gate_id",
                    "outbox_id": "outbox_id",
                    "frame_id": "frame_id",
                    "action": "action",
                    "source_digest": "source_digest",
                },
            ),
            (
                use,
                {
                    "capability_id": "capability_id",
                    "outbox_id": "outbox_id",
                    "frame_id": "frame_id",
                    "action": "action",
                },
            ),
            (consume, {"lease_id": "lease_id", "frame_id": "frame_id"}),
            (
                close,
                {
                    "risk_id": "risk_id",
                    "hypothesis_id": "hypothesis_id",
                    "frame_id": "frame_id",
                    "ledger_digest": "ledger_digest",
                },
            ),
        )
        for env, field_map in checks:
            for payload_field, expected_key in field_map.items():
                if env.payload.get(payload_field) != expected_fields[expected_key]:
                    builder.error(
                        "gate-bundle-coherence",
                        "gate bundle row does not match the GateCheck request tuple",
                        location=env.eid,
                        details={
                            "field": payload_field,
                            "expected": expected_fields[expected_key],
                            "actual": env.payload.get(payload_field),
                        },
                    )

        if (
            close.commit_time < claim.commit_time
            or close.commit_time < use.commit_time
            or close.commit_time < consume.commit_time
        ):
            builder.error(
                "gate-bundle-risk-close-order",
                "risk close must not precede claim, capability use, or resource consume",
                location=close.eid,
            )


def legal_log(horizon: Horizon, envelopes: Sequence[Envelope]) -> CheckResult:
    return EnvelopeVerifier().verify(horizon, envelopes)


def canonical_order(horizon: Horizon, envelopes: Sequence[Envelope]) -> tuple[Envelope, ...]:
    return EnvelopeVerifier().canonical_order(horizon, envelopes)


def _matching_dependency_eids(dep: DependencyRef, envelopes: Sequence[Envelope]) -> tuple[str, ...]:
    if dep.eid is not None:
        return (dep.eid,)
    matches = []
    for env in envelopes:
        if dep.event is not None and env.event != dep.event:
            continue
        if dep.slot is not None and env.slot != dep.slot:
            continue
        matches.append(env.eid)
    return tuple(matches)


def _check_acyclic(name: str, edges: Sequence[OrderEdge], builder: CheckBuilder) -> None:
    graph: dict[str, set[str]] = defaultdict(set)
    indegree: dict[str, int] = defaultdict(int)
    nodes: set[str] = set()
    for edge in edges:
        nodes.update((edge.before, edge.after))
        if edge.after not in graph[edge.before]:
            graph[edge.before].add(edge.after)
            indegree[edge.after] += 1
            indegree.setdefault(edge.before, indegree.get(edge.before, 0))

    ready = [node for node in nodes if indegree.get(node, 0) == 0]
    visited = 0
    while ready:
        node = ready.pop()
        visited += 1
        for child in graph[node]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    if visited != len(nodes):
        builder.error("cyclic-order", "horizon order relation must be acyclic", location=name)


def _slot_rank(slot: str) -> tuple[int, str]:
    try:
        return (int(slot), slot)
    except ValueError:
        return (10_000, slot)
