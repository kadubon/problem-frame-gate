# Theory Mapping

This project implements the paper's finite audit calculus as executable
portable records and strict checkers.  The software is intentionally
conservative: it proves that a finite log and its checker records are internally
consistent.  It does not prove
external truth, real-world effect, cryptographic strength, or statistical model
validity unless a deployment adds those assumptions and certificates.

## Core Objects

| Paper term | Library term | Module |
| --- | --- | --- |
| bounded horizon `H` | strict finite manifest | `model.Horizon`, `model.StrictManifest` |
| envelope | append-only audit-log row | `model.Envelope` |
| legal log | finite log accepted by verifier | `verifier.EnvelopeVerifier` |
| canonical fold | deterministic replay | `fold.FoldKernel` |
| transcript | finite checker result and record digest | `result.CheckResult`, `model.AuditTranscript` |
| problem frame | bounded decision frame | `model.Frame`, `formation` |
| certificate liveness | issued, unrevoked, unexpired check | `certificates` |
| capability/resource/outbox folds | linear authority state | `fold` default components |
| risk ledger | finite reserve/spend/close accounting | `risk` |
| executor gate | before-action authorization predicate and atomic bundle | `gate.ExecutorGate`, `gate.GateBundle` |
| patch preservation | footprint/touch/affected-clause checking | `patch.PatchChecker` |
| join preservation | ancestor/repair/recheck checking | `join.JoinChecker` |

## Implemented Checks

`EnvelopeVerifier` checks:

- unique envelope identifiers;
- unique protected slots `(event, slot, payload kind, object id)`;
- event downset closure for causal, availability, and audit orders;
- explicit dependency presence;
- declared commit-group completeness when commit groups are configured;
- capacity limits by envelope class;
- writer authorization by payload kind;
- manifest version intervals;
- deterministic canonical ordering;
- secret-looking values and machine-local paths in payloads.

`FoldKernel` checks that the same accepted log deterministically replays through
finite components.  The default components enforce single-use capabilities,
single-consume resource leases, outbox state transitions, issued/revoked
certificates, frame status, evidence records, and risk reserve/spend/close
ordering.

`ExecutorGate` checks the before-action boundary and returns a `GateBundle`:

- source-prefix fold is legal;
- frame is active;
- requested action belongs to the frame;
- capability is unused and scoped to the frame and action;
- resource lease is live and scoped to the frame;
- outbox is authorized and scoped to the frame and action;
- risk spend is live and matches hypothesis, mode, certificate, and optional
  ledger digest;
- required certificates are live;
- source time precedes commit time;
- source-prefix digest matches when supplied.
- `GateCheck` embeds a first-class source cut, gate record, gate-record digest,
  and transcript digest.

The verifier rejects any standalone or incoherent gate row.  Accepted bundles
contain:

1. `GateCheck`
2. `OutboxClaim`
3. `UseCap`
4. `ConsumeResource`
5. `RiskClose`

## Deliberate Boundaries

The package avoids hidden or global assumptions.  When a deployment needs
stronger claims, it should add typed certificates and treat the issuer,
cryptographic binding, physical actuator, statistical model, and monitor as
explicit trusted-footprint items.

Domain checks should be written as small invariant functions passed to
`PatchChecker` or as additional `StateComponent` implementations.

## v1 Coverage

| Area | v1 executable check | Still external |
| --- | --- | --- |
| Source cut | included set, excluded frontier, dependency closure, commit-group closure, digest equality | trustworthy storage clock |
| Gate bundle | five-row order, commit group, tuple equality, source cut, gate record, transcript digest, close row | real actuator effect |
| Certificate | issuer table, issue row, expiry, revocation, dependency digest, source availability, family-check record | real issuer authentication and key custody |
| Risk | reserve before spend, single spend, close state, four route shapes, route witness, finite alpha bound | statistical model validity |
| Patch | append-only ids, write universe, touch/non-touch matrix, affected completeness, transported cells, liveness repairs | domain invariant correctness |
| Join | common ancestor, conflicting envelope ids, escrow conflict keys, repair witnesses, repair rechecks, liveness repair | semantic merge policy chosen by deployment |
| Reachability | transition kind, digest chain, typed witness payload, patch/join/gate checker replay, abort/fail-closed row class | the external transition premise itself |

## Witness Replay Boundary

| Witness | Replayed by this package | Remains an assumption unless supplied by deployment |
| --- | --- | --- |
| Certificate family | issue row shape, dependency digest, source availability, revocation frontier, optional callable registry checker | issuer identity, key custody, external source truth |
| Risk route | finite route witness shape, spend-before-selection, alpha accounting, optional callable registry checker | statistical model validity |
| Gate | source fold, active frame, capability, resource, outbox, live certificate, live risk spend, bundle transcript | actuator effect after dispatch |
| Patch | source digest, append-only ids, write cover, touch matrix, transported cells, liveness repair | correctness of domain invariant functions |
| Join | common ancestor, conflict keys, repair witnesses, repair rechecks | semantic merge policy selected by the deployment |
| Reachability | typed patch/join/gate witness replay and abort/fail-closed row checks | real-world transition premise outside the finite log |

## Commercial-Use Boundary

| Claim area | Implemented by this package | Required external control |
| --- | --- | --- |
| Audit-log legality | Finite schema, authority, capacity, dependency, version, and bundle checks | Durable append-only storage and backup policy |
| Action authorization | Five-row executor gate bundle and replayable source digest | Tool sandbox, actuator policy, and human or service-level approval where required |
| Certificate liveness | Issued, unrevoked, unexpired, source-linked certificate records | Real issuer authentication and key management |
| Risk accounting | Finite reserve/spend/close ledger and route checks | Statistical model validation and monitoring |
| Patch and join preservation | Footprint, touch matrix, affected clause, ancestor, and repair checks | Domain invariants supplied by the deployment |
| External truth and physical effect | Explicit `assumptions` footprint only | Independent observation, incident response, and operational safety controls |
