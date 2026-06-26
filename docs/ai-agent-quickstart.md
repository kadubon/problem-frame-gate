# AI Agent Quickstart

Use this package as a final gate before an agent writes to an external system,
calls a tool with real side effects, starts an experiment, or sends a command to
an actuator.

## Recommended Flow

1. Append evidence and certificates as envelopes.
2. Define a decision frame with goal, scope, allowed actions, acceptance
   criteria, risk ids, and obligations.
3. Activate the frame only after `check_formation` accepts.
4. Reserve risk and resources before action.
5. Mint a single-use capability for one frame and one action.
6. Authorize one outbox entry.
7. Call `ExecutorGate.check`.
8. Append the generated `GateBundle` atomically.
9. Dispatch only after the bundle is committed.

The key rule is simple: the model may propose actions, but only the gate writes
the externally actionable claim.
