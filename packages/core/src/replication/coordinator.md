# A7a coordinator contract

This slice provides durable service rotation and a finite attempt-admission
contract. It does **not** enable A9/A10, wire a tester host, bound discovery or
history scans, or make signer/write/feed operations physically cancellable.

## Step and idle

Both hosts use `step({ now, budget, signal })`. `now` is a nonnegative safe
integer in milliseconds on the host scheduling clock. The settlement clock,
when supplied, must use the same time base and move forward; eligibility,
backoff, phase order and dependency wake policy stay in core.

`budget.units` is required. Units and explicit bytes must be positive safe
integers: zero, negative, fractional, NaN and infinite values throw before
state load, hint reads or selection. Omitted bytes means 64 MiB, not infinity.
Known item byte estimates must be nonnegative safe integers. Bytes limit
admission estimates, not total allocations or network traffic; omitted item
estimates are uncharged. A unit is one admitted attempt, not a bound on its
internal storage/CPU work. Work larger than the remaining byte budget is
deferred intact and sets `nextWake` to `now`. Under an explicit byte budget,
work larger than the whole budget stays deferred until a step's budget fits it.
Under the omitted 64 MiB default, such work runs when no other item has charged
bytes in the step and spends the rest of it, as the unbounded default ran it
before.

An item with a `part` is admitted once per part in a step: after a run, the
same item may run again in that step only under a different part (its next
resumable unit, e.g. the next fragment), and it never overlaps itself. An
item without `part` runs at most once per step. A handler whose work can
exceed a step's budget advertises the bytes of one part, so the step makes
progress on it instead of deferring it.

The result is always a `ProgressReport`. No admitted work or future durable
deadline means `nextWake: undefined` (not `null`). Pre-aborted steps perform no
hint read, run or checkpoint; they may read durable scheduling state to retain
the existing next-wake behavior. The coordinator rejects overlapping steps.

The Node worker is a documented wrapper: optional `now` defaults to its injected
clock; omitted budget is `{ units: 256, bytes: 64 * 1024 * 1024 }`. Its existing
`cycle()` calls one such finite step; it no longer grants infinite units. No
bootstrap or Lite runtime enablement is part of this change.

## Deadlines, polling and diagnostics

Each admitted run races a positive finite per-run timeout (core default 30s;
Node keeps its existing receive timeout). This is not an absolute whole-step
deadline. A host may abort the step. The inner signal is aborted and late
attempt plans are discarded/released. The timeout is capped at 2^31-1ms to
avoid host timer clamping. A run still pending is not redispatched by that
coordinator instance, but process reconstruction cannot physically stop old
external work. Existing registration intents still reconcile uncertain effects.

Optional finality hints are cached per instance, at most once per configured
refresh interval (default 2s). Each hint read has the configured run timeout or
2s when none is supplied. A hung hint is not awaited again by that instance;
restart can poll again. Durable wait deadlines remain the fallback. Poll-only
sources retain their host cadence and do not gain independent retry loops.

Reports contain at most 256 entries across all five diagnostic arrays. The
`diagnosticsTruncated` flag means the report may be incomplete; it is not a
durable work ledger. The Node wrapper also limits appended diagnostic rows.
These are returned-entry bounds, not proven SQL scan/serialized-byte bounds.
Checkpoints continue even when their diagnostics cannot fit the report.

## Durable rotation and ownership

`ReplicaCoordinatorStatePort` loads at every step entry. Its snapshot contains
the next phase name, last serviced writer per phase, opaque owner token and
monotonic revision. A successful checkpoint advances to the following phase
and records the selected writer. For a fixed eligible phase/writer set and
positive grants that can admit the work, budget-one restart traces serve each
phase in at most the number of phases and each writer in at most one traversal
of that phase's writers. This is opportunity, not guaranteed successful import.

The port's synchronous `commit(expected, rotation, checkpoint)` must check the
current owner/revision, run the checkpoint, write rotation and increment the
revision in **one transaction**, or roll everything back. No cursor-only write
after returning a receipt is allowed. A stale owner/revision rejects before
the plan and is not converted into a fallback Retry. A failed attempt plan may
roll back and commit one Retry plus one cursor revision in a new transaction.

An abort observed before the durable checkpoint commits does **not** advance
rotation or persist this attempt's outcome/plan. Core rechecks after the run
promise settles and inside the fenced checkpoint; Node also checks before its
outer transaction returns. Abort after durable commit (including during resource
release) does not undo that already-committed receipt or cursor.
A timeout **does** advance, atomically with its durable `deadline_exceeded`
Retry; otherwise one hot/hung early writer can monopolize the restart turn.
Neither decision rewrites PR507's preexisting registration-intent/recovery
semantics. Any preexisting durable intent made before the attempt checkpoint
retains its existing recovery behavior.

Node keeps the exclusive `pdpp_transport_lock` PID/token acquisition unchanged.
The adapter adds only the idempotent `pdpp_transport_coordinator` table and
initial row at an enabled forward open. It checks the current lock token and
revision before the callback and token/revision again before returning. It uses
`receiver.atomically`, with the outer door check before entering the capture
guard and nested commit checks inside it. The existing receiver boundary owns
derived-state synchronization and savepoint rollback. The new table does not
rewrite old data or require a non-forward schema conversion. Older code that
ignores it does not acquire restart-fairness guarantees.

Omitting `state` from core is an in-memory-only fixture seam, not a durable host
configuration. Lite must provide its own transactional ownership adapter and
pass `replicaCoordinatorStateContract` on real native storage before runtime
enablement. Node's PID-based recovery is not a portable native lifecycle model.

## Proofs and remaining gates

The shared contract tests receipt/cursor success, rollback, cursor-write failure,
stale revision, competing owners, recovered-owner late receipts and ownership
replacement inside a callback. Focused traces close/reopen SQLite before every
one-unit turn and assert exact persisted phase/writer/revision values. Core
tests cover abort, deadline, late plans, budget rejection, caps and next wakes.
The transport suite adds hot-retain/quiet-inbound service across every-turn
reopen, using the actual Node selectors and receiver.

Before publication run native Vitest with `--maxWorkers=4`, the server typecheck,
and the existing retry/wake/atomic-plan/flag/nested-rollback suites. Supplemental
Node/SQLite execution is not the native gate. A7a is not all of A7: bounded
discovery/maintenance/history, I/O cancellation/fencing, native readiness,
default-off host wiring, rollback and real Desktop/phone acceptance remain
separate work and enablement gates.
