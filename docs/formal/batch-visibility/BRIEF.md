# Batch visibility model: assignment

This file is the full contract for the TLA+ model in this directory. The model, its .cfg files and README.md go next to it.

Build a TLA+ model (TLA+ before any code) for one proposed change in vana-com/personal-server-ts: per-batch visibility during a connector run. Base: feat/stream-sync at df94f29aa2b48cc241ae6ac07c6d46d43817dd7f. Write only new files under docs/formal/batch-visibility/.

TODAY (read the code to ground the model; cite file:line in docs/formal/batch-visibility/README.md): a connector run stages batches into run_rows (packages/core/src/localdb/run-intake.ts) and merges them into records only at run end (packages/core/src/localdb/run-end.ts, packages/core/src/localdb/merge.ts). At run end, decideReplace (packages/core/src/localdb/replace.ts:20) decides whether the pass may delete rows it did not observe (omission), using the head replacedAt cutoff (packages/core/src/localdb/apply.ts near :520, merge.ts near :203). A failed run drops its staged rows (merge.ts dropRunRows near :305). Records carry an observation stamp (o,r); the greatest stamp wins per key. Explicit deletes are rows in record_changes with explicit_delete. Coverage strategies are in packages/core/src/stream-sync/intake.ts:62 (full_inventory, checkpoint_window, parent_detail_accounting, snapshot_import_receipt, singleton_presence).

PROPOSED: merge each staged batch into records as plain upserts when it arrives (visible locally and publishable to other devices at once). Keep checkpoint moves at connector checkpoints, and keep omission deletes and replace at run end, only when decideReplace is true (proven-full pass). On a failed run, keep the per-batch merged rows (true observations) and drop only the replace.

MODEL (small, finite): keys K = {k1,k2,k3}; a source whose key set and values can change between and during runs; one collecting device D with a local store; one remote writer W that can upsert or explicitly delete any key with its own stamp at any time (its changes reach D by apply); one reader device R that sees whatever D has published (any prefix of D's committed changes). A run emits batches in any order and may fail at any step. Model both the PROPOSED design and TODAY's design, selected by a constant, so each property can be checked against both.

PROPERTIES (invariants unless noted):
P1 NoOmissionBeforeProof: no key is removed by omission in D or R unless a run that observed a proven-full pass has ended successfully.
P2 FailedRunNeverDeletes: a failed run removes no key from D's records.
P3 NoResurrection: an upsert whose stamp is older than a delete (explicit or by a proven omission) for the same key never makes that key present again.
P4 LaterWriteKept: the omission delete at run end keeps every key whose row stamp is later than the pass cutoff stamp (the head replacement cutoff), for example a row that the other writer changed while the run was in progress.
P5 StampConvergence (liveness under fairness, or a quiescence invariant): when no run is active and all changes have been applied, D and R hold, per key, the greatest-stamp observation or delete.
P6 CheckpointSoundness: for checkpoint_window, the checkpoint never moves past a batch that has not been merged.
Model coverage strategy as at least {full_inventory, checkpoint_window} (two constants are enough).

DISCRIMINATION: add mutant configs that must FAIL, each named in docs/formal/batch-visibility/README.md with the counterexample length: (m1) omission applied per batch instead of at run end; (m2) failed run keeps the replace; (m3) omission without the replacedAt cutoff; (m4) per-batch merge that overwrites without the stamp comparison. Each property must be violated by at least one mutant, or say which one is not discriminated and why.

RUN: if TLC (tla2tools.jar) and Java are available in your sandbox, run every config (-workers 2) and paste the exact TLC result lines (states generated, distinct, depth, and Error/No error) for each config into docs/formal/batch-visibility/README.md. If TLC is not available, still write the spec and cfgs, say plainly in docs/formal/batch-visibility/README.md that nothing was run, and check the spec with SANY if available. Follow the style of docs/formal/PublishSnapshot.tla and docs/formal/registry-poke/.

docs/formal/batch-visibility/README.md must also answer, with file:line: which of the five coverage strategies need a different visibility rule (e.g. snapshot_import_receipt only at the receipt), and whether today's run-end code already enforces P4 or whether the proposed design would need a new check.

Expect it to work because: the proposed change only moves the time at which non-destructive upserts become visible; all destructive steps (omission, replace) keep the single gate at run end that they have today. Stamps make upserts commutative and idempotent per key, so earlier visibility should not change the final state. The most likely wrong assumption is in P3 and P4: an upsert merged early may now interleave with a delete or a later write from the other writer, which today is resolved inside one run-end transaction. The model exists to find that interleaving.
