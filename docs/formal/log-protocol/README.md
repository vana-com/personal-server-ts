# Bounded ordered-log design model

Source pin: `1ca1a110d9304adc4dab709c78cf770584a895fa`.
Status: authored and statically reviewed; **TLC has not been run**. Expected
outcomes below are predictions, not verification evidence. No production code
changes. This models the requested future protocol, not a claim that this pin
already implements immutable operation segments.

## Source mapping and explicit boundaries

- `packages/core/src/localdb/merge.ts`: `mergeIncoming` compares effective
  SEEN observation pairs, preserves later local sightings, and can promote a
  sighting when a remote different body loses. `replaceDelete` removes only
  pairs strictly below the cutoff. `deleteRunRecords` gives explicit deletes
  their run stamp and records tombstones even for missing keys. The model treats
  promoted effective observations as already emitted operations. It does not
  confuse immutable content stamps with local SEEN stamps.
- The accepted operation corpus rejects equal-stamp/different-body conflicts
  through `Admissible`; this is an admission assumption of the requested
  design. The scoped merge SQL alone is not proof of an exception-throwing
  rejection path: it simply does not let an equal-stamp different body replace
  the row. Identical retransmitted bodies are idempotent.
- `localdb/replace.ts#decideReplace` requires declared full inventory,
  mutable state, successful covered/proven full streams; `replaceMayApply`
  requires the recorded basis. Model omission operations assume those admission
  checks succeeded. They name a specific absent key, not a whole-stream wipe.
- `localdb/apply.ts#control` refuses stale active generations after a known
  deletion; generation changes purge/reset stream state. The head-generation
  guards and final control recheck reject old-lifetime content.
  `publish.ts#commitBatchTurn` uses connection control and per-stream CAS
  conditions in one batch request, but supports unbatched fallback and
  per-row conflict outcomes. The proposed single immutable segment and global
  connection position are **new design**, not inferred current CAS semantics.
- `replication/envelope.ts` declares upsert/delete, connection register/reset/
  delete and stream-complete/invalidate. Its completion carries proof,
  dependencies and digest, **not the proposed omission list**.
  `completion.ts` checks unique digest-bound dependencies and selects
  completion by revisions. `visibility-engine.ts#completionAvailability`
  additionally requires matching live count/digest and eligible evidence.
  Those facts are assumed established before emitting a proposed omission.
- `replication/stream.ts` validates per-writer sequence/previous and fragment
  bindings; that is not the model's connection-wide log position.
  `revision.ts#compareRevisions` orders counter, original writer/operation,
  then own writer/operation; `nextLamportCounter` increments the observed
  maximum. The P6 witness has distinct counters, so omitted tie fields and
  rebaseline-origin fields cannot change that witness.
- P5 promises only a **known-lifetime fence**, consistent with apply/publish
  generation guards and profile visibility withdrawal on superseded generation.
  It does not promise instantaneous disappearance on an offline device, prevent
  legitimate recollection in a new lifetime, or model profile connection-delete
  (which is absorbing rather than reset). Local purge implementation and
  lifetime-boundary internals are outside this source selection.

## State and abstraction

Devices 1 and 2 are writers and replicas; device 3 only reads. Two keys stand
for two distinct streams. A batch is an ordered sequence applied atomically;
the first two batches each touch both streams. A fixed five-batch corpus keeps
the state space small while allowing every delivery/compaction/reset interleaving.
There is no local uncommitted overlay; writers' committed views synchronize by
the same reader actions. This is not exhaustive arbitrary-operation checking.

Encoded stamp `s=2*o+r`, with `r in {0,1}`, preserves lexicographic pair order.
An ordinary operation has rank `2*s`; omission cutoff has rank `2*s-1`.
Thus a live observation at or above cutoff survives and older ones lose.
Rank/body zero is absence; nonzero rank with body zero retains a tombstone.
Real explicit-delete/upsert equal-stamp conflicts are refused at admission.

`log` is immutable committed history and the reference oracle.
`retained` is the fetchable segment index set. Readers may fetch only indices
in it, except that `Install` obtains the compacted snapshot. The oracle retains
history only for assertions and snapshot construction, not reader fallback.
Compaction bound is derived as head minus one retained tail segment.
Snapshots replace a committed-prefix view; there is no uncommitted local overlay
to merge. The latest winner, including a tombstone, is preserved per key.

`MaxSteps=6` bounds commits plus reset, **not network transitions**. This is
intentional: cutting off all actions at depth six would invalidate liveness
claims about delivery after writers stop. The graph is finite without bounding
duplicate hints. One reset is possible; position resets to zero only when
adopting a newer epoch, so monotonicity means the pair (epoch, position).

## Actions

- Commit: writer of the next catalog batch appends one immutable segment and
  atomically advances the connection position; emits a hint.
- Stop: writers stop permanently; weak fairness guarantees eventual quiescence.
- Deliver / Drop: choose any hint. Deliver can repeat indefinitely and reorder
  old/new hints; max-known position never retreats. Stale epochs cannot roll
  back a device. Drop removes a hint without applying any content.
- FullCheck: authoritative head/lifetime read independent of hints; adopts a
  new lifetime by clearing old data/position.
- Apply: fetch one retained next segment and atomically apply its whole batch.
  No position n+1 before n in good mode.
- Compact: snapshot at the derived bound, remove only covered fetchable segments.
- Install: a reader behind the bound installs snapshot then applies the tail.
- Reset: new authoritative lifetime, empty log/snapshot; offline views are not
  magically rewritten. All old hints remain eligible for transport, not authority.
- SkipGap: mutant-only advancement of a checkpoint from a later hint.

## Properties and expected host results

| Configuration | Expected result | Target |
| --- | --- | --- |
| Good.cfg | PASS within this finite abstraction | TypeOK, P1–P5; eventual convergence |
| LostPush.cfg | PASS, even with no Deliver action | P2 full-check recovery and eventual convergence |
| DropGap.cfg | FAIL P2 | skipped missing predecessors |
| OutOfOrder.cfg | FAIL P2 | later segment applied first |
| DropTombstone.cfg | FAIL P1 after snapshot+tail | P4 compaction must retain latest deletion |
| OmissionWithoutCutoff.cfg | FAIL P3 | newer observed row erased by old omission |
| LamportDifference.cfg | FAIL StampEqualsLamport | P6 orders choose different winners |

P1 compares every caught-up replica with greatest-stamp reference state, not
just replicas with each other. P2 records actual step-order and lexicographic
position checks. P3 records an omission's before/after safety obligation.
P4 compares every compacted snapshot with its exact reference prefix.
P5 compares each current-lifetime device prefix with that lifetime's oracle;
this is stronger than merely checking an epoch tag on stale content.
`EventuallyConverged` uses weak fairness for Stop and each device's FullCheck
and Recover. Storage reads succeed eventually; Byzantine storage, perpetual
outage and infinitely continuing writers are not silently proved live.

## Predicted counterexample recipes (not TLC output)

- Gap: Commit twice; FullCheck(3); SkipGap(3) advances 0 to 2 without records.
- Out-of-order: Commit twice; FullCheck(3); Apply(3,2) violates prefixOK.
- Tombstone: Commit three times; Compact to 2; reader at 0 FullCheck, Install,
  Apply tail 3. Dropped explicit delete lets key 2's older body 21 reappear.
- Cutoff: Commit through batch 4; reader applies 1,2,3,4 in order. Before
  completion, key 1 has stamp 5/body 13; cutoff 4 must not remove it. Mutant does.
- P6: Commit batch 1 then 2. Key 1 observation stamp 3/body 11 beats stamp 2/
  body 12; Lamport counter 2 instead beats counter 1. Greatest-stamp replicas
  still converge when all segments arrive. This is an order mismatch, not a
  demonstrated production bug or equivalence of the two protocols.

Each mutant changes a transition/reducer, not the invariant. The tombstone
mutant folds the compacted prefix with explicit delete operations removed,
retaining earlier live values; its config tests a reader-visible error rather
than failing immediately on the snapshot oracle.

## Host invocation and exclusions

From this directory, use the host's installed TLC, for example:
`java -cp /path/to/tla2tools.jar tlc2.TLC -workers 1 -config Good.cfg LogProtocol`.
Repeat for all seven configs; save actual traces/states/timing. Expected FAIL
configs are successful mutation detection only if the named invariant fails.
Parse failures, deadlocks, timeouts and unrelated failures do not count.
No tool download, TLC, syntax check or repository script was run by the worker.

Excluded: arbitrary stamp conflicts, profile equivocation/quarantine, hash/
signature verification, auth/declarations, crash durability, storage failures,
writer CAS retries, per-writer fragment reassembly, bulk schema/attachment
semantics, local SEEN promotion internals, operation-id tie cases, and physical
snapshot garbage collection. No refinement mapping to the current implementation
is claimed. Host validation remains necessary before relying on this model.

## TLC results (host run)

Run on 2026-11-15 with TLC 2.19 (`tla2tools.jar` 1.7.4, Java 17), `-workers 4`,
under `nice -n 19 ionice -c3`, one job at a time, foreground. Each config had its
own metadir, deleted after its run.

Spec change for this run: one lexical edit, line 108 of `LogProtocol.tla`,
`log'=<<>>` → `log' = <<>>`. In TLA+ ASCII, `=<` is the `≤` token, so `'=<<>>`
did not lex. A grep for `=<<` found no other hit. No other spec or config
change.

| Configuration | Expected | Actual | Distinct states | Depth | Wall time |
| --- | --- | --- | --- | --- | --- |
| Good.cfg | PASS | PASS: no error (95,264,783 generated) | 6,160,198 | 31 | 14 min 46 s |
| LostPush.cfg | PASS | PASS: no error (50,450,693 generated) | 6,160,198 | 31 | 8 min 56 s |
| DropGap.cfg | FAIL P2 | FAIL P2 as expected (`Invariant P2 is violated`) | 146 at failure | 6 | <1 s |
| OutOfOrder.cfg | FAIL P2 | FAIL P2 as expected (`Invariant P2 is violated`) | 154 at failure | 6 | <1 s |
| DropTombstone.cfg | FAIL P1 | FAIL P1 as expected (`Invariant P1 is violated`) | 2,883 at failure | 8 | <1 s |
| OmissionWithoutCutoff.cfg | FAIL P3 | FAIL P3 as expected (`Invariant P3 is violated`) | 6,473 at failure | 9 | <1 s |
| LamportDifference.cfg | FAIL StampEqualsLamport | FAIL StampEqualsLamport as expected | 4 at failure | 3 | <1 s |

For the FAIL rows, the distinct-state count is what TLC had reached when it
stopped on the violation. It is not a full state-space size. The PASS rows
completed their search (`0 states left on queue`). Good and LostPush report the
same distinct-state count; I did not check why.

No config hit the bound (20M distinct states or 45 min). No trace was needed,
because every result matched its expected outcome.

These are the first TLC results for this model. They are a check of the finite
abstraction only, within the scope limits above. They do not show a refinement
to the implementation.
