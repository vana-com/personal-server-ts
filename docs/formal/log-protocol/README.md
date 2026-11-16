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
- Two bodies of one key at one stamp are admitted: a collection run that
  publishes while it collects can emit a key again in a later intake batch.
  The model no longer assumes they agree (the old `Admissible` assumption is
  removed). The order that settles them is in "Equal-stamp order" below.
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
- ApplyRun (`Mode` grouped, groupedSkip): the segments `position+1..q` apply in
  ONE transaction that writes position q with the last of them. It models the
  host's group commit of a first load, and equals q-position separate `Apply`
  steps with no committed state between them (each segment folds over the rows
  of the ones before it). The `groupedSkip` mutant leaves out the middle
  segments and must fail P5.
- KeyedLoad / KeyedPublish / StageLost (`Mode` keyed, keyedSkip, keyedEarly): a
  device with position 0 and no rows, over a log that has never compacted,
  folds the log key by key into a staging area (`KeyedLoad(d,k,q)`: key k's
  operations from segments 1..q), in any key order, any number of times.
  `KeyedPublish(d,q)` writes the rows and the position q in ONE transaction,
  and only when every key is folded to q. `StageLost` drops the staging area
  (a crash, or the next start). Reset, Rollback and FullCheck clear it. The
  `keyedSkip` mutant leaves a key's fold without the segment before its last
  (a stage that lost rows) and must fail P1. The `keyedEarly` mutant publishes
  while a key is not yet folded and must fail P5.

## Properties and expected host results

| Configuration             | Expected result                     | Target                                                                                          |
| ------------------------- | ----------------------------------- | ----------------------------------------------------------------------------------------------- |
| Good.cfg                  | PASS within this finite abstraction | TypeOK, P1–P5; eventual convergence                                                             |
| LostPush.cfg              | PASS, even with no Deliver action   | P2 full-check recovery and eventual convergence                                                 |
| DropGap.cfg               | FAIL P2                             | skipped missing predecessors                                                                    |
| OutOfOrder.cfg            | FAIL P2                             | later segment applied first                                                                     |
| DroppedDeleteEffect.cfg   | FAIL P1 after snapshot+tail         | snapshot built without delete operations                                                        |
| ForgetTombstone.cfg       | FAIL P1 via replay                  | correct delete, then snapshot forgets its tombstone; a later replayed upsert resurrects the key |
| OmissionWithoutCutoff.cfg | FAIL P3                             | newer observed row erased by old omission                                                       |
| OmissionInclusive.cfg     | FAIL P3                             | omission at equal stamp erases an observation AT the cutoff (`<=` boundary)                     |
| LamportDifference.cfg     | FAIL StampEqualsLamport             | P6 orders choose different winners                                                              |
| Grouped.cfg               | PASS within this finite abstraction | group commit (`ApplyRun`): TypeOK, P1–P5, OrderOK                                               |
| GroupedSkip.cfg           | FAIL P5                             | a group commit that leaves out the segments between its first and last                          |
| Keyed.cfg                 | PASS within this finite abstraction | key-ordered first load (`KeyedLoad`, `KeyedPublish`, `StageLost`): TypeOK, P1–P5, OrderOK       |
| KeyedSkip.cfg             | FAIL P1                             | a key's fold that leaves out a segment                                                          |
| KeyedEarly.cfg            | FAIL P5                             | the position written while a key is not yet folded                                              |

Corpus (batch 6): an equal-cutoff omission (key 1, stamp 5) meets the live
stamp-5 row, and an older omission (key 2, stamp 1) sits below the live delete.
Good requires the correct boundary: omission rejects `<`, so an observation AT
the cutoff wins. Traces of each failing mutant are in `traces/`.

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

| Configuration             | Expected                | Actual                                                                                                                | Distinct states               | Depth | Wall time                             |
| ------------------------- | ----------------------- | --------------------------------------------------------------------------------------------------------------------- | ----------------------------- | ----- | ------------------------------------- |
| Good.cfg                  | PASS                    | BOUNDED: stopped at 20.3M distinct, no invariant error in explored states; EventuallyConverged not checked            | at least 20,309,206 (partial) | n/a   | 47 min 51 s, stopped                  |
| LostPush.cfg              | PASS                    | BFS COMPLETE, no invariant error (23,019,334 distinct, 0 left on queue); temporal check cut at bound                  | 23,019,334                    | n/a   | 46 min 7 s, stopped in temporal check |
| DropGap.cfg               | FAIL P2                 | FAIL P2 as expected (`Invariant P2 is violated`)                                                                      | 130 at failure                | 6     | <1 s                                  |
| OutOfOrder.cfg            | FAIL P2                 | FAIL P2 as expected (`Invariant P2 is violated`)                                                                      | 131 at failure                | 6     | <1 s                                  |
| DroppedDeleteEffect.cfg   | FAIL P1                 | FAIL P1 as expected (`Invariant P1 is violated`)                                                                      | 2,509 at failure              | 8     | <1 s                                  |
| ForgetTombstone.cfg       | FAIL P1                 | FAIL P1 as expected; trace: Install, then replayed batch 5 resurrects key 2                                           | 16,135 at failure             | 10    | 2 s                                   |
| OmissionWithoutCutoff.cfg | FAIL P3                 | FAIL P3 as expected (`Invariant P3 is violated`)                                                                      | 7,842 at failure              | 9     | <1 s                                  |
| OmissionInclusive.cfg     | FAIL P3                 | FAIL P3 as expected; trace: stamp-5 omission erases the stamp-5 row                                                   | 45,443 at failure             | 11    | <1 s                                  |
| LamportDifference.cfg     | FAIL StampEqualsLamport | FAIL StampEqualsLamport as expected                                                                                   | 4 at failure                  | 3     | <1 s                                  |
| Grouped.cfg               | PASS                    | BFS COMPLETE, no invariant error (372,262,911 generated, 0 left on queue); no temporal property                       | 20,306,222                    | 24    | 22 min 29 s (2 workers)               |
| GroupedSkip.cfg           | FAIL P5                 | FAIL P5 as expected; trace: three commits, FullCheck, then a group that omits the segments between its first and last | 184 at failure                | 6     | <1 s                                  |

Good and LostPush hit the bound before TLC finished (20M distinct states or 45
min), so their PASS is not established. Good stopped with no invariant violation
in its explored states; LostPush finished the state space with no invariant
violation, and its liveness check did not finish. Earlier, under the 5-batch
corpus, both completed (6,160,198 distinct states, depth 31); the batch-6
corpus grew the space by roughly 3.7x (23.0M vs 6.16M).

For FAIL rows, the distinct-state count is what TLC had reached when it stopped
on the violation. It is not a full state-space size. Counterexample traces for
every failing mutant are in `traces/`. The `DroppedDeleteEffect` trace is the
old `DropTombstone` mutant, renamed.

These are the first TLC results for this model. They are a check of the finite
abstraction only, within the scope limits above. They do not show a refinement
to the implementation.

## Key-ordered first load (host run, 2026-11-16)

TLC 2.19, `-workers 4`, `nice -n 19`, one job at a time, metadirs deleted after
each run. Expected results were stated before the run: `Keyed.cfg` holds,
`KeyedSkip.cfg` fails P1, `KeyedEarly.cfg` fails P5.

| Configuration  | Expected | Actual                                                                                                                            | Distinct states     | Depth | Wall time       |
| -------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------- | ----- | --------------- |
| Keyed.cfg      | PASS     | BOUNDED: stopped at the 25 min limit; no invariant error in the explored states (462,751,607 generated, 41,591,212 left on queue) | at least 56,493,699 | n/a   | 25 min, stopped |
| KeyedSkip.cfg  | FAIL P1  | FAIL P1 as expected: a key's fold omits a segment, then the keyed publish installs rows that differ from the reference            | 5,922 at failure    | 8     | 1 s             |
| KeyedEarly.cfg | FAIL P5  | FAIL P5 as expected: the position is written while a key is not folded, so a device claims a prefix it does not hold              | 791 at failure      | 6     | <1 s            |

`Keyed.cfg` did not finish, so its PASS is not established: the model is bounded
evidence, the same status as `Good.cfg`. Its space is larger than `Grouped.cfg`'s
because fold progress per key adds state. Traces: `traces/KeyedSkip.txt`,
`traces/KeyedEarly.txt`.

## #705 r3 extension (host run, 2026-11-15)

Scope: the model now represents the r3 rules of the log-segments PR (head
`664c5d10`, `packages/stream-sync/src/log.ts` and `packages/core/src/localdb/log-apply.ts`):

- Tombstone kinds rank omission < upsert < explicit delete at equal stamp.
  Mutant `dropKind` gives delete the upsert rank.
- Each row carries `first` (firstSeen): the smallest batch position at which an
  observation with the winning rank was applied. Equal-rank observations merge
  by minimum.
- Install merges the snapshot into the reader's existing rows (`MergeRow`),
  not a replacement. Lagging, fresh and uninterrupted readers are checked by
  P5 at every position, on body, stamp, rank and `first`.
- A registry rollback (`Rollback`, at most one, needs epoch 1 and leaves
  epoch 2) moves the head back one batch, or drops it, or replaces it with
  another corpus batch, and rebases the snapshot to Empty. Under Good, devices
  on the old lifetime fail closed through `FullCheck`. Mutant `replayFromBase`
  keeps the rows and position of such a device.
- Corpus batch 7: an upsert and an explicit delete at stamp 4 in one batch.
  `OrderOK` checks each batch folds the same forwards and backwards. Batch 7
  is reached only by Rollback's replacement path, since commits are capped by
  MaxSteps.
- P5 now fails on a device whose position is past the head, instead of
  comparing a prefix that does not exist.

Not represented: hintApplied (job 1 item c, not done), the transport and
generation fences of the real gateway, and firstSeen as a wall-clock value.

Expected results were written down before any run, in
`~/.tmp/job3-scratch/EXPECTED.md` (not committed), and are restated here.

| Configuration           | Invariant                                  | Expected                                                                     | Actual                                                                                                                    | Distinct states                                      | Depth | Wall time                       |
| ----------------------- | ------------------------------------------ | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- | ----- | ------------------------------- |
| Good.cfg (r3 model)     | TypeOK P1–P5, OrderOK; EventuallyConverged | no violation; bounded, not PASS                                              | BOUNDED: stopped at 45 min (exit 124); no invariant error in explored states; liveness not finished                       | at least 31,812,556 distinct (343,151,617 generated) | n/a   | 45 min                          |
| DropKind.cfg            | OrderOK                                    | violated, depth 1                                                            | FAIL as expected (`The invariant of OrderOK is equal to FALSE`, reported before any step; the check is state-independent) | 1                                                    | 0     | 241 s, mostly queued for a slot |
| ReplayFromBase.cfg      | P5                                         | violated after Rollback + FullCheck, depth ~6–9                              | FAIL as expected at depth 8: device 1 at position 2 over a one-batch log is labelled current                              | 135,191 at failure                                   | 8     | 1 s                             |
| ForgetTombstone.cfg     | P1, P5                                     | P5 violated: a fresh device installs a snapshot missing the delete, depth ~6 | FAIL P5 at depth 7 (3 commits, Compact, FullCheck, Install); P1 not reached first                                         | 867 at failure                                       | 7     | <1 s                            |
| DroppedDeleteEffect.cfg | P1                                         | not predicted                                                                | FAIL P1 at depth 8                                                                                                        | 2,700 at failure                                     | 8     | <1 s                            |
| OmissionInclusive.cfg   | P3                                         | not predicted                                                                | FAIL P3 at depth 11                                                                                                       | 55,581 at failure                                    | 11    | <1 s                            |

Expected-versus-actual: every prediction matched. The DropKind failure is
reported as a constant-level invariant error, not as a counterexample trace.
Its trace file holds only that line. Good was not run to completion, so
`EventuallyConverged` is not established.

Traces for the failing r3 runs are in `traces/r3-*.txt`. The earlier traces
(`traces/DroppedDeleteEffect.txt`, `ForgetTombstone.txt`, `OmissionInclusive.txt`)
are from the pre-r3 model. The earlier table above is also from the pre-r3 model:
the delete rank changed, rows carry `first`, and Install merges, so its state
counts and depths do not apply to this file.

## Equal-stamp order (host run, 2026-11-15)

Defect: with publish-while-collecting on, one run can emit two different
bodies for one key at the same stamp `(o, r)`. The writer kept the later body
(`INSERT OR REPLACE` in run intake, `replaceOwnRunRows` in admission). A
reader kept the first (the strict newer-stamp rule in `merge.ts`, the first
equal-stamp upsert in the `log.ts` fold). The old `Admissible` assumption said
equal key and stamp imply equal body, so the model never explored the case.

Model change: operations carry `ord`, the intake batch ordinal (`OpN`; `Op` is
`OpN` with ord 0). Mode `equalStamp` adds a corpus where one run emits a key
again at one stamp, with a delete, an omission and a clone (same run id, other
writer) at neighbouring stamps. `Rank` is the one total order:

    (stamp, kind rank, ordinal, body hash)    omission < upsert < delete

Equal rank implies equal body. A writer incarnation field, when the log
provenance design adds one, goes between kind rank and ordinal; it is equal
for all non-clone data, so no outcome changes. `P7` compares every reader with
an oracle that does not depend on apply order (greatest rank, then its body).
Mode `equalStampToday` is the mutant that ignores ordinal and body hash.

| Configuration          | Expected                                     | Actual                                                                                                                                          | Distinct states               | Depth | Wall time |
| ---------------------- | -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- | ----- | --------- |
| EqualStampToday.cfg    | FAIL P7                                      | FAIL P7 (`traces/EqualStampToday.txt`): a reader applies batch 2 (bodies 12, 22) after batch 1 (11, 21) at one stamp and keeps the first bodies | 704 at failure                | 6     | <1 s      |
| EqualStamp.cfg         | PASS (P1–P5, P7, EventuallyConverged)        | PASS, state space complete, no error found                                                                                                      | 3,447,086                     | 31    | 17 min    |
| EqualStampLifetime.cfg | no violation (same, with Reset and Rollback) | BOUNDED: stopped at 40 min (exit 124), no invariant error in explored states; 9.5M states left on queue; liveness not checked                   | at least 81,930,672 (partial) | n/a   | 40 min    |

Each run used `-workers 4`, `nice -n 19`, one job at a time, and its own
metadir, deleted after the run. An earlier 6-batch corpus did not finish in 30
minutes with no violation; the corpus was cut to five batches, which is the
one the table covers. Reset and Rollback are checked only in the Lifetime
config, because together with the equal-stamp corpus they grew the space
without bound.

The other configs still fail where expected (DropGap P2, OmissionInclusive P3,
DropKind OrderOK). Rerun 11-16 with radices derived from the corpus: EqualStampToday fails P7 (704 distinct states at failure), DropKind fails OrderOK, EqualStamp completes with the same 3,447,086 states and no error. Good.cfg and LostPush.cfg were not rerun: the base corpus
has ord 0 throughout and `Rank` reduces to the old order there, so their
results are unchanged by construction, not by a new run.

These results cover the abstract max operator only. The incremental SQL step is
checked separately, in "Incremental apply" below.

Clone and legacy rules the model fixes: two writers with one run id and one
ordinal go to the greater body hash, never to first seen; a legacy entry with
no ordinal counts as 0; an explicit delete beats every ordinal; an omission
loses to every upsert at its stamp.

## Incremental apply (`SqlRank.tla`, host run, 2026-11-16)

`LogProtocol.tla` folds a log with the max of one order. The local database
does not fold. It applies one observation at a time to a stored row in SQL:
`mergeIncoming` for a pulled operation and `replaceOwnRunRows` for the run's
own batch. The `LogProtocol.tla` result therefore covers the abstract max
operator only. The first version of the fix had two SQL shortcuts the model did
not explore:

- An identical body took the stored row only at a strictly greater stamp, so a
  higher ordinal of a body the database held was dropped. Trace: A at ordinal
  0, A at 2, then B at 1. The fold keeps A at 2 and rejects B; the incremental
  database kept A at 0 and then took B.
- `replaceOwnRunRows` replaced a different body at the run's stamp whatever the
  row held. A run that had pulled a clone's higher-ranked body lost it to its
  own lower batch.

`SqlRank.tla` models the incremental step on one key at one stamp (order:
ordinal, then body hash, as a tuple compare with no numeric packing). A
database either pulls an operation from the log or admits its own next batch
(strictly increasing ordinal). Its own batch is in the log only when it changed
the row. `RowIsFold`: the stored row equals the fold of the log, in any order.

| Configuration           | Expected | Actual                                                                                                                  | Distinct states | Depth |
| ----------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------- | --------------- | ----- |
| SqlRank.cfg             | PASS     | PASS, state space complete, no error found                                                                              | 1,029,883       | 6     |
| SqlRankSameBodyKeep.cfg | FAIL     | FAIL `RowIsFold` in 3 states (`traces/SqlRankSameBodyKeep.txt`): a pulled identical body at a higher ordinal is dropped | 33 at failure   | 3     |
| SqlRankOwnReplace.cfg   | FAIL     | FAIL `RowIsFold` in 3 states (`traces/SqlRankOwnReplace.txt`): the run's lower batch replaces a pulled higher one       | 80 at failure   | 3     |

Rules the passing model fixes, and the code that carries them:

- One order, `rankAfter` in `merge.ts` (stamp, ordinal, body hash). Pulled
  operations, an identical body at a higher ordinal included, advance the stored
  row. `replaceOwnRunRows` replaces only when the incoming batch ranks above
  the row by the same function. The stream-sync fold uses `upsertAfter`, the
  same order in TypeScript. `equal-stamp-order.test.ts` runs the SQL and the
  fold on the same operations: every sequence of up to three observations and
  200 random sequences of eight, drawn from a 32-bit generator. The test also
  counts the shapes in that corpus (every kind of step, an identical body at a
  higher ordinal, mixed alternation), so a degenerate generator fails it.
- A database's own batch with a body the row already holds is a sighting, not a
  change. It moves no ordinal and publishes nothing. So the ordinal a row holds
  is always one that is in the log or waiting to be published. Two writers that
  share a run id and both emit one body at different ordinals both publish, and
  the log then orders them. The alternative (the own sighting advances the
  ordinal and publishes the same body again) costs a log entry for each
  re-emitted unchanged row and fixes nothing the fold can see.
- Pulled operations apply to the row under origin `remote`. That already logged
  nothing for publish, so advancing the ordinal on an identical body needs no
  publish step.

Not modelled: the SEEN stamp, `promoteSeen` and a stored stamp older than the
run's. They act between different stamps. The older-stamp case of
`replaceOwnRunRows` is covered by the same `rankAfter`: a row with an older
stamp ranks below the run's batch whatever its ordinal. The `LogProtocol.tla`
rank packing takes its radices from the corpus (one more than the largest
ordinal and body it uses; kinds have three ranks), so it is exact for any
corpus. `SqlRank.tla` compares the tuple and packs nothing.

## Per-stream heads beside the log (`apply.ts`)

A head's parts carry no ordinal, and the server does not serialize `stamp_n` in
a head (`stamp_n` is read only by `log-publish.ts` and written by intake,
admission, the merge and the log's apply). `apply.ts` stages a part's row with
`stamp_n = 0`, so in the merge it is a legacy log entry: one `Pull` of
`SqlRank.tla` with ordinal 0. A log-on device applies the registry's heads
before the log (`applyConnection`), then the log, so a first load meets both. The
order is one total order, so a part and a log entry arriving in either order
give one row. `equal-stamp-order.test.ts` has a `part` step (same SQL options as
`applyOneOnce`) in its exhaustive and random sequences, and
`log-protocol.test.ts` loads a head and a log naming one key at one stamp
through a first load, a progressive first load and a compacted snapshot. Those
tests assert first-load devices only. The writer and a reader that already
followed the log are cycled and asserted in the boundary tests (below).

Boundary, not an ordering matter: a log-on device that already follows the log
does not read a head whose registry version is not above its own
(`applyOneOnce`, the `head_version > read.version` answer), at any stamp. A first
load reads it. So a head published outside the followed log reaches first loads
and not the devices that follow it. `log-protocol.test.ts` pins this at an equal
stamp and at a later one (the second case is decided by the stamp alone, so the
ordinal plays no part). The test expects today's split; closing the boundary
changes its expected values.

What publishes a head beside a log is not only the flag. A log-off device does.
So does a log-on device whose registry has no batch route, or that cached "no
batch route" earlier: `publishLog` returns `null` and the caller publishes per
stream (`log-publish.ts:184-185`, `232-234`). A fleet whose flags are all on is
not by that fact free of this boundary, for example during a gateway rollout.
No test here drives that fallback. A device that flips from log on to log off on
one database also fails its per-stream publish with a `UNIQUE` error on
`stream_versions` (the log's apply allocates versions there); that refusal
predates the ordinal. Whether it leaves the records, the remote head and the
retry consistent is not verified here.

With the log off and admission on (`publishWhileCollecting`) a device stores
`stamp_n` in its own rows and orders its own bodies by it. No log segment is
written and a head holds no ordinal. A device that turns the log on after it
published a head, then a first load, both hold the final body (the test asserts
bodies only).
