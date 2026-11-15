## R4: D1-D4 model, source reconciliation and host gate

Pinned source: personal-server-ts 49d1e3d4d3700022af9e9a9a03f332e215331796.
Use **BatchVisibilityR4.tla with R4-\*.cfg**, not the historical module/configs
below. This section redoes/supersedes the R3 README reconciliation (receipt
report_dc8d7bb0-392e-4696-bb33-4c4b159ca7f4, diff 300530409e04ecc2...).
The three helper definitions and writerCompatibility are now in scope and read.
The historical module and masked property text below are untouched.
The predicted outcomes below were checked by the host run in "R4 host TLC
results" (SANY parse, then TLC on every R4 config). Historical counts do not transfer.

### Model and actions

One connection, one mutable-state stream, two keys, two simultaneously open
runs with fixed scalar ranks 1 (older), 2 (newer), embedding their (o,r) order.
Both begin at generation 1/delete snapshot 0. Each can receive up to three
strictly sequential single-key batches. Values are distinct per run/batch/key.
The row's batch field records the last winner for the oracle; it is NOT part
of the stamp. Equal-stamp upserts replace in PROPOSED, except M11.
Batch updates staging by key, including upsert/delete/upsert. Deletes remain
staged; only upserts become visible early. Admission checks all three concrete
fence facts and compatibility against version floor, head version and key.
Rejected compatibility marks updateRequired; earlier admitted rows stay.
A later run can raise the version floor at accepted End, then Publish a new
connector head while the older run remains collecting.

End(success,proof) separates complete accepted success from failed/refused end.
Acceptance requires current fence/compatibility, no updateRequired and no
newer committed run. It gates explicit deletes and checkpoint advancement.
PROPOSED does not unwrite previously admitted upserts on failed/refused end.
TODAY stages until accepted End. Publish rechecks admission/order and can
refuse an accepted end; TODAY then drops rows with that run's content stamp.
No preimage stack or restoration algorithm is invented.

An accepted full-inventory proof permits omission only at successful Publish;
checkpoint_window never omits. Proof is an explicit environment assertion of
complete source coverage, not inferred from a changing source or empty batch.
The modeled publication assumes replacement basis/CAS validation succeeded;
it is not a model of transport, CAS races or deferred basis reconciliation.
D2 removes out_of_order from batch admission, not from end/publication:
old-run upserts may enter only where no newer row/tombstone defeats them.

D3 stores the deleting run's stamp for explicit and omission deletes, including
absent keys. Per key, only the maximum tombstone matters for this finite model.
After every action, PROPOSED compacts strictly below the oldest COLLECTING run's
start stamp, or all tombstones when none remain collecting. Ended runs cannot
receive batches. Publication does not acknowledge away a still-needed tombstone.
TODAY instead models pending explicit floors and clears covered floors only at
successful publication. It does not claim durable omission protection.
Purge(control_deleted/generation_moved_by_delete/stream_deleted_after_start)
clears the one modeled stream and checkpoint. Stale runs stay fenced; there is
no new post-purge run in this bounded experiment.

### Properties and mutant discrimination

- AcceptedEndOnly: explicit/omission side effects and checkpoint have accepted
  end evidence; acceptance history remains even if later publication refuses.
- NoPurgedRows: no visible row from the pre-purge lifetime/delete snapshot.
- CompatibleAdmission: no proposed upsert admitted against incompatible head/floor.
- NoOlderResurrection: independent high-stamp history checks newer writes and
  deletes even after publication/compaction. An absent row does not carry an
  artificial immortal stamp in the implementation state.
- SameRunLaterBatch: a winning admitted upsert must contain that batch's value.
- TombstoneBound: no retained tombstone below the open horizon, none without an
  open run, at most one maximum per key. This finite bound is NOT a cardinality
  bound for arbitrary keys or arbitrarily long production runs.
- CurrentPrimaryKeyOnly: expected-fail known-gap property, checked after the
  newer primary-key head is published. It is not a required D1-D4 invariant.

All configs have two keys and MaxSteps=8; the two initial open runs eliminate
two Begin actions from each trace. No liveness/fairness claim; bound exhaustion
stutters and CHECK_DEADLOCK is FALSE.

| Config                        | Predicted TLC result                           |
| ----------------------------- | ---------------------------------------------- |
| R4-PROPOSED-full_inventory    | PASS all configured invariants                 |
| R4-PROPOSED-checkpoint_window | PASS all configured invariants                 |
| R4-TODAY-full_inventory       | PASS configured local-phase invariants         |
| R4-TODAY-checkpoint_window    | PASS configured local-phase invariants         |
| R4-new-connector              | PASS; older connector's next batch is rejected |
| R4-pk-known-gap               | FAIL CurrentPrimaryKeyOnly, intentionally      |
| R4-m7                         | FAIL NoPurgedRows                              |
| R4-m8                         | FAIL CompatibleAdmission                       |
| R4-m9-full_inventory          | FAIL NoOlderResurrection, omission only        |
| R4-m9-checkpoint_window       | FAIL NoOlderResurrection, explicit only        |
| R4-m10-full_inventory         | FAIL NoOlderResurrection, omission only        |
| R4-m10-checkpoint_window      | FAIL NoOlderResurrection, explicit only        |
| R4-m11                        | FAIL SameRunLaterBatch                         |

Predicted witness recipes (not executed TLC traces):

- M7: Purge, then stale Batch(1,x,upsert).
- M8: End(2,success), Publish(2), Batch(1,x,upsert), with version 2.
- M9/M10 explicit: Batch(1,x,upsert), Batch(2,x,delete),
  End(2,success), Publish(2), Batch(1,x,upsert).
- M9/M10 omission: Batch(1,x,upsert), Batch(2,y,upsert),
  End(2,success,proof), Publish(2), Batch(1,x,upsert).
  DeleteMode forces omission-only versus explicit-only, so one mutant cannot
  accidentally satisfy both coverage goals through the same delete mechanism.
- M11: two consecutive upserts of x by run 1; second value must replace first.
- Known gap: Batch(1,x,upsert), Batch(2,y,upsert), End(2,success),
  Publish(2), with connector version 2 and changed primary key. Old x remains
  under key profile 1; generation remains 1. No purge is invented to fix this.

Host invocation for each named config:
`java -cp /path/to/tla2tools.jar tlc2.TLC -config R4-m7.cfg BatchVisibilityR4.tla`
Run every R4 config separately and record parser status, actual invariant,
trace and state counts. A syntax/type/runtime error is not a mutant success.
Increase bounds only after this small set is validated.

### R4 host TLC results (2026-11-15)

SANY: `BatchVisibilityR4.tla` parses (exit 0, no errors). Each config ran alone
through the host suite-slot wrapper, 4 workers, nice 19, own metadir, 45-minute
cap. The PASS configs completed their search; the FAIL configs stopped at their
first violation. None hit the cap.
Traces for failing configs are in `traces/`.

| Config                        | Predicted                  | Actual                                                    | Distinct states  | Depth |
| ----------------------------- | -------------------------- | --------------------------------------------------------- | ---------------- | ----- |
| R4-PROPOSED-full_inventory    | PASS                       | PASS, no error                                            | 160,880          | 9     |
| R4-PROPOSED-checkpoint_window | PASS                       | PASS, no error                                            | 80,973           | 9     |
| R4-TODAY-full_inventory       | PASS                       | PASS, no error                                            | 153,296          | 9     |
| R4-TODAY-checkpoint_window    | PASS                       | PASS, no error                                            | 75,387           | 9     |
| R4-new-connector              | PASS                       | PASS, no error (rejection witness not separately checked) | 89,931           | 9     |
| R4-pk-known-gap               | FAIL CurrentPrimaryKeyOnly | FAIL CurrentPrimaryKeyOnly (intended)                     | 503 at failure   | 6     |
| R4-m7                         | FAIL NoPurgedRows          | FAIL NoPurgedRows                                         | 455 at failure   | 5     |
| R4-m8                         | FAIL CompatibleAdmission   | FAIL CompatibleAdmission                                  | 432 at failure   | 5     |
| R4-m9-full_inventory          | FAIL NoOlderResurrection   | FAIL NoOlderResurrection                                  | 1,427 at failure | 6     |
| R4-m9-checkpoint_window       | FAIL NoOlderResurrection   | FAIL NoOlderResurrection                                  | 1,651 at failure | 6     |
| R4-m10-full_inventory         | FAIL NoOlderResurrection   | FAIL NoOlderResurrection                                  | 1,430 at failure | 6     |
| R4-m10-checkpoint_window      | FAIL NoOlderResurrection   | FAIL NoOlderResurrection                                  | 7,042 at failure | 7     |
| R4-m11                        | FAIL SameRunLaterBatch     | FAIL SameRunLaterBatch                                    | 21 at failure    | 4     |

No expected/actual mismatch. The "at failure" counts are the states TLC had
reached when it stopped on the violation, not full state-space sizes.
Not checked: the new-connector "next batch is rejected" witness is a prediction
about the trace; the config's invariants passed, but this run did not verify it.

### Source matrix and remaining other causes

Paths are relative to packages/core/src unless qualified otherwise.

- localdb/fence.ts:20-43,94-106: control_deleted, generation_moved_by_delete,
  stream_deleted_after_start. Null admission/undefined connection branches are
  real but excluded by this model's initially bound, existing connection.
- stream-sync/publish-plan.ts:176-186,205-221: out_of_order and
  connector_update_required are the two planner refusal reasons. Version floor,
  head version and key compatibility are independent of whole-connection purge.
- packages/stream-sync/src/head.ts:486-502: same key uses base; changed key
  requires strictly higher version; otherwise connector_update_required.
- localdb/bootstrap.ts:42-78 writes generation from the control state, not a
  primary-key change. The old-key-row gap is deliberately retained and isolated.
- localdb/run-intake.ts:76-83,445-454,517-546: stopped/key-type conflict and
  sequential/replayed batch validation, staging INSERT OR REPLACE. These are
  invalid/intake failures, not successful admitted observations. The new D1
  per-batch compatibility check is PROPOSED, not a claim current intake has it.
- localdb/run-end.ts:77-95,105-123,155,177-179: missing/ended lifecycle returns,
  failed/cancelled abort, batch-gap error and missing stream state. These are
  other non-accepted outcomes; none authorizes deletes/checkpoint.
- localdb/run-end.ts:207-280: planner refusal versus accepted/deferred staging
  merge and explicit deletion. :330-367 has nuanced retry/per-stream checkpoint
  rules; R4 restricts to a complete single-stream success with candidate and no
  unresolved seed, not a purported proof of those multi-stream retry rules.
- localdb/publish.ts:2489-2542: lifetime_changed removes run-stamped work and
  forces recollection; :2545-2579 handles the three fence trips. R4's explicit
  environment purge covers their stale-lifetime safety, not every cleanup step.
- localdb/publish.ts:2694-2713 returns planner refusal or deferral;
  :1085-1096 unwrites refused content then calls applyRegistry. localdb/unwrite.ts:
  18-52 deletes run-stamped rows/head parts and marks refused. R4 models that
  unwrite boundary, NOT the following registry reimport. Consequently TODAY
  assertions are local-phase checks, not final remote-state equivalence.
- localdb/merge.ts:114-124 pending explicit floors are publish-watermark bound;
  :138-160 distinguishes equal-body SEEN from content ownership; :267-311
  orders omission/explicit deletes; :314-337 unwrites content and clears SEEN.
  Distinct bodies intentionally avoid collapsing the equal-body ownership case.
- stream-sync/publish-plan.ts:135-147,188-204,294-307: generation_unbound,
  stale_generation, seed_unresolved, earlier_run_pending, publication_in_flight
  are DEFERRED, not additional refusal causes. R4 does not convert them to failure.
- localdb/publish.ts:2761-2791 excludes seed rows outside generation 1; separate
  import special case, not an admitted ordinary-run observation.

The remaining identified wrong-profile concern is the specified KNOWN GAP, not
a reason to reopen the fixed design. Other input/lifecycle failures above are
not evidence that an already admitted row is wrong. No exhaustive claim is made
about helpers outside scope. R4 excludes remote application, equal-body SEEN,
additional runs/reconnects, multi-stream retries, seed import, three other
coverage strategies, and concrete registry/network/crash behavior. It is a
finite design experiment and not an implementation refinement proof.

---

# Batch visibility: finite design model (unexecuted)

Pinned source: vana-com/personal-server-ts 03b809316abf86c4c9b429e63d64578c7e508524.
The BRIEF names df94f29aa2b48cc241ae6ac07c6d46d43817dd7f as the conceptual base;
source grounding here uses the assigned checkout, not an inferred older checkout.

## Status

SANY passes on the spec. TLC ran on the host (see TLC results) and produced:

- Baselines at K=2: all eight configs pass at MaxSteps=6 with no error. At
  MaxSteps=8 all four K=2 baselines hit the 900 s timeout unfinished.
- Mutants at K=2, MaxSteps=6 (m1-K2-S6 to m5): each violates its expected
  invariant. m5 is new and breaks CheckpointSoundness.
- Mutants m1-m4 at K=3, MaxSteps=8 (earlier run) also violate their invariants.
- Not checked: K=3 baselines, MaxSteps=8 at K=2, any unbounded proof.

BRIEF line 27 is redacted, so one obligation is unknown. The spec TODO marks it.
Nothing was reconstructed for it.

## Source grounding and abstraction

- run-intake.ts:89 and :515-546 stage run_rows and advance last_batch atomically;
  the latter is ingestion sequencing, NOT an asserted connector checkpoint.
- run-end.ts:198-240 derives full proof and decides replace, :263-280 stages accepted
  upserts and explicit deletes for merge.
- replace.ts:20-28 requires full_inventory, mutable_state, successful stream,
  full_refresh, coverage and producer proof. The model assumes mutable_state and
  full_refresh and makes successful proof an explicit Prove action.
- merge.ts:18-42 distinguishes effective SEEN observation from published content
  stamp; :97-128 documents ordering and pending explicit-delete protection.
- merge.ts:267-281 preserves observations at/after the replacement cutoff.
  :285-312 commits explicit deletion stamps; :315-330 describes dropping rows
  of a refused/discarded run. Failed model runs drop staging, not previously
  committed observations. Refusal after publication is a separate excluded case.
- apply.ts:520-522 applies the head omissionCutoff; merge.ts:212-261 describes
  remote omission and promotion of later local observations.
- schema.ts:20-32 stores rows and ordered changes; :54-73 stores runs and staging.
- stream-sync/intake.ts:62-67 declares the five coverage strategies. This bounded
  model covers full_inventory and checkpoint_window only.
- Style: PublishSnapshot.tla uses a finite history and constant-selected design;
  RegistryPoke.tla separates state transitions from property predicates.

All paths above are under packages/core/src/ except the two formal model examples.

## State and design choices

K has three keys; values have two non-absent values. Each batch contains one
arbitrarily selected source key, once per run, so batch order is arbitrary.
ChangeSource may alter values/membership before or during runs. Begin reserves a
fixed run observation stamp; W can upsert or explicitly delete any key at any time
with a newer stamp. A scalar rank abstracts the total lexicographic (o,r) order,
not wall-clock synchronization. TODAY stages until successful End; PROPOSED merges
batches immediately and keeps them on failure. Either can fail before proof.
Prove is allowed after every currently present source key has been seen, but does
not assert snapshot consistency across a changing source. Checkpoint events copy
only the merged batch set. TODAY advances its checkpoint at successful merge/end.
A checkpoint is a set of acknowledged batch identities, not a numeric external cursor.

Every committed action appends a store image plus deletion floor. Publish advances
R one commit at a time, permitting every prefix, including long lag. This abstracts
transactional publication/replay; it does not prove registry CAS, partition encoding,
crash recovery, transport, encryption, generation fencing, or concurrent collectors.
Publishing duplicate/no-op images is harmless but increases the state space.

Delete floors are retained indefinitely in this design model. This is a REQUIRED
anti-resurrection abstraction, not a claim that current SQL retains all explicit or
omission tombstones forever (merge.ts pending-delete protection is watermark-bound).
Implementers must prove an equivalent ordering/floor protocol before treating model
results as implementation evidence. Content/SEEN stamp compaction is collapsed to
the effective observation stamp. Source mutation itself is not a committed record.

## Properties and discrimination

P1 NoOmissionBeforeProof tracks actual omission removals, whether committed to D
or subsequently visible in any R prefix. P2 tracks removal by failed End only;
an independent W delete is not attributed to a failed run.
P3 compares each device with deletion floors in its own committed prefix, so a
lagging reader is not falsely called a resurrection. P4 compares pre-omission
later rows with post-End rows. P5 is the permitted quiescence invariant, not a
fairness/liveness claim: inactive run and fully replayed log imply both stores
equal an independent greatest-stamp oracle. P6 checks acknowledged batches are
included in merged batches.

Witnesses below were reasoning examples. TLC has since run each at K=2,
MaxSteps=6; the counterexample lengths are in TLC results.

- m1.cfg: W seeds k1; Begin; Batch(k2) with k1 absent from that batch. Early omission
  violates P1 before proof. R can then publish that premature removal.
- m2.cfg: W seeds k1; Begin with source absent; Prove; End(FALSE). Failed replace
  violates P1 and P2.
- m3.cfg: Begin with source absent; W upserts k1; Prove; End(TRUE). Missing cutoff
  removes a later row, violating P4; after draining Publish, P5 also fails.
- m4.cfg: Begin with source k1; W deletes k1; Batch(k1). Unconditional old-stamp
  overwrite violates P3; after failure/end and draining publication, P5 fails.
- m5.cfg (TODAY, checkpoint_window, Mutant=5): the Checkpoint action sets
  checkpoint to seen, not merged. TODAY never merges during a run, so seen holds
  keys that are not in merged. Checkpoint(k1) after Batch(k1) breaks P6. PROPOSED
  cannot show this: its Batch merges each key at once, so seen = merged during
  a run. The Checkpoint guard also reads seen for Mutant=5; without that change
  the action never fires in TODAY, because checkpoint and merged both stay {}.
  TLC stops at the first invariant failure, so to observe subsequent P5 witnesses,
  rerun a copied mutant config checking only TypeOK and StampConvergence.
  P6 (CheckpointSoundness) is discriminated only by m5. The four mandated mutants
  do not advance checkpoints ahead of merge.

## Host gate

From this directory, with an independently available trusted tla2tools.jar:

```
java -cp /path/to/tla2tools.jar tla2sany.SANY BatchVisibility.tla
for cfg in TODAY-*.cfg PROPOSED-*.cfg m?.cfg; do
  java -cp /path/to/tla2tools.jar tlc2.TLC -workers 2 -config "$cfg" BatchVisibility.tla
done
```

Record each config's generated states, distinct states, depth, Error/No error
lines and measured counterexample length here. Baselines must pass; mutants must
fail semantically, not from parser/type/runtime errors. MaxSteps=8 bounds source,
writer and collector actions; Publish may drain after the bound. This is finite
bounded exploration, not an unbounded proof. Increase the bound separately and
report cost/results. Deadlock checking is disabled because exhaustion intentionally
stutters; no liveness property is asserted.

## TLC results (host, 2026-11-15)

Command: `java -XX:+UseParallelGC -Xmx2g -cp tla2tools.jar tlc2.TLC -workers 2 -deadlock`
(tla2tools 1.7.4, `nice -n 19 ionice -c3`, 900 s timeout per run). Each run ran
alone. Depth for completed runs is TLC's "complete state graph search" depth. For
unfinished runs it is the last `Progress(n)` level. Counts for unfinished runs are
the last Progress line before the timeout. Logs are in `~/.tmp/tla-brief-meta/`
(not committed); state dirs were deleted after each run.

| Config                           | K        | MaxSteps | Result                                                | States generated            | Distinct states            | Depth                    | Runtime       |
| -------------------------------- | -------- | -------- | ----------------------------------------------------- | --------------------------- | -------------------------- | ------------------------ | ------------- |
| TODAY-full_inventory             | k1,k2,k3 | 8        | unfinished (not run at K=3; 74.7M distinct per brief) | n/a                         | n/a                        | n/a                      | n/a           |
| TODAY-full_inventory-K2          | k1,k2    | 8        | unfinished                                            | 205,638,194 (last Progress) | 97,515,271 (last Progress) | >=10 (last Progress(10)) | 900 s timeout |
| TODAY-full_inventory-K2-S6       | k1,k2    | 6        | No error                                              | 24,217,061                  | 9,823,939                  | 13                       | 1m 12s        |
| TODAY-checkpoint_window-K2       | k1,k2    | 8        | unfinished                                            | 208,949,589 (last Progress) | 99,681,765 (last Progress) | >=10 (last Progress(10)) | 900 s timeout |
| TODAY-checkpoint_window-K2-S6    | k1,k2    | 6        | No error                                              | 23,943,077                  | 9,717,346                  | 13                       | 1m 08s        |
| PROPOSED-full_inventory-K2       | k1,k2    | 8        | unfinished                                            | 153,418,766 (last Progress) | 78,257,208 (last Progress) | >=9 (last Progress(9))   | 900 s timeout |
| PROPOSED-full_inventory-K2-S6    | k1,k2    | 6        | No error                                              | 27,911,023                  | 11,703,559                 | 13                       | 1m 48s        |
| PROPOSED-checkpoint_window-K2    | k1,k2    | 8        | unfinished                                            | 152,716,748 (last Progress) | 79,146,279 (last Progress) | >=9 (last Progress(9))   | 900 s timeout |
| PROPOSED-checkpoint_window-K2-S6 | k1,k2    | 6        | No error                                              | 28,787,923                  | 12,191,646                 | 13                       | 1m 38s        |

Mutants (earlier runs, not rerun):

| Config | K        | MaxSteps | Result                                   | States generated | Distinct states | Depth       | Runtime |
| ------ | -------- | -------- | ---------------------------------------- | ---------------- | --------------- | ----------- | ------- |
| m1     | k1,k2,k3 | 8        | Invariant NoOmissionBeforeProof violated | 7,742            | 4,324           | not printed | 1 s     |
| m2     | k1,k2,k3 | 8        | Invariant NoOmissionBeforeProof violated | 770,626          | 396,488         | not printed | 4 s     |
| m3     | k1,k2,k3 | 8        | Invariant LaterWriteKept violated        | 815,117          | 419,263         | not printed | 4 s     |
| m4     | k1,k2,k3 | 8        | Invariant NoResurrection violated        | 11,627           | 6,357           | not printed | <1 s    |

Mutants at K=2, MaxSteps=6 (this run, `-workers 2 -deadlock`, one run at a time).
Counts are at the point TLC stopped on the violation. Trace length is the number
of states TLC printed, including the initial state.

| Config   | Design / Coverage / Mutant    | Violated invariant    | States generated | Distinct states | Counterexample length | Runtime |
| -------- | ----------------------------- | --------------------- | ---------------- | --------------- | --------------------- | ------- |
| m1-K2-S6 | PROPOSED / full_inventory / 1 | NoOmissionBeforeProof | 1,764            | 1,027           | 4                     | <1 s    |
| m2-K2-S6 | PROPOSED / full_inventory / 2 | NoOmissionBeforeProof | 71,330           | 37,207          | 5                     | <1 s    |
| m3-K2-S6 | PROPOSED / full_inventory / 3 | LaterWriteKept        | 77,341           | 40,258          | 5                     | <1 s    |
| m4-K2-S6 | PROPOSED / full_inventory / 4 | NoResurrection        | 3,415            | 1,880           | 4                     | <1 s    |
| m5       | TODAY / checkpoint_window / 5 | CheckpointSoundness   | 3,466            | 1,901           | 4                     | <1 s    |

Notes:

- No baseline reported an invariant violation, so there is no counterexample trace.
- The two checkpoint_window K=2, MaxSteps=6 baselines were re-run after the
  Checkpoint edit for m5. They gave the same counts as before (TODAY 23,943,077 /
  9,717,346; PROPOSED 28,787,923 / 12,191,646), so Mutant=0 behaviour is unchanged.
  The full_inventory baselines were not re-run; that action is untouched.
- m5 trace: Initial, Begin, Batch(k1), Checkpoint. checkpoint = {k1} while merged = {}.
- Every K=2 run at MaxSteps=8 hit the 900 s timeout. Dropping from 3 keys to 2 did
  not make MaxSteps=8 tractable: distinct states were still growing at about
  6M per minute when the timeout hit.
- MaxSteps=6 completed for all eight baselines (0 states left on queue, no error).
  Depth 13 is larger than MaxSteps because `Publish` may drain after the bound
  (see Host gate).
- The MaxSteps=6, K=2 result is a bounded check only. It does not cover K=3 or
  MaxSteps=8.
