# Formal model of whole-file stream sync

Status: design revision 4.1 with these rulings and review fixes:

- **Base rule with three outcomes (§2.7).** The stream row has generation
  `< T` or there is no row: empty base. Generation `= T`: that row is the
  base. Generation `> T`: `stale_generation`. Publish nothing, re-read
  control and decide again.
- **Ruling Q9 (§2.6, §2.4).** A no-op onto a `complete:false` base sets
  `needsFull` and blocks the checkpoint, the same as publishing
  `complete:false`.
- **S1 reads the current stream row**, not the latest head of a
  generation.
- **The model has a device that leaves** and an explicit no-op path.
- **An empty base never gives a no-op (M3).** A run onto no row, an old
  app's tombstone or a row of an older generation publishes, at least an
  empty `complete:false` head. That sets `needsFull` and blocks the
  checkpoint, so the next run is full. This matches the package, whose
  `isNoop` is false for a null base.
- **A run's `full` flag follows `runMustBeFull`:** no checkpoint, or any
  `needsFull` of the connector, makes the run full.

The model also has the run intake contract v2 (its section 9), as the
owner's decisions reduce it: no tombstones, no deletion by absence and
no restricted streams. A START that limits fields or resources is
rejected, so the model does not have one. The intake parts are:

- **Covered streams.** A run declares the streams it covered. Only those
  are published or checkpointed. An uncovered stream keeps its row. A
  covered stream may have no records.
- **The writer issues the START state.** A full run that the owner starts
  gets the stored checkpoint with mode `full_refresh`. Only a full run
  that the writer forces (`needsFull`, or no checkpoint) gets no state.
  The model takes `full` from the issued mode, never from "no state".
- **`retry_pending`.** The run publishes nothing and saves its checkpoint
  candidate, with the same control check as a finished run.
- **`abortRun`.** The run publishes and saves nothing.
- **Checkpoint merge.** A save merges its streams' cursors into the
  stored checkpoint when that has the same namespace and generation;
  otherwise it replaces it.
- **Per-stream full.** A stream declared `incremental: false` is full in
  every run (`fullS(s) = full ∨ s ∈ FullStreams`). A full stream merges
  into its base and never replaces it.
- **The raw-file seed is gone.** The seed from the old raw file and its
  account check (`RawSeedChecksId`, `C17`) are removed. The old raw
  file stays as one of the legacy files that reads are checked against.

The intake model found two defects (S7 on a `retry_pending` end, and L3
on `Live-leave`). Their F2 fixes (`RetryQuietOnly`, `RetryCkptStaysFull`
and the `Fix-*` configs) are superseded by R28 and removed from the
model. Read "R28" below.

No other counterexample was found within the bounds below. Read
"Results" for what was checked at which bounds and in which mode.

Model: `StreamSync.tla`, sha256 prefix `3cc40833c1f1`. TLC 2026.11.03
(`tla2tools.jar`).


## R28 (F3): retry_pending publishes progress

Ruling R28 replaces R19 ("retry_pending saves its checkpoint only"). The
model now has these rules. Each one is a guard, and each guard has a
negative control that must fail with its named property.

- **Publication.** A `retry_pending` end that received records publishes
  its covered streams by the ordinary rules and its record-bearing
  uncovered streams as keyed merges, always `complete:false`
  (`PubSet`, `CovD`; control `C-retry-head-complete`, `C-retry-replace`).
  An uncovered stream with no records gets no head. An end with no
  records at all is checkpoint-only (`RetryEmpty`).
- **Checkpoint after publish.** The retained streams are the
  `candidate` of a retry end and the covered streams of a succeeded or
  partial end. The checkpoint is saved by `Finish`, after every planned
  stream committed (control `C-retry-checkpoint-before-publish`,
  action `RetryEarly`).
- **Provenance.** `ckpt[d].prov[s]` is the run whose cursor carries retry
  provenance, saved in the same update as the cursor under the same
  `(n, g)`. A retry end gives it to a stream with `needsFull` debt. A
  later succeeded run keeps it while the debt remains (control
  `C-drop-provenance-on-success`). A covered full repair clears the debt,
  and so the provenance. Invalidation clears the whole checkpoint.
- **runPlan.** Per stream, explicit `wantFull` issues no state. A stream
  with `needsFull` is issued no state unless it holds eligible
  provenance, in which case it is issued its cursor (control
  `C-needsfull-hides-token`: today's rule, any `needsFull` hides every
  cursor). The run-wide START mode is `full_refresh` only when no stream
  is issued a state (`R24_CursorImpliesIncremental`, control
  `C-full-with-cursor`: an explicit full request issued with the saved
  cursor). A stream's full-read status is "issued no state"
  (`FullS`), not the run's mode.
- **Retry-progress streams do not clear their checkpoint.** A
  `complete:false` commit (publish or no-op) of a stream that is retry
  progress (`RP`) keeps `needsFull` debt visible but does not clear the
  checkpoint or block the save. Any other stream keeps F2's rule.
- **Checkpoint shape.** `ckpt` gains `pg` (the page a cursor names) and
  `prov`; `byRun` and `RetryCkptStaysFull` are gone (R27 rejected the
  fix). `RetryQuietOnly` is gone: a record-bearing retry stream may keep
  its cursor once it is published.
- **Budgeted connector.** `Budgeted` streams need two pages
  (`Page1`, `Page2`), one page per run. The next page is the one after
  the used cursor, a run before the last page ends `retry_pending`
  with a candidate, and a run at or past the last page may succeed.
  The budget profiles set `Desktop` to a model value outside `Devices`,
  because the Desktop seed would publish every key on the first run.

New properties: `S7_CheckpointSafety` (unchanged text; now also covers
retry cursors of record-bearing streams), `CoveredOnly` (an uncovered
head is never `complete:true`), `NoFalseDelete` (unchanged, now over retry
merges), `R24_CursorImpliesIncremental`, `ProvenanceAtomic`,
`NeedsFullRunIsFull` (per stream, exempting streams issued from
provenance), and liveness `L5_BudgetProgress` = `[]NoRestart /\ <>(every
page published)`. TLC reports the `[]` half as `Invariant NoRestart`.
`check.mjs` maps it to `L5_BudgetProgress`.

## Results (F3, model `3cc40833c1f1`)

Every run used 4 workers under `nice -n 19` on a shared, loaded host.
"Violates X" for a control or witness is the expected outcome: TLC stops
at the first violation, which must be the named property. The table was
generated from the run log; a row with "not run" had no completed run on
this model (see "Open gaps").

| Config | Property | Expected | Result | Distinct states | Depth | Seconds |
| --- | --- | --- | --- | ---: | ---: | ---: |
| `Small` | small | pass | not run (queue stopped) |  |  |  |
| `Key` | key | pass | not run (queue stopped) |  |  |  |
| `Full` | full | pass | not run (queue stopped) |  |  |  |
| `IdLess` | idless | pass | not run (queue stopped) |  |  |  |
| `Slice-faults` | slice-faults | pass | not run (queue stopped) |  |  |  |
| `Slice-faults2` | slice-faults | pass | not run (queue stopped) |  |  |  |
| `Slice-accounts` | slice-accounts | pass | not run (queue stopped) |  |  |  |
| `Slice-key` | slice-key | pass | not run (queue stopped) |  |  |  |
| `Slice-idless` | slice-idless | pass | not run (queue stopped) |  |  |  |
| `Slice-twice` | twice | pass | not run (queue stopped) |  |  |  |
| `Slice-q9` | slice-q9 | pass | not run (queue stopped) |  |  |  |
| `Slice-intake` | slice-intake | pass | not run (queue stopped) |  |  |  |
| `Slice-intake1` | slice-intake1 | pass | not run (queue stopped) |  |  |  |
| `Bud-delete` | bud | pass | not run (queue stopped) |  |  |  |
| `Bud-restart` | bud | pass | not run (queue stopped) |  |  |  |
| `Bud2` | bud2 | pass | not run (queue stopped) |  |  |  |
| `Retry1` | retry1 | pass | not run (queue stopped) |  |  |  |
| `Bud-live` | bud-live | pass | pass | 5339 | 25 | 2 |
| `Live` | live | pass | not run (queue stopped) |  |  |  |
| `Live-fail` | live-fail | pass | not run (queue stopped) |  |  |  |
| `Live-leave` | live-leave | pass | not run (queue stopped) |  |  |  |
| `Live-cover` | live-cover | pass | not run (queue stopped) |  |  |  |
| `CE-split-run` | split | pass | pass | 5018904 | 29 | 638 |
| `CE-late-head` | late | pass | pass | 6998289 | 30 | 656 |
| `C-late-head-old-rule` | late | violate S1_NoLostCommit | violates S1_NoLostCommit | 9078242 | 17 | 312 |
| `C01-no-gen-in-names` | late | violate S5_CleanupSafety | violates S5_CleanupSafety | 13291049 | 18 | 495 |
| `C02-key` | slice-key | pass | not run (queue stopped) |  |  |  |
| `C02-split` | split | pass | not run (queue stopped) |  |  |  |
| `C02-idless` | slice-idless | pass | not run (queue stopped) |  |  |  |
| `C03-non-exclusive` | late | violate S1_NoLostCommit | violates S1_NoLostCommit | 2081245 | 16 | 75 |
| `C04-reader-unions` | slice-accounts | violate S4_NoAccountMix | violates S4_NoAccountMix | 11525532 | 16 | 588 |
| `C05-seed-any-gen` | late | violate S3_CleanGeneration | violates S3_CleanGeneration | 1863978 | 15 | 109 |
| `C06-early-checkpoint` | split | violate S7_CheckpointSafety | violates S7_CheckpointSafety | 13226 | 9 | 3 |
| `C07-no-reread-after-create` | late | violate S3_CleanGeneration | violates S3_CleanGeneration | 52171 | 9 | 6 |
| `C08-rebind-old-spool` | late | violate S3_CleanGeneration | violates S3_CleanGeneration | 182257 | 13 | 13 |
| `C09-no-listing-needed` | slice-faults | violate S3_CleanGeneration | violates S3_CleanGeneration | 35338 | 8 | 4 |
| `C10-legacy-ignores-delete` | late | violate S2a_DeleteHolds | violates S2a_DeleteHolds | 33797 | 9 | 4 |
| `C11-collectedat-competition` | late | violate S9_OneWay | violates S9_OneWay | 86777 | 9 | 6 |
| `C12-no-needsfull` | slice-q9 | violate IncompleteOwned | violates IncompleteOwned | 118135 | 12 | 10 |
| `C13-pending-blocks-import` | live-fail | violate L2_Convergence | violates L2_Convergence | 1854021 | 16 | 722 |
| `C14-seed-only-empty-base` | late | violate S11_SeedCoverage | violates S11_SeedCoverage | 1150247 | 15 | 42 |
| `C15-failed-row-replaceable` | slice-settle | violate S8_AckImmutable | violates S8_AckImmutable | 3883509 | 16 | 188 |
| `C16-readiness-live-only` | slice-q9 | violate S10_ReadinessMatchesRead | violates S10_ReadinessMatchesRead | 60253 | 9 | 10 |
| `C19-no-q9` | slice-q9 | violate IncompleteOwned | violates IncompleteOwned | 9367787 | 21 | 691 |
| `C19L-no-q9` | live-leave | violate L3_NoStuckIncomplete | violates L3_NoStuckIncomplete | 337612 | 14 | 323 |
| `C20-null-base-noop` | slice-q9 | violate IncompleteOwned | violates IncompleteOwned | 61657 | 10 | 6 |
| `C21-needsfull-not-full` | slice-accounts4 | violate NeedsFullRunIsFull | violates NeedsFullRunIsFull | 17457 | 17 | 2 |
| `C18-immediate-delete` | slice-lag | violate S2_Immediate | violates S2_Immediate | 30610 | 9 | 4 |
| `C-publish-uncovered` | late | violate CoveredOnly | violates CoveredOnly | 109804 | 10 | 4 |
| `C-producer-state` | late | violate IssuedStart | violates IssuedStart | 186925 | 12 | 8 |
| `C-retry-checkpoint-before-publish` | late | violate S7_CheckpointSafety | violates S7_CheckpointSafety | 29805 | 9 | 2 |
| `C-retry-head-complete` | late | violate CoveredOnly | violates CoveredOnly | 90701 | 11 | 4 |
| `C-retry-replace` | late | violate NoFalseDelete | violates NoFalseDelete | 1817255 | 15 | 50 |
| `C-full-with-cursor` | late | violate R24_CursorImpliesIncremental | violates R24_CursorImpliesIncremental | 179867 | 12 | 7 |
| `C-drop-provenance-on-success` | bud-live | violate L5_BudgetProgress | violates L5_BudgetProgress | 1245 | 16 | 1 |
| `C-needsfull-hides-token` | bud-live | violate L5_BudgetProgress | violates L5_BudgetProgress | 256 | 10 | 1 |
| `C-full-replaces` | late | violate NoFalseDelete | violates NoFalseDelete | 1839937 | 15 | 49 |
| `W-trace-a` | lean | violate NotTraceA | violates NotTraceA | 2415753 | 8 | 53 |
| `W-trace-b` | lean | violate NotTraceB | not run (queue stopped) |  |  |  |
| `W-offline-vs-5` | twice | violate NotOfflineVs5 | not run (queue stopped) |  |  |  |
| `W-late-old-head` | lean | violate NotLateOldHead | not run (queue stopped) |  |  |  |
| `W-twice` | twice | violate NotTwice | not run (queue stopped) |  |  |  |
| `W-first-write-in-delete` | lean | violate NotFirstWriteDuringDelete | not run (queue stopped) |  |  |  |
| `W-phone-first-seed` | late | violate NotPhoneFirstThenSeed | not run (queue stopped) |  |  |  |
| `W-zero-emission-seed` | slice-accounts | violate NotZeroEmissionSeed | not run (queue stopped) |  |  |  |
| `W-settle-after-ack` | slice-settle | violate NotSettleAfterAck | not run (queue stopped) |  |  |  |
| `W-switch-reused-ckpt` | slice-accounts | violate NotSwitchReusedCkpt | not run (queue stopped) |  |  |  |
| `W-needsfull-with-ckpt` | slice-accounts4 | violate NotNeedsFullWithCkpt | not run (queue stopped) |  |  |  |
| `W-failed-entry` | lean | violate NotFailedEntryNewerHeads | not run (queue stopped) |  |  |  |
| `W-budget-resume` | bud | violate NotBudgetResume | violates NotBudgetResume | 22468 | 11 | 3 |
| `W-token-resume` | retry1 | violate NotTokenResume | violates NotTokenResume | 1387862 | 20 | 27 |
| `W-mixed-modes` | retry1 | violate NotMixedModes | violates NotMixedModes | 14880439 | 23 | 335 |
| `W-retry-merge` | retry1 | violate NotRetryMerge | violates NotRetryMerge | 518764 | 18 | 13 |

Run state: the queue stopped after `W-trace-a` (cause unknown), so 35
configs have **no run on this model**: the four simulations, every
exhaustive slice, `Live*`, `Bud-delete`, `Bud-restart`, `Bud2`, `Retry1`,
`C02-*` and the older witnesses. Their F2 results (model
`a14998644a62`) no longer apply, because R28 changed the transition
relation. They are not claimed.

### Bounds changed in F3, and what each removes

- **`split` profile** (used by `CE-split-run`, `C02-split`,
  `C06-early-checkpoint`): `MaxRetry 0`, `PartialCover FALSE`, `MaxVer 3`.
  Before the cut `CE-split-run` reached 24.4M distinct states at depth 14
  after 55 minutes with the queue still growing. After it: 5,018,904
  distinct states, depth 29, 638 s, exhaustive. Removed: retry ends and
  partial coverage in the split scenario, so every head there is
  complete. It still reaches the split case (a delete lands between two
  streams of one user-connect run). `MaxVer 3` removes nothing there; the
  review found the saving comes from the retry and coverage cut. As a
  result `CoveredOnly`, `ProvenanceAtomic`, `NeedsFullRunIsFull`,
  `IncompleteOwned` and `LaterWriteSurvives` are vacuous on this profile.
  Its pass is not R28 coverage.
- **`bud` split** into `Bud-delete` (`MaxSessions 0`) and `Bud-restart`
  (`MaxDeletes 0`): the joint delete-and-restart run did not finish.
  Restart together with delete is unchecked.
- **`Bud2`, `Retry1`:** `MaxRuns 3` instead of 4 (4 runs passed 7.0M and
  3.3M distinct states with no violation and no end). Removed: a fourth
  run that consumes a preserved result.
- **`Desktop = nodesk`** on the budget profiles: the Desktop seed would
  publish every key on the first run and hide the paging.
- The comment that names `split` as a place where partial coverage and
  `retry_pending` are checked is out of date.

### Counterexample summaries (negative controls, all as required)

- `C-retry-checkpoint-before-publish` (S7): a retry end saves the cursor
  of a stream whose records are not yet published; a crash after the save
  loses them. Depth 9.
- `C-retry-head-complete` (CoveredOnly): a retry merge for an uncovered
  stream is written `complete:true`, so a later full read believes the
  stream is whole. Depth 11.
- `C-retry-replace` (NoFalseDelete): a retry head replaces the base
  instead of merging; keys that the spool did not carry are deleted.
  Depth 15.
- `C-full-with-cursor` (R24): an explicit full request is issued with the
  retry cursor, so the run is full in name and incremental in fact.
  Depth 12.
- `C-drop-provenance-on-success` (L5): a later incremental success drops
  the provenance while the stream is still incomplete; the next run
  restarts at page 1. Depth 16.
- `C-needsfull-hides-token` (L5): today's rule, any `needsFull` hides the
  saved token, so the connector restarts at page 1. Depth 10.
- `C06-early-checkpoint` still fails S7, now on the cut `split` profile.
- No positive config found a counterexample. No R28 rule needed a fix
  after the push of `6c591823`; `StreamSync.tla` is unchanged since.

### Property to test map (RETRY-PROGRESS-DESIGN.md section 6)

- S7_CheckpointSafety (retry cursors included): tests 7, 8, 13.
- NoFalseDelete across retry merges: test 6.
- CoveredOnly: tests 1, 2, 12.
- R24_CursorImpliesIncremental: tests 3, 10.
- ProvenanceAtomic: tests 7, 11.
- L5_BudgetProgress: test 4; test 5 for the non-resumable cap.
- Admission and isolation (S2a, S3, unchanged): test 9.
- No test in section 6 covers: a run that mixes a resumed stream with a
  stream issued no state (witness `W-mixed-modes` reaches it, depth 23);
  cumulative coverage across several retry ends; a delete between two
  commits of a retry run. These need tests.

### Open gaps (for F3b)

The shrunk `split` and the missing positive runs leave these R28 plus
delete combinations without an exhaustive check (from the dot review):

- Retry, success that keeps provenance, a further continuation, and a
  remote delete in the third run, with two ordinary streams.
- Two-key retry merge with a delete splitting a two-stream run.
- Two or more retry ends (record retry, token-only retry, continuation)
  with a mid-run delete in a multi-stream history.
- A budgeted stream with a normal sibling and a remote delete; a budgeted
  continuation with a restart and a delete together.
- A retry head whose reply is lost across a delete.
- Liveness with retry debt and a delete: no positive liveness config
  has both. `Bud-live` has no delete, and L5 across a delete needs a
  generation-conditional property.
- The 35 configs listed under "Run state" must run on the final model.

Proposed constant-only configs are in the dot review report
(`f3-shrunk-constants-review.report.md`, section 3).

### R28 ambiguities and how they were resolved

- The full-read status is per stream by presence of issued state, not by
  the run's mode.
- A retry end with no records is checkpoint-only even when it covers
  streams.
- Provenance is saved only while `needsFull` debt exists.
- An explicit full request issues no cursor. This overrides F2's "an
  owner-started full run keeps the stored checkpoint".
- The model uses two pages (K=2).
- Crash points are modelled by a restart, a failed entry and a leaving
  device, with an outbox that persists.
- The `Live-leave` gap (a retry token, an old-app DELETE, the creator
  leaves) stays a known gap, as ruled in R27.

### C02 and C12

F2 text. `RetryCkptStaysFull`, `C12L-fix` and `Fix-*` are superseded by R28 and are no longer in the model.

For each of these guards, no control shows that the model needs it.
Neither is removed from the package.

**`C02`, `ClearOnGenChange`.** With the guard off, a device keeps its
checkpoint and outbox entry when the generation changes. Every safety
invariant still holds on `slice-key`, `split` and `slice-idless`, three
profiles where a delete changes the generation (`C02-key`, `C02-split`,
`C02-idless`). So the guard is redundant for safety in the model. A kept
checkpoint is tagged with its namespace and generation, so a save at the
new generation replaces it and never merges into it. A kept entry
decides again at publish, against the current control row (S3). An
incremental run at the new generation either merges into a head of that
generation, which deletes nothing, or publishes `complete:false` onto an
empty base (M3), which sets `needsFull`. The guard saves that one
incomplete run. In the package the guard is `observeControl` in
`writer.ts`, with the `clearCheckpoints` decision in `decide.ts`.

**`C12`, `NeedsFull`.** With the guard off, a `complete:false` publish
does not set `needsFull`. On `slice-q9`, `IncompleteOwned` fails
(`C12-no-needsfull`). That is by definition, because the invariant says
the device holds `needsFull`. The question is liveness (L3). A
`complete:false` publish also clears the checkpoint, so the next run
is full without `needsFull`, because the device has no checkpoint. The
one exception is a `retry_pending` end between the publish and the next
run that saves a job token: the next run is then incremental. In the
ruled contract only `needsFull` keeps that run full. With the proposed
fix (`RetryCkptStaysFull`) the run stays full anyway, so `needsFull`
may be redundant for liveness then. No config within the load limit
decides this:

- `C12L-fix` (`live-leave`, fix on, `needsFull` off) timed out at 3600
  seconds with no violation: 2,321,769 distinct states, 46,134 still
  queued. TLC checks liveness only on the graph it has built, so this
  is weaker than a pass.
- On `live-cover`, and on `live-leave` cut to `d1` with no leave, the
  state count is the same with `NeedsFull` on and off (42,776 and
  5,818). The path never occurs there, so those profiles cannot decide
  it, and their rows are not kept.

So the case for `needsFull` is argued, not checked: in the ruled
contract it is the only guard on the retry-token path. Keep it. In the
package, `afterCommit` in `needs-full.ts` adds the key, and
`runMustBeFull` and `runPlan` in `writer.ts` read it.

### Bounds

Superseded by R28: mentions below of `RetryQuietOnly`, `RetryCkptStaysFull` and the `Fix-*` configs describe the F2 model. R28 removed them.

All guards are TRUE except the one a control turns off, and
`RetryCkptStaysFull`, which only the `Fix-*` rows and `C12L-fix` turn
on. Devices are `d1` (the Desktop) and `d2` in every profile except
`slice-accounts4`, `slice-intake1` and `live-cover`. `MaxVer` is 6 (a
state constraint on chain length) in every safety profile. Symmetry:
accounts, record keys, and streams other than `s1` (streams declared
`incremental: false` permute only among themselves). Liveness profiles
have no symmetry and no state constraint.

Intake bounds: every profile allows one run that ends `retry_pending`
(`MaxRetry` 1) and no abort (`MaxAbort` 0), and declares no stream
`incremental: false` (`FullStreams` empty), except where the table says
so. Rows marked "cut" in Results use `CUT` from `configs.mjs`:
`PartialCover` FALSE, so every `ok` run covers every stream, and
`MaxRetry` 0. Without the cut those slices do not finish within an
hour. Partial coverage and `retry_pending` are checked on `split`,
`slice-key`, `slice-q9`, `slice-idless`, `slice-intake` and
`slice-intake1`, in the controls on `late`, and, for liveness, on
`live-cover` (partial coverage) and `live-leave` (`retry_pending`).

| Profile | Acct | PK | Streams | Runs (+ reruns) | Deletes | Lost / restarts / failed entries | Other |
| ------- | ---- | -- | ------- | --------------- | ------- | -------------------------------- | ----- |
| `late` | A | x1, x2 | s1 | 3 | 1 | 0 / 0 / 0 | |
| `split` | A | x1 | s1, s2 | 2 | 1 | 0 / 0 / 0 | |
| `slice-faults` | A | x1 | s1 | 3 | 1 | 1 / 1 / 1 | |
| `slice-accounts` | A, B | x1 | s1 | 3 | 1 | 0 / 0 / 0 | |
| `slice-accounts4` | A, B | x1 | s1 | 4 | 0 | 0 / 0 / 0 | `d1` only; `C21` and its witness only |
| `slice-key` | A | x1 | s1 | 3 | 1 | 0 / 0 / 0 | `d2` holds another owner key; imports on |
| `slice-idless` | A, B | x1 | s1 | 3 | 1 | 0 / 0 / 0 | identity-less connector |
| `twice` | A | x1 | s1 | 4 | 2 | 0 / 0 / 0 | |
| `slice-q9` | A | x1 | s1 | 4 | 0 | 0 / 0 / 0 | 1 old stream DELETE (L11), 1 leave |
| `slice-intake` | A, identity-less | x1 | s1, s2 | 2 | 1 | 0 / 0 / 0 | `s2` is `incremental: false`; 1 `retry_pending` and 1 abort |
| `slice-intake1` | A, identity-less | x1 | s1, s2 | 4 | 1 | 0 / 0 / 0 | as `slice-intake`, `d1` only |
| `slice-settle` | A | x1, x2 | s1 | 3 | 1 | 0 / 0 / 0 | 1 settlement failure |
| `slice-lag` | A | x1, x2 | s1 | 3 | 1 | 0 / 0 / 0 | reader PS `r1` |
| `lean` | A | x1 | s1, s2 | 3 | 1 | 1 / 1 / 1 | witnesses only |
| `live` | A | x1 | s1 | 2 (+2) | 1 | 0 / 0 / 0 | imports on, reader `r1` |
| `live-fail` | A | x1 | s1 | 2 (+2) | 1 | 0 / 0 / 1 | imports on, reader `r1` |
| `live-leave` | A | x1 | s1 | 3 (+3) | 0 | 0 / 0 / 0 | 1 old stream DELETE, 1 leave, 1 `retry_pending`; no imports, so no L2 |
| `live-cover` | identity-less | x1 | s1, s2 | 3 (+2) | 0 | 0 / 0 / 0 | `d1` only; partial coverage, no `retry_pending`; no imports, so no L2 |
| `small` (§4) | A, B | x1, x2 | s1, s2, s3 | 3 | 1 | 1 / 1 / 1 | simulation only |
| `key`, `full`, `idless` (§4) | as `small` | | | | `full`: 2 | `full`: 2 / 2 / 1 | simulation only |

### Scale

The section 4 profiles do not finish on this host. Breadth-first search
on `small` reached depth 11 with 37 million distinct states after
30 minutes, with 25 million more queued, before run intake v2 added its
choices. So this model checks those profiles in two ways:

- **Exhaustive slices.** Each slice keeps one dimension of `small` at
  full size and cuts the others: two accounts, faults, a second owner
  key, an identity-less connector, two deletes, two streams (`split`),
  two record keys (`late`), the Q9 events, and the intake choices
  (`slice-intake`, `slice-intake1`).
- **Simulation.** `Small`, `Key`, `Full` and `IdLess` run TLC's random
  simulation with seed 1 and depth 60 (`SIM` in `configs.mjs`). Each
  stops at 900 seconds. The intake choices make each step about 14 times
  slower than before, because TLC enumerates every subset of streams a
  run may cover, emit or keep. So each profile ran about 21,000 to
  25,000 random behaviours, not the earlier 800,000. A simulation that
  finds no violation is evidence, not proof. Most random behaviours end
  early: the mean length was 7 steps (standard deviation 9 to 10).

## What is proven, simulated only, and unproven

**Proven within the bounds of each row** (breadth-first search finished):

- Every safety invariant, including the four intake properties, holds
  on the exhaustive slices (`slice-key`, `slice-idless`, `slice-q9`,
  `slice-intake`, `slice-intake1`), on the cut slices (`slice-faults`
  twice, `slice-accounts`, `twice`) and on the two counterexample
  profiles (`split`, `late` with the cut). With the proposed fix on,
  they hold on `slice-idless` and `split`.
- The intake controls fail as expected. Publishing an uncovered stream
  breaks `CoveredOnly`. A producer-chosen START state breaks
  `IssuedStart`. Section 9's `retry_pending` save as written breaks S7.
  A full run that replaces its base breaks `NoFalseDelete`.
- L1 to L4 hold on `live` and `live-fail` (both cut). L1, L3 and L4 hold
  on `live-leave` with the proposed fix. L1 and L4 hold on `live-cover`,
  where L3 is vacuous (no `complete:false` head is reachable).
- L3 fails on `live-leave` with the ruled contract (see
  "Counterexamples").
- Q9 is needed. Without it L3 fails on `live-leave` (`C19L-no-q9`) and
  `IncompleteOwned` fails on `slice-q9` (`C19-no-q9`).
- M3 is needed. Without it `IncompleteOwned` fails (`C20-null-base-noop`).
- The `runMustBeFull` rule decides runs. A device can hold a checkpoint
  and a `needsFull` at once (`W-needsfull-with-ckpt`). Without the rule
  `NeedsFullRunIsFull` fails (`C21-needsfull-not-full`).
- `ClearOnGenChange` is not needed for safety on three profiles (read
  "C02 and C12").
- Every other control stops at its expected property, and every witness
  is reached.

**Simulated only:** the section 4 profiles `small`, `key`, `full` and
`idless`, about 21,000 to 25,000 random behaviours each, with no
violation.

**Unproven:**

- The section 4 profiles, exhaustively.
- Partial coverage or `retry_pending` together with two accounts,
  faults or four runs. Those slices finish only with the cut.
- Liveness with two streams and a reachable `complete:false` head, lost
  replies, restarts, or a failed entry together with a leave. Profiles
  with these did not finish on this host.
- Whether `needsFull` is needed for liveness once `RetryCkptStaysFull`
  holds (read "C02 and C12").
- That the package matches the model. This directory checks the model
  only.
- Everything under "Not modelled" below.

## Counterexamples kept as controls

Superseded by R28: mentions below of `RetryQuietOnly`, `RetryCkptStaysFull` and the `Fix-*` configs describe the F2 model. R28 removed them.

- [traces/retry-token-incremental.txt](traces/retry-token-incremental.txt):
  the ruled contract, found by the positive config `Live-leave`. `d2`
  has no checkpoint, so its run 2 is full. The run ends `retry_pending`
  with a job token for `s1` and no records, and the token is saved. No
  head of `s1` exists yet. Run 3 is incremental because `d2` holds a
  checkpoint and no `needsFull`. Onto the empty base it publishes
  `complete:false` (M3). An old app's DELETE then tombstones `s1`, and
  the scheduler's rerun is fair only while the stream is live and
  `complete:false`. So no run follows, and L3 fails. Proposed fix
  (`RetryCkptStaysFull`, config `Fix-live-leave`): a checkpoint that
  only `retry_pending` ends saved is issued as the START state, but the
  run is full (`full_refresh`).
- [traces/retry-spooled-cursor.txt](traces/retry-spooled-cursor.txt):
  run intake v2 section 9 as written. A `retry_pending` end saves its
  checkpoint candidate and publishes nothing, and the candidate may hold
  any covered stream. `d2`'s run emits records for `s1`, ends
  `retry_pending` with a cursor for `s1`, and saves it at generation 1
  after `d1` creates the control row. The records are dropped, and the
  next incremental run starts after them (`C-retry-saves-spooled`, S7).
  Fix, adopted and the model's default (`RetryQuietOnly`): a `retry_pending`
  end keeps no cursor of a stream that had records in the run. It can
  keep a cursor such as a job token only for a stream with no records.
  An equivalent fix accepts the candidate only when the run has no
  record batches.
- [traces/late-head.txt](traces/late-head.txt): the two-outcome base rule
  (revision 4.1 before F1). A run of generation 1 resumes after a delete
  and a reconnect elsewhere, and commits a generation-1 head over an
  acknowledged generation-3 head. With S1 against the current row, S1
  alone catches it (`C-late-head-old-rule`).
- [traces/no-q9.txt](traces/no-q9.txt): Q9 removed. An old app's DELETE
  tombstones the stream, `d1` publishes an empty `complete:false` head,
  and `d2`'s run is a no-op onto it. `d2` saves its checkpoint and holds
  no `needsFull` (`C19-no-q9`).
- [traces/null-base-noop.txt](traces/null-base-noop.txt): an empty base
  that gives a no-op (the model before M3). An old app's DELETE
  tombstones the stream during `d1`'s incremental run, whose spool for it
  is empty. The run saves its checkpoint and holds no `needsFull`, so no
  full run restores the stream (`C20-null-base-noop`).
- [traces/split-run.txt](traces/split-run.txt): revision 4. A
  `userConnect` run commits one stream at generation 1 and the next at
  generation 3 (`CE-split-run` now passes).

Reproduce a trace: add `-dumpTrace json FILE` to the TLC command and run
`python3 formal/traces/story.py FILE`.

## What the model is

Superseded by R28: mentions below of `RetryQuietOnly`, `RetryCkptStaysFull` and the `Fix-*` configs describe the F2 model. R28 removed them.

`StreamSync.tla` models one connector `c`. Each action maps to one
package function or host step; the module header lists the map. It
models:

- **Connections.** A namespace per account, or `""` for an
  identity-less connector. Each has a control row chain (`ctl`).
- **Streams.** One row chain per stream (`hd`), with exclusive writes.
  A row is a head, or the tombstone an old app's non-exclusive DELETE
  writes (limitation L11, `OldDelete`).
- **Storage.** Blobs stored by name (`store`).
- **Per device:** the session listing, `known`, `stopped`, `needsFull`,
  the checkpoint, one outbox entry (`ob`) and, optionally, the imported
  view. A device can leave for good (`Leave`); it loses its entry,
  `needsFull`, checkpoint and view.
- **Desktop.** `seedTarget` and the seed receipts.
- **Old raw file.** It is one of the legacy files (`Legacies`) that
  reads are checked against. Nothing seeds from it.
- **Lost replies.** `inflight`, which can land late (`LateApply`).

Each guard in section 4, and each ruling that adds a rule, is a
constant. A control sets one of them to FALSE. `configs.mjs` is the one
source of the TLC configs in `cfg/`. `check.mjs` regenerates the
configs, checks that `cfg/` matches, and runs TLC (`--run`).

Modelling choices the reader should check:

- **Records.** A line is `<<pk, run, account, origin>>`. Run ids follow
  run start order, so `(o, r)` order is run id order. Seed lines have
  run 0 and rank below run lines.
- **Runs.** A run chooses its end (`ok`, `retry_pending` or abort), the
  streams with records `E`, a non-empty set of keys, the covered streams
  `cov` and, for `retry_pending`, the streams of its checkpoint candidate
  `cand`. A stream outside `E` has an empty spool. A key the run does not
  emit is a record the source no longer has, or one outside the
  increment. Choices with the same future are made canonical: an `ok`
  run's records lie in `cov`, because the spool of an uncovered stream is
  dropped unread. A run plans its covered streams, and the Desktop's seed
  streams. An uncovered stream that only the seed plans publishes only
  if seeded; otherwise the run skips it with its receipt.
- **START.** The writer forces a full run when the device has no
  checkpoint or holds a `needsFull`; it then issues no state. A run that
  the owner starts (`userConnect`) may also ask for a full run while a
  checkpoint exists; it gets that checkpoint with mode `full_refresh`.
  A full run whose stored checkpoint has another namespace counts as an
  account switch, so its heads are `complete:false`.
- **Run ends.** Only an `ok` run publishes, and it saves its checkpoint
  only if it covered at least one stream. A `retry_pending` end saves its
  candidate under the same control check as `Finish`. On a connection
  with no control row it saves nothing. It keeps no cursor of a stream
  with records (`RetryQuietOnly`). An abort removes the entry.
- **Checkpoint.** A checkpoint holds one cursor per stream. A save
  merges into the stored checkpoint of the same namespace and generation,
  else it starts empty.
- **Delete.** A delete tombstones every active control row of the
  connector, as §2.11 says. It also purges the device's entry, checkpoint
  and view, and sets `stopped`.
- **Decide.** Each stream decides when it reaches publish, by the §2.4
  table on (start snapshot, current control). A create or reconnect reply
  sends the stream back to decide (the re-read). `NeverInconsistent`
  checks that the `registry_inconsistent` row never applies.
- **Base (§2.7).** Three outcomes on the stream row at the version the
  device writes after: generation `< T` (or a tombstone, or no row)
  gives an empty base; `= T` gives that row; `> T` is `stale_generation`
  (`PlanStale`): the stream goes back to decide, which discards the run.
  `NoHeadAboveControl` shows that control never still reads `active(T)`
  then.
- **No-op (§2.6).** A base of generation T, and every part and
  `complete` unchanged, or an empty spool with no seed: no upload and no
  POST, and the stream counts as committed. Under Q9 a no-op onto a
  `complete:false` base of generation T sets `needsFull`, blocks the
  checkpoint and clears it. An empty base never gives a no-op (M3): the
  run publishes, at least an empty `complete:false` head. A stream that
  never has records therefore costs one extra full run per generation.
- **Full runs.** A run is full when the device has no checkpoint or holds
  any `needsFull` (the model has one connector), as `runMustBeFull` says.
  A device can hold `needsFull` for one account and a checkpoint for
  another, so the second condition decides runs (`W-needsfull-with-ckpt`,
  `C21-needsfull-not-full`).
- **Reads.**
  - Checked on every reachable registry state. Rows are append-only in
    the design, so a reader's snapshot is always some past state, and
    the current-state check covers it.
  - Checked against every legacy file: none, or any account's, older
    than every head or newer than every head. This stands for old
    installs that write at any time, also after a delete or after
    cutover, so those two section 4 scenarios hold by construction.
  - Only `C18` and `slice-lag` use a lagging reader PS. It shows that
    deletion is eventual, not immediate.
- **Imports.** `Import` is one sync-loop pass per device. Only S12 and
  L2 read the view, so the other profiles turn it off (`Views = FALSE`).
- **Settlement failure.** It changes what a writer does only when
  `AckImmutable` is FALSE (C15). The other profiles leave it out.
- **Cleanup.** It removes the objects of all heads of a deleted
  generation, all streams at once.
- **Fairness.** Weak fairness on each device's progress, listing and
  import, on reader sync and late replies, and on the scheduler's run
  (`Rerun`) for a device that has not left. No strong fairness. `Leave`,
  `OldDelete`, `UserDelete` and the bounded `StartRun` are not fair: they
  may never happen.
- **A failed entry blocks its device.** The model keeps one outbox entry
  per device, so a device whose entry failed never runs again. The Q9
  liveness profile (`live-leave`) therefore has no failed entries.
- **Not modelled:**
  - `record_too_large` and `bucket_too_large`;
  - head verification and format or profile versions;
  - identity failures;
  - the fresh full run after a `userConnect` run is discarded for not
    being full;
  - record values (a record is its key and the run that wrote it).

How the properties read here:

| Property | Reading in the model |
| -------- | -------------------- |
| S1 | For every acknowledged head of generation `g`, while control is `active(g)`: the current stream row is a head of generation `g`, and for each line of the acknowledged head it holds a line of the same key with an equal or greater `(o, r)`. Exempt: an L11 tombstone above the acknowledged head. |
| S3 | Every run line in a head of generation `g` comes from a run that was bound to `g` while `decide(start, control)` gave `g`. Seed lines appear only at generation 1. |
| S7 | A saved checkpoint `(ns, g)` with one cursor (a run) per stream: control was `active(g)` at the save, and each stream's cursor names a run that committed that stream at `g`, or a `retry_pending` save of a stream that had no records in that run (`quiet`). |
| S11 | A seed receipt at generation 1: the stream is live and holds every key. Exempt: an L11 tombstone in the stream. |
| IncompleteOwned | L3 and M3 as bounded safety. After a device that stays finishes a run at `(ns, T)`, a stream row it saw that is still current, and is live and `complete:false`, an L11 tombstone, or no row, is one it holds `needsFull` for. Its next run is then full. |
| NeedsFullRunIsFull | A run for a connection the device holds `needsFull` for is full, unless the run itself published `complete:false`. |
| NoHeadAboveControl, HeadGenMonotone | No head has a generation above the control chain; along a stream row chain the generation never goes down (tombstones aside). |
| S2a, S4, S9, S10 | Checked as described under Reads. |
| CoveredOnly | No head is published for a stream that its run did not cover, except a Desktop seed head. A head carries a ghost bit (`oc`) set when it is written for an uncovered stream that the seed does not fill. |
| IssuedStart | Every run in an outbox used the START state the writer issued: the stored checkpoint, or no state when the writer forced the run full. |
| NoFalseDelete | Every key of a head's base is a key of the head. The base is the row just below it, when that row has the same generation and is not a tombstone. Nothing deletes a record: no tombstones and no deletion by absence. |
| LaterWriteSurvives | A base line written by a later run than the publishing one (a greater run id than the head's `at`) is still in the head. This is the plain no-lost-write check of the merge. |
| L3 | A live `complete:false` stream becomes live `complete:true`, or control moves, under the fairness above. |

## Earlier work

- **Revision 4 counterexample** (`traces/split-run.txt`). Revision 4.1
  closes it.
- **Revision 4.1 counterexample** (`traces/late-head.txt`). The
  three-outcome base rule closes it.
- **Notes on `src/`.** Edits to `src/` made with this model were
  reverted; the package is being rewritten to revision 4.1 separately.
  Notes for that rewrite:
  - In the reference device, `readBack` labelled the new version but
    held stale records, so later runs could merge onto an old base.
    Reading the base by version fixed it.
  - A delete before the first publish did not tombstone streams that had
    no rows yet.
  - The reference store needs an exclusive (compare-and-set) mode to
    exercise §2.3. A plain overwrite mode helps as a negative control.
  - The lost-reply path read the row back and compared contents. Section
    2.3 wants an exact byte-for-byte resend of the persisted request.
  - `chooseBase` in `src/head.ts` had the two-outcome rule. The rewrite
    needs the third outcome, `stale_generation`.
