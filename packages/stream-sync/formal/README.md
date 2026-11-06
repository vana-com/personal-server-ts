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

No counterexample to this design was found within the bounds below. Read
"Results" for what was checked at which bounds and in which mode.

Model: `StreamSync.tla`, sha256 `cb85b4f8c217ded154968be8e4b72b4596dd3fb5a11f614f18b3d0da57ed18b5`. TLC 2026.11.03
(`tla2tools.jar`).

## Results

Every run used 4 workers under `nice -n 19` on a shared, loaded host, so
the times show that load. "Exhaustive" means breadth-first search
finished: every reachable state within the bounds was checked. A control
or witness passes when TLC stops at the expected violation.

| Config | Slice | Expected | Observed | Distinct states | Depth | Mode | Seconds | Model |
| ------ | ----- | -------- | -------- | --------------: | ----: | ---- | ------: | ----- |
| `Small` | small | pass | pass | 20,501,352 generated |  | simulation | 1413 | `cb85b4f8c217` |
| `Key` | key | pass | pass | 20,667,229 generated |  | simulation | 1659 | `cb85b4f8c217` |
| `Full` | full | pass | pass | 21,221,242 generated |  | simulation | 1516 | `cb85b4f8c217` |
| `IdLess` | idless | pass | pass | 20,274,382 generated |  | simulation | 1002 | `cb85b4f8c217` |
| `Slice-faults` | slice-faults | pass | pass | 33,991,646 | 33 | exhaustive | 2472 | `1e95f2aee0b6` |
| `Slice-accounts` | slice-accounts | pass | pass | 12,556,684 | 30 | exhaustive | 1635 | `1e95f2aee0b6` |
| `Slice-key` | slice-key | pass | pass | 457,688 | 28 | exhaustive | 28 | `1e95f2aee0b6` |
| `Slice-idless` | slice-idless | pass | pass | 2,860,536 | 28 | exhaustive | 173 | `1e95f2aee0b6` |
| `Slice-twice` | twice | pass | pass | 15,112,596 | 37 | exhaustive | 927 | `1e95f2aee0b6` |
| `Slice-q9` | slice-q9 | pass | pass | 2,400,482 | 37 | exhaustive | 197 | `1e95f2aee0b6` |
| `Live` | live | pass | pass | 374,776 | 24 | exhaustive | 811 | `cb85b4f8c217` |
| `Live-fail` | live-fail | pass | pass | 860,976 | 24 | exhaustive | 1945 | `cb85b4f8c217` |
| `Live-leave` | live-leave | pass | pass | 1,019,113 | 47 | exhaustive | 1001 | `cb85b4f8c217` |
| `CE-split-run` | split | pass | pass | 758,372 | 29 | exhaustive | 85 | `1e95f2aee0b6` |
| `CE-late-head` | late | pass | pass | 8,642,702 | 31 | exhaustive | 903 | `1e95f2aee0b6` |
| `C-late-head-old-rule` | late | S1_NoLostCommit | S1_NoLostCommit | 878,725 | 17 | breadth-first, stopped | 34 | `1e95f2aee0b6` |
| `C01-no-gen-in-names` | late | S5_CleanupSafety | S5_CleanupSafety | 1,348,398 | 18 | breadth-first, stopped | 54 | `1e95f2aee0b6` |
| `C02-no-clear-on-gen-change` | slice-faults | S3_CleanGeneration | pass | 44,121,686 | 33 | exhaustive | 1304 | `1e95f2aee0b6` |
| `C03-non-exclusive` | late | S1_NoLostCommit | S1_NoLostCommit | 193,149 | 14 | breadth-first, stopped | 10 | `1e95f2aee0b6` |
| `C04-reader-unions` | slice-accounts | S4_NoAccountMix | S4_NoAccountMix | 804,627 | 15 | breadth-first, stopped | 42 | `1e95f2aee0b6` |
| `C05-seed-any-gen` | late | S3_CleanGeneration | S3_CleanGeneration | 189,552 | 14 | breadth-first, stopped | 8 | `1e95f2aee0b6` |
| `C06-early-checkpoint` | split | S7_CheckpointSafety | S7_CheckpointSafety | 2,575 | 9 | breadth-first, stopped | 1 | `1e95f2aee0b6` |
| `C07-no-reread-after-create` | late | S3_CleanGeneration | S3_CleanGeneration | 4,222 | 8 | breadth-first, stopped | 2 | `1e95f2aee0b6` |
| `C08-rebind-old-spool` | late | S3_CleanGeneration | S3_CleanGeneration | 13,235 | 9 | breadth-first, stopped | 3 | `1e95f2aee0b6` |
| `C09-no-listing-needed` | slice-faults | S3_CleanGeneration | S3_CleanGeneration | 5,495 | 7 | breadth-first, stopped | 2 | `1e95f2aee0b6` |
| `C10-legacy-ignores-delete` | late | S2a_DeleteHolds | S2a_DeleteHolds | 2,587 | 8 | breadth-first, stopped | 2 | `1e95f2aee0b6` |
| `C11-collectedat-competition` | late | S9_OneWay | S9_OneWay | 7,129 | 9 | breadth-first, stopped | 2 | `1e95f2aee0b6` |
| `C12-no-needsfull` | slice-q9 | IncompleteOwned | not re-run with this config; last run on `live-leave` checked L3: pass | 1,040,621 | 47 | exhaustive | 720 | `cb85b4f8c217` |
| `C13-pending-blocks-import` | live-fail | L2_Convergence | L2_Convergence | 524,920 | 19 | breadth-first, stopped | 64 | `cb85b4f8c217` |
| `C14-seed-only-empty-base` | late | S11_SeedCoverage | S11_SeedCoverage | 104,796 | 14 | breadth-first, stopped | 5 | `1e95f2aee0b6` |
| `C15-failed-row-replaceable` | slice-settle | S8_AckImmutable | S8_AckImmutable | 392,604 | 15 | breadth-first, stopped | 17 | `1e95f2aee0b6` |
| `C16-readiness-live-only` | slice-q9 | S10_ReadinessMatchesRead | S10_ReadinessMatchesRead | 44,700 | 16 | breadth-first, stopped | 5 | `1e95f2aee0b6` |
| `C17-raw-seed-ignores-id` | slice-accounts | S4_NoAccountMix | S4_NoAccountMix | 1,130,223 | 15 | breadth-first, stopped | 54 | `1e95f2aee0b6` |
| `C19-no-q9` | slice-q9 | IncompleteOwned | IncompleteOwned | 1,137,988 | 24 | breadth-first, stopped | 34 | `1e95f2aee0b6` |
| `C19L-no-q9` | live-leave | L3_NoStuckIncomplete | L3_NoStuckIncomplete | 801,745 | 32 | breadth-first, stopped | 481 | `cb85b4f8c217` |
| `C20-null-base-noop` | slice-q9 | IncompleteOwned | IncompleteOwned | 46,475 | 15 | breadth-first, stopped | 4 | `1e95f2aee0b6` |
| `C21-needsfull-not-full` | slice-accounts4 | NeedsFullRunIsFull | NeedsFullRunIsFull | 7,694 | 22 | breadth-first, stopped | 2 | `1e95f2aee0b6` |
| `C18-immediate-delete` | slice-lag | S2_Immediate | S2_Immediate | 2,705 | 7 | breadth-first, stopped | 2 | `1e95f2aee0b6` |
| `W-trace-a` | lean | NotTraceA | NotTraceA | 7,127 | 8 | breadth-first, stopped | 2 | `1e95f2aee0b6` |
| `W-trace-b` | lean | NotTraceB | NotTraceB | 1,069,431 | 13 | breadth-first, stopped | 23 | `1e95f2aee0b6` |
| `W-offline-vs-5` | twice | NotOfflineVs5 | NotOfflineVs5 | 489,473 | 18 | breadth-first, stopped | 11 | `1e95f2aee0b6` |
| `W-late-old-head` | lean | NotLateOldHead | NotLateOldHead | 52,080 | 10 | breadth-first, stopped | 3 | `1e95f2aee0b6` |
| `W-twice` | twice | NotTwice | NotTwice | 178,354 | 16 | breadth-first, stopped | 5 | `1e95f2aee0b6` |
| `W-first-write-in-delete` | lean | NotFirstWriteDuringDelete | NotFirstWriteDuringDelete | 57,511 | 10 | breadth-first, stopped | 3 | `1e95f2aee0b6` |
| `W-phone-first-seed` | late | NotPhoneFirstThenSeed | NotPhoneFirstThenSeed | 194,875 | 15 | breadth-first, stopped | 7 | `1e95f2aee0b6` |
| `W-zero-emission-seed` | slice-accounts | NotZeroEmissionSeed | NotZeroEmissionSeed | 1,938,868 | 17 | breadth-first, stopped | 43 | `1e95f2aee0b6` |
| `W-settle-after-ack` | slice-settle | NotSettleAfterAck | NotSettleAfterAck | 14,332 | 11 | breadth-first, stopped | 2 | `1e95f2aee0b6` |
| `W-switch-reused-ckpt` | slice-accounts | NotSwitchReusedCkpt | NotSwitchReusedCkpt | 34,483 | 10 | breadth-first, stopped | 2 | `1e95f2aee0b6` |
| `W-needsfull-with-ckpt` | slice-accounts4 | NotNeedsFullWithCkpt | NotNeedsFullWithCkpt | 6,899 | 22 | breadth-first, stopped | 1 | `1e95f2aee0b6` |
| `W-failed-entry` | lean | NotFailedEntryNewerHeads | NotFailedEntryNewerHeads | 91,265 | 10 | breadth-first, stopped | 2 | `1e95f2aee0b6` |

The Model column is the first 12 hex digits of the sha256 of
`StreamSync.tla` for that run. `1e95f2aee0b6` differs from the final
model `cb85b4f8c217` only in `L4_Resume` and its comment: L4 moved
"the device has not left" from the quantifier bound into the formula,
because TLC cannot bound a quantifier by a state variable there. No
safety config checks L4, so the `1e95f2aee0b6` safety rows hold for the
final model.

`C02-no-clear-on-gen-change` with `ClearOnGenChange = FALSE` passes S3
on `slice-faults`. A run of the same config against every safety
invariant was stopped by hand at a deadline, not finished: no violation in
42,337,267 distinct states to depth 28, with 1,822,042 states still
queued, after 2971 seconds on `cb85b4f8c217`.

`C12-no-needsfull` moved from `live-leave` (L3) to `slice-q9`
(IncompleteOwned) after its last run. It was not re-run with the new
config.

Positive configs check every safety invariant: TypeOK, S1 to S12,
NeverInconsistent, NoHeadAboveControl, HeadGenMonotone, IncompleteOwned
and NeedsFullRunIsFull. Liveness configs check TypeOK and L1 to L4, except L2 on a profile
without imports (`live-leave`). A control or
witness checks TypeOK and its one expected property, so TLC's first
violation is that one.

`node formal/check.mjs --list` prints every config with its slice and
expected result.

### Bounds

All guards are TRUE except the one a control turns off. Devices are `d1`
(the Desktop) and `d2` in every profile except `slice-accounts4`. `MaxVer` is 6 (a state
constraint on chain length) in every safety profile. Symmetry: accounts,
record keys and streams other than `s1`. Liveness profiles have no
symmetry and no state constraint.

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
| `slice-settle` | A | x1, x2 | s1 | 3 | 1 | 0 / 0 / 0 | 1 settlement failure |
| `slice-lag` | A | x1, x2 | s1 | 3 | 1 | 0 / 0 / 0 | reader PS `r1` |
| `lean` | A | x1 | s1, s2 | 3 | 1 | 1 / 1 / 1 | witnesses only |
| `live` | A | x1 | s1 | 2 (+2) | 1 | 0 / 0 / 0 | imports on, reader `r1` |
| `live-fail` | A | x1 | s1 | 2 (+2) | 1 | 0 / 0 / 1 | imports on, reader `r1` |
| `live-leave` | A | x1 | s1 | 3 (+3) | 0 | 0 / 0 / 0 | 1 old stream DELETE, 1 leave; no imports, so no L2 |
| `small` (§4) | A, B | x1, x2 | s1, s2, s3 | 3 | 1 | 1 / 1 / 1 | simulation only |
| `key`, `full`, `idless` (§4) | as `small` | | | | `full`: 2 | `full`: 2 / 2 / 1 | simulation only |

### Scale

The section 4 profiles do not finish on this host. Breadth-first search
on `small` reached depth 11 with 37 million distinct states after
30 minutes, with 25 million more queued. So this model checks those
profiles in two ways:

- **Exhaustive slices.** Each slice keeps one dimension of `small` at
  full size and cuts the others: two accounts, faults, a second owner
  key, an identity-less connector, two deletes, two streams (`split`),
  two record keys (`late`), and the Q9 events.
- **Simulation.** `Small`, `Key`, `Full` and `IdLess` run TLC's random
  simulation with seed 1 and depth 60 (`SIM` in `configs.mjs`).
  `num=200000` is per worker, so each profile ran 800,000 random
  behaviours. A simulation that finds no violation is evidence, not
  proof. Most random behaviours end early: the mean length was 8 to 11
  steps (standard deviation 7 to 9). The table gives states generated,
  not distinct states, for these rows.

## What is proven, simulated only, and unproven

**Proven within the bounds of each row** (breadth-first search finished):

- Every safety invariant holds on the exhaustive slices (`slice-faults`,
  `slice-accounts`, `slice-key`, `slice-idless`, `twice`, `slice-q9`)
  and on the two counterexample profiles (`late`, `split`).
- L1 to L4 hold on `live` and `live-fail`; L1, L3 and L4 hold on
  `live-leave`, under the fairness below. So L3 holds as liveness, not
  only in its bounded safety form (`IncompleteOwned`), on these
  profiles.
- Q9 is needed. Without it L3 fails on `live-leave` (`C19L-no-q9`) and
  `IncompleteOwned` fails on `slice-q9` (`C19-no-q9`).
- M3 is needed. Without it `IncompleteOwned` fails (`C20-null-base-noop`).
- The `runMustBeFull` rule decides runs. A device can hold a checkpoint
  and a `needsFull` at once (`W-needsfull-with-ckpt`). Without the rule
  `NeedsFullRunIsFull` fails (`C21-needsfull-not-full`).
- Every other control except `C02` and `C12` stops at its expected
  property, and every witness is reached.

**Simulated only:** the section 4 profiles `small`, `key`, `full` and
`idless`. Each ran 800,000 random behaviours with no violation.

**Unproven:**

- The section 4 profiles, exhaustively.
- Liveness with two streams, lost replies, restarts, or a failed entry
  together with a leave. Profiles with these did not finish on this
  host.
- That `ClearOnGenChange` is needed. `C02` passes S3 on `slice-faults`
  (see Results).
- That `needsFull` is needed for liveness. The last `C12` run, with
  `needsFull` off, passed L3 on `live-leave`. `C12` was not re-run with
  its `slice-q9` safety config.
- That the package matches the model. This directory checks the model
  only.
- Everything under "Not modelled" below.

## Counterexamples kept as controls

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
- **Old raw file.** `rawF`, which can record an account identity.
- **Lost replies.** `inflight`, which can land late (`LateApply`).

Each guard in section 4, and each ruling that adds a rule, is a
constant. A control sets one of them to FALSE. `configs.mjs` is the one
source of the TLC configs in `cfg/`. `check.mjs` regenerates the
configs, checks that `cfg/` matches, and runs TLC (`--run`).

Modelling choices the reader should check:

- **Records.** A line is `<<pk, run, account, origin>>`. Run ids follow
  run start order, so `(o, r)` order is run id order. Seed and raw-seed
  lines have run 0 and rank below run lines.
- **Runs.** Every run plans every stream of `c`. The source emits records
  for a chosen subset of streams and a chosen non-empty subset of keys.
  A stream outside that subset has an empty spool. A full run emits
  records for every stream, with any non-empty subset of keys. A key the
  run does not emit is a record the source no longer has.
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
| S3 | Every run line in a head of generation `g` comes from a run that was bound to `g` while `decide(start, control)` gave `g`. Seed and raw lines appear only at generation 1. |
| S7 | A saved checkpoint `(ns, g, run)`: control was `active(g)` at the save, and every stream of the run committed at `g`. |
| S11 | A seed receipt at generation 1: the stream is live and holds every key. Exempt: an L11 tombstone in the stream. |
| IncompleteOwned | L3 and M3 as bounded safety. After a device that stays finishes a run at `(ns, T)`, a stream row it saw that is still current, and is live and `complete:false`, an L11 tombstone, or no row, is one it holds `needsFull` for. Its next run is then full. |
| NeedsFullRunIsFull | A run for a connection the device holds `needsFull` for is full, unless the run itself published `complete:false`. |
| NoHeadAboveControl, HeadGenMonotone | No head has a generation above the control chain; along a stream row chain the generation never goes down (tombstones aside). |
| S2a, S4, S9, S10 | Checked as described under Reads. |
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
