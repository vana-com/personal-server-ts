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

The intake model found two defects. Read "Counterexamples".

- **Safety (S7).** In section 9 as written, a `retry_pending` end can
  save the cursor of a stream whose records it drops. The fix keeps a
  `retry_pending` cursor only for a stream with no records in the run.
  It is adopted, and it is the model's default (`RetryQuietOnly`).
- **Liveness (L3).** With that fix, a job token that a `retry_pending`
  end saved makes the device's next run incremental, before any head of
  the generation exists. That run publishes `complete:false`. If an old
  app's DELETE then tombstones the stream, no run is required to follow,
  and L3 fails on `Live-leave`. The proposed fix, `RetryCkptStaysFull`,
  is not in the ruled contract, so it is off by default. The `Fix-*`
  rows check it.

No other counterexample was found within the bounds below. Read
"Results" for what was checked at which bounds and in which mode.

Model: `StreamSync.tla`, sha256 `a14998644a6207f78d759175a196c12335c8e487fd6ee2c640f14d8faea2cf22`. TLC 2026.11.03
(`tla2tools.jar`).

## Results

Every run used 4 workers under `nice -n 19` on a shared, loaded host, so
the times show that load. "Exhaustive" means breadth-first search
finished: every reachable state within the bounds was checked. A control
or witness passes when TLC stops at the expected violation. A row whose
Observed column differs from its Expected column is a finding; the text
after the table explains it.

| Config | Slice | Expected | Observed | Distinct states | Depth | Mode | Seconds | Model |
| ------ | ----- | -------- | -------- | --------------: | ----: | ---- | ------: | ----- |
| `Small` | small | pass | no violation, stopped by hand | 9,562,741 checked, 24,639 behaviours | | simulation | 932 | `f2c42e6d2504` |
| `Key` | key | pass | no violation, stopped at 900 s | 8,945,417 checked, 23,066 behaviours | | simulation | 900 | `f2c42e6d2504` |
| `Full` | full | pass | no violation, stopped at 900 s | 8,188,425 checked, 21,095 behaviours | | simulation | 901 | `f2c42e6d2504` |
| `IdLess` | idless | pass | no violation, stopped at 900 s | 9,780,709 checked, 25,119 behaviours | | simulation | 900 | `f2c42e6d2504` |
| `Slice-faults` | slice-faults (cut, lost replies only) | pass | pass | 9,222,368 | 31 | exhaustive | 962 | `23acd6410d61` |
| `Slice-faults2` | slice-faults (cut, no lost replies) | pass | pass | 15,874,769 | 30 | exhaustive | 1390 | `a14998644a62` |
| `Slice-accounts` | slice-accounts (cut) | pass | pass | 23,627,834 | 30 | exhaustive | 3085 | `23acd6410d61` |
| `Slice-key` | slice-key | pass | pass | 3,501,147 | 28 | exhaustive | 226 | `f2c42e6d2504` |
| `Slice-idless` | slice-idless | pass | pass | 10,549,465 | 28 | exhaustive | 899 | `b48bf8a62957` |
| `Slice-twice` | twice (cut, 3 runs) | pass | pass | 3,818,141 | 30 | exhaustive | 273 | `a14998644a62` |
| `Slice-q9` | slice-q9 | pass | pass | 22,987,926 | 37 | exhaustive | 1841 | `b48bf8a62957` |
| `Slice-intake` | slice-intake | pass | pass | 12,345,919 | 29 | exhaustive | 1269 | `f2c42e6d2504` |
| `Slice-intake1` | slice-intake1 | pass | pass | 9,668,164 | 41 | exhaustive | 966 | `f2c42e6d2504` |
| `Live` | live (cut) | pass | pass | 665,867 | 24 | exhaustive | 1299 | `23acd6410d61` |
| `Live-fail` | live-fail (cut, no reader PS) | pass | pass | 366,930 | 23 | exhaustive | 522 | `f2c42e6d2504` |
| `Live-leave` | live-leave (every run covers s1) | pass | L3_NoStuckIncomplete | 358,958 | 17 | breadth-first, stopped | 325 | `23acd6410d61` |
| `Live-cover` | live-cover | pass | pass | 42,776 | 29 | exhaustive | 36 | `f2c42e6d2504` |
| `Fix-live-leave` | live-leave | pass | pass | 2,435,418 | 47 | exhaustive | 3215 | `f2c42e6d2504` |
| `Fix-idless` | slice-idless | pass | pass | 10,470,273 | 28 | exhaustive | 743 | `a14998644a62` |
| `Fix-split` | split | pass | pass | 12,176,674 | 29 | exhaustive | 1344 | `a14998644a62` |
| `CE-split-run` | split | pass | pass | 12,176,674 | 29 | exhaustive | 1012 | `b48bf8a62957` |
| `CE-late-head` | late (cut) | pass | pass | 6,998,289 | 30 | exhaustive | 728 | `23acd6410d61` |
| `C-late-head-old-rule` | late | S1_NoLostCommit | S1_NoLostCommit | 2,662,050 | 17 | breadth-first, stopped | 60 | `b48bf8a62957` |
| `C01-no-gen-in-names` | late | S5_CleanupSafety | S5_CleanupSafety | 3,723,528 | 18 | breadth-first, stopped | 83 | `b48bf8a62957` |
| `C02-key` | slice-key | pass | pass | 4,505,291 | 28 | exhaustive | 341 | `f2c42e6d2504` |
| `C02-split` | split | pass | pass | 16,238,496 | 29 | exhaustive | 2005 | `f2c42e6d2504` |
| `C02-idless` | slice-idless | pass | pass | 13,483,670 | 29 | exhaustive | 939 | `f2c42e6d2504` |
| `C03-non-exclusive` | late | S1_NoLostCommit | S1_NoLostCommit | 678,999 | 15 | breadth-first, stopped | 13 | `b48bf8a62957` |
| `C04-reader-unions` | slice-accounts | S4_NoAccountMix | S4_NoAccountMix | 5,921,144 | 16 | breadth-first, stopped | 165 | `b48bf8a62957` |
| `C05-seed-any-gen` | late | S3_CleanGeneration | S3_CleanGeneration | 609,722 | 15 | breadth-first, stopped | 12 | `b48bf8a62957` |
| `C06-early-checkpoint` | split | S7_CheckpointSafety | S7_CheckpointSafety | 101,173 | 9 | breadth-first, stopped | 3 | `b48bf8a62957` |
| `C07-no-reread-after-create` | late | S3_CleanGeneration | S3_CleanGeneration | 21,902 | 9 | breadth-first, stopped | 1 | `b48bf8a62957` |
| `C08-rebind-old-spool` | late | S3_CleanGeneration | S3_CleanGeneration | 54,520 | 11 | breadth-first, stopped | 2 | `b48bf8a62957` |
| `C09-no-listing-needed` | slice-faults | S3_CleanGeneration | S3_CleanGeneration | 36,746 | 8 | breadth-first, stopped | 2 | `b48bf8a62957` |
| `C10-legacy-ignores-delete` | late | S2a_DeleteHolds | S2a_DeleteHolds | 13,414 | 9 | breadth-first, stopped | 1 | `b48bf8a62957` |
| `C11-collectedat-competition` | late | S9_OneWay | S9_OneWay | 32,538 | 10 | breadth-first, stopped | 2 | `b48bf8a62957` |
| `C12-no-needsfull` | slice-q9 | IncompleteOwned | IncompleteOwned | 370,739 | 15 | breadth-first, stopped | 6 | `b48bf8a62957` |
| `C13-pending-blocks-import` | live-fail | L2_Convergence | L2_Convergence | 1,010,722 | 17 | breadth-first, stopped | 199 | `b48bf8a62957` |
| `C14-seed-only-empty-base` | late | S11_SeedCoverage | S11_SeedCoverage | 387,003 | 15 | breadth-first, stopped | 9 | `b48bf8a62957` |
| `C15-failed-row-replaceable` | slice-settle | S8_AckImmutable | S8_AckImmutable | 1,274,854 | 16 | breadth-first, stopped | 24 | `b48bf8a62957` |
| `C16-readiness-live-only` | slice-q9 | S10_ReadinessMatchesRead | S10_ReadinessMatchesRead | 239,798 | 15 | breadth-first, stopped | 8 | `b48bf8a62957` |
| `C19-no-q9` | slice-q9 | IncompleteOwned | IncompleteOwned | 5,855,555 | 21 | breadth-first, stopped | 101 | `b48bf8a62957` |
| `C12L-fix` | live-leave | pass | stopped at 3600 s | 2,321,769 |  | breadth-first, timed out | 3601 | `a14998644a62` |
| `C19L-no-q9` | live-leave | L3_NoStuckIncomplete | L3_NoStuckIncomplete | 591,731 | 17 | breadth-first, stopped | 589 | `b48bf8a62957` |
| `C20-null-base-noop` | slice-q9 | IncompleteOwned | IncompleteOwned | 37,407 | 10 | breadth-first, stopped | 1 | `b48bf8a62957` |
| `C21-needsfull-not-full` | slice-accounts4 | NeedsFullRunIsFull | NeedsFullRunIsFull | 35,830 | 22 | breadth-first, stopped | 2 | `b48bf8a62957` |
| `C18-immediate-delete` | slice-lag | S2_Immediate | S2_Immediate | 13,117 | 9 | breadth-first, stopped | 1 | `b48bf8a62957` |
| `C-publish-uncovered` | late | CoveredOnly | CoveredOnly | 50,684 | 10 | breadth-first, stopped | 3 | `b48bf8a62957` |
| `C-producer-state` | late | IssuedStart | IssuedStart | 63,959 | 12 | breadth-first, stopped | 2 | `b48bf8a62957` |
| `C-retry-saves-spooled` | late | S7_CheckpointSafety | S7_CheckpointSafety | 41,356 | 10 | breadth-first, stopped | 2 | `b48bf8a62957` |
| `C-full-replaces` | late | NoFalseDelete | NoFalseDelete | 623,640 | 15 | breadth-first, stopped | 13 | `b48bf8a62957` |
| `W-trace-a` | lean | NotTraceA | NotTraceA | 525,071 | 9 | breadth-first, stopped | 7 | `b48bf8a62957` |
| `W-trace-b` | lean | NotTraceB | NotTraceB | 64,867,358 | 15 | breadth-first, stopped | 1008 | `b48bf8a62957` |
| `W-offline-vs-5` | twice | NotOfflineVs5 | NotOfflineVs5 | 8,649,332 | 20 | breadth-first, stopped | 148 | `b48bf8a62957` |
| `W-late-old-head` | lean | NotLateOldHead | NotLateOldHead | 3,352,083 | 11 | breadth-first, stopped | 34 | `b48bf8a62957` |
| `W-twice` | twice | NotTwice | NotTwice | 2,743,602 | 17 | breadth-first, stopped | 41 | `b48bf8a62957` |
| `W-first-write-in-delete` | lean | NotFirstWriteDuringDelete | NotFirstWriteDuringDelete | 3,379,581 | 11 | breadth-first, stopped | 40 | `b48bf8a62957` |
| `W-phone-first-seed` | late | NotPhoneFirstThenSeed | NotPhoneFirstThenSeed | 679,159 | 16 | breadth-first, stopped | 14 | `b48bf8a62957` |
| `W-zero-emission-seed` | slice-accounts | NotZeroEmissionSeed | NotZeroEmissionSeed | 75,590 | 9 | breadth-first, stopped | 3 | `b48bf8a62957` |
| `W-settle-after-ack` | slice-settle | NotSettleAfterAck | NotSettleAfterAck | 54,122 | 11 | breadth-first, stopped | 3 | `b48bf8a62957` |
| `W-switch-reused-ckpt` | slice-accounts | NotSwitchReusedCkpt | NotSwitchReusedCkpt | 130,758 | 10 | breadth-first, stopped | 4 | `b48bf8a62957` |
| `W-needsfull-with-ckpt` | slice-accounts4 | NotNeedsFullWithCkpt | NotNeedsFullWithCkpt | 25,331 | 21 | breadth-first, stopped | 1 | `b48bf8a62957` |
| `W-failed-entry` | lean | NotFailedEntryNewerHeads | NotFailedEntryNewerHeads | 3,344,717 | 11 | breadth-first, stopped | 38 | `b48bf8a62957` |

The Model column is the first 12 hex digits of the sha256 of
`StreamSync.tla` for that run. Four versions ran:

- `b48bf8a62957`: the intake model.
- `23acd6410d61`: adds the bound `PartialCover`. It is TRUE, so it
  changes nothing, except in the rows marked "cut".
- `f2c42e6d2504`: adds the proposed guard `RetryCkptStaysFull` and the
  checkpoint field `byRun`. Both are inert while the guard is FALSE,
  which is the default.
- `a14998644a62`, the final model: differs from `f2c42e6d2504` only in
  three comments.

`Slice-key` reached the same 3,501,147 distinct states and 18,500,789
states generated on the first three versions, and the fourth changes
only comments. So every row holds for the final model with its
defaults.

Findings and open rows:

- `Live-leave` fails L3 with the ruled contract. Read
  `traces/retry-token-incremental.txt`. `Fix-live-leave` passes with the
  proposed fix on.
- The four simulations found no violation. `Small` was stopped by hand
  at 932 seconds; the others stopped at their 900-second cap. The table
  gives states checked and random behaviours at the last progress
  report.
- `C12L-fix` timed out at 3600 seconds with no violation. Read "C02 and
  C12".
- `Fix-split` reached the same state count as `CE-split-run`: on
  `split` the fix changes no reachable state.
- These bounds timed out at 3600 seconds with no violation, and were
  then cut to the bounds in the table: `slice-intake` with three runs
  (33.7 million distinct states, depth 17) and with no delete
  (30,378,089, depth 18); `twice` with four runs and the cut
  (40,787,341, depth 28); `live-fail` with the reader PS and the cut
  (1,512,262, depth 23).

Positive configs check every safety invariant: TypeOK, S1 to S12,
NeverInconsistent, NoHeadAboveControl, HeadGenMonotone, IncompleteOwned,
NeedsFullRunIsFull, CoveredOnly, IssuedStart, NoFalseDelete and
LaterWriteSurvives. Liveness configs check TypeOK and L1 to L4, except
L2 on a profile without imports (`live-leave`, `live-cover`). A control
or witness checks TypeOK and its one expected property, so TLC's first
violation is that one.

`node formal/check.mjs --list` prints every config with its slice and
expected result.

### C02 and C12

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
