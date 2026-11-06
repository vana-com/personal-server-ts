# Formal model of whole-file stream sync

Status: design revision 4.1 with two rulings and two review fixes:

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

No counterexample to this design was found within the bounds below. Read
"Results" for what was checked at which bounds and in which mode.

Model: `StreamSync.tla`, sha256 `033a987a0f025fe880b75161ea6742d939a7e6ef123902bbf5efd23569c7864c`. TLC 2026.11.03
(`tla2tools.jar`).

## Results

Every run used 4 workers under `nice -n 19` on a shared, loaded host, so
the times show that load. "Exhaustive" means breadth-first search
finished: every reachable state within the bounds was checked. A control
or witness passes when TLC stops at the expected violation.

Results for this model are being recorded. The next commit adds the table.

Positive configs check every safety invariant: TypeOK, S1 to S12,
NeverInconsistent, NoHeadAboveControl, HeadGenMonotone and
IncompleteOwned. Liveness configs check TypeOK and L1 to L4. A control or
witness checks TypeOK and its one expected property, so TLC's first
violation is that one.

`node formal/check.mjs --list` prints every config with its slice and
expected result.

### Bounds

All guards are TRUE except the one a control turns off. Devices are `d1`
(the Desktop) and `d2` in every profile. `MaxVer` is 6 (a state
constraint on chain length) in every safety profile. Symmetry: accounts,
record keys and streams other than `s1`. Liveness profiles have no
symmetry and no state constraint.

| Profile | Acct | PK | Streams | Runs (+ reruns) | Deletes | Lost / restarts / failed entries | Other |
| ------- | ---- | -- | ------- | --------------- | ------- | -------------------------------- | ----- |
| `late` | A | x1, x2 | s1 | 3 | 1 | 0 / 0 / 0 | |
| `split` | A | x1 | s1, s2 | 2 | 1 | 0 / 0 / 0 | |
| `slice-faults` | A | x1 | s1 | 3 | 1 | 1 / 1 / 1 | |
| `slice-accounts` | A, B | x1 | s1 | 3 | 1 | 0 / 0 / 0 | |
| `slice-key` | A | x1 | s1 | 3 | 1 | 0 / 0 / 0 | `d2` holds another owner key; imports on |
| `slice-idless` | A, B | x1 | s1 | 3 | 1 | 0 / 0 / 0 | identity-less connector |
| `twice` | A | x1 | s1 | 4 | 2 | 0 / 0 / 0 | |
| `slice-q9` | A | x1 | s1 | 4 | 0 | 0 / 0 / 0 | 1 old stream DELETE (L11), 1 leave |
| `slice-settle` | A | x1, x2 | s1 | 3 | 1 | 0 / 0 / 0 | 1 settlement failure |
| `slice-lag` | A | x1, x2 | s1 | 3 | 1 | 0 / 0 / 0 | reader PS `r1` |
| `lean` | A | x1 | s1, s2 | 3 | 1 | 1 / 1 / 1 | witnesses only |
| `live` | A | x1 | s1, s2 | 2 (+2) | 1 | 1 / 0 / 1 | imports on, reader `r1` |
| `live-leave` | A | x1 | s1 | 3 (+2) | 0 | 0 / 0 / 0 | 1 old stream DELETE, 1 leave |
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
  simulation with a fixed seed and depth (`SIM` in `configs.mjs`). A
  simulation that finds no violation is evidence, not proof. Most random
  behaviours end early: in a probe run, the mean length was 8 steps.

## What is proven, simulated only, and unproven

Pending the results above.

## Counterexamples kept as controls

- [traces/late-head.txt](traces/late-head.txt): the two-outcome base rule
  (revision 4.1 before F1). A run of generation 1 resumes after a delete
  and a reconnect elsewhere, and commits a generation-1 head over an
  acknowledged generation-3 head. With S1 against the current row, S1
  alone catches it (`C-late-head-old-rule`).
- [traces/no-q9.txt](traces/no-q9.txt): Q9 removed. An old app's DELETE
  tombstones the stream, `d2` publishes `complete:false`, and `d1`'s run
  is a no-op onto it. `d1` saves its checkpoint and holds no `needsFull`
  (`C19-no-q9`).
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
- **No-op (§2.6).** Every part and `complete` unchanged, or an empty
  spool with no seed: no upload and no POST, and the stream counts as
  committed. Under Q9 a no-op onto a `complete:false` base of generation
  T sets `needsFull`, blocks the checkpoint and clears it.
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
| IncompleteOwned | L3 as bounded safety. After a device that stays finishes a run at `(ns, T)`, a stream row it saw that is still current, live and `complete:false` is one it holds `needsFull` for. Its next run is then full. |
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
  - `chooseBase` in `src/head.ts` has the two-outcome rule. It needs the
    third outcome, `stale_generation`.
