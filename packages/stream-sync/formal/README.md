# Formal model of whole-file stream sync

Status: **stopped on a counterexample to design revision 4.1.** The model
follows section 4 of revision 4.1. The revision 4 counterexample
(`CE-split-run`) now passes. A new trace breaks S1 (no lost commit). The
design is not patched here. The trace is in
[traces/late-head.txt](traces/late-head.txt).

Model: `StreamSync.tla`, sha256
`27dfaa6ab448fadf81ac5d6b450f26c3b744c55d73284423b9760890c3efbd14`.
TLC 2026.11.03 (`tla2tools.jar`), 4 workers.

## The counterexample (revision 4.1)

There is one connection `A`, one stream `s1`, record keys `x1` and `x2`,
and two devices.

| Step  | What happens                                                                                                                                                                                                       | Control     |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------- |
| 2–6   | `d1` starts run 1, creates the control row and decides `s1` at generation 1. It has not read the stream row yet.                                                                                                   | `active(1)` |
| 7     | `d2` deletes the connector.                                                                                                                                                                                        | `deleted(2)` |
| 9–15  | `d2` starts run 2 (`userConnect`, full), reconnects, re-reads, decides generation 3 and commits head v1 at generation 3 with `x1` and `x2`.                                                                         | `active(3)` |
| 16–17 | `d1` continues run 1. It reads the stream row: v1 is of another generation, so its base is empty (§2.7). It commits head v2 at generation 1. Nothing in §2.3 or §2.7 stops it: the POST at N+1 only needs a free version. | `active(3)` |
| 18    | `d2` saves its checkpoint `(A, 3)`. Control is `active(3)` and nothing was published `complete:false`, so §2.4 allows it.                                                                                         | `active(3)` |
| 19–22 | `d2` starts run 3, which is incremental and collects only `x1`. It decides generation 3 and reads the stream row: v2 is of another generation, so its base is empty. It commits head v3 at generation 3 with `x1` only, `complete:false`. | `active(3)` |

Result: the latest generation-3 head (v3) does not hold `x2`. Run 2
committed `x2` at generation 3, and no greater `(o, r)` has replaced it.
That breaks S1.

- **What the user sees.** From step 17, `s1` is not live: its latest head
  has generation 1 while control is `active(3)`. From step 22, `s1` is
  live but incomplete, so reads do not serve its view (§2.10 step 1). The
  run after that is full (`needsFull`). It collects `x2` again if the
  source still has it. So the loss lasts until that full run. If the
  source no longer has `x2`, the loss is permanent.
- **Cause.** A late head of an old generation is the latest row. §2.7
  then gives every later run of the current generation an empty base.
  §4 names "late old-generation head" as a scenario that must be
  reachable, but no rule keeps the current generation's lines across it.
- **Not checked here.** Two possible fixes: (1) after reading the stream
  row, discard if its generation is greater than T; or (2) take the base
  from the latest row of generation T, not from the latest row. Neither
  is in the model.

Reproduce:

```sh
TLA2TOOLS=/path/to/tla2tools.jar node formal/check.mjs --run CE-late-head
```

Expected: `ok CE-late-head: violates S1_NoLostCommit`, depth 22, about
320,000 distinct states. Add `-dumpTrace json FILE` to the TLC command and
run `python3 formal/traces/story.py FILE` to print the table in
`traces/late-head.txt`.

## Results

Each run used 4 workers under `nice -n 19` on a shared, loaded host. The
times show that load.

| Config         | Profile | Expected         | Result           | Distinct states | Depth | Time        |
| -------------- | ------- | ---------------- | ---------------- | --------------: | ----: | ----------- |
| `CE-split-run` | split   | pass             | pass             |       1,910,866 |    28 | 20 min 19 s |
| `CE-late-head` | late    | S1 violated      | S1 violated      |         320,325 |    22 | 12 s        |

The model stopped there. These configs exist, but they were **not run**
on revision 4.1:

- the positives `Small`, `Key`, `Full`, `IdLess` and `Live`;
- the controls `C01`–`C18`;
- the scenario witnesses `W-*`.

`node formal/check.mjs --list` prints each config with its expected
result.

### Bounds

| Constant                     | split          | late           | small (not run)    |
| ---------------------------- | -------------- | -------------- | ------------------ |
| Devices (d1 is the Desktop)  | d1, d2         | d1, d2         | d1, d2             |
| Acct                         | A              | A              | A, B               |
| PK                           | x1             | x1, x2         | x1, x2             |
| Streams                      | s1, s2         | s1             | s1, s2, s3         |
| MaxRuns                      | 2              | 3              | 3                  |
| MaxDeletes                   | 1              | 1              | 1                  |
| MaxLost / MaxSessions / MaxFail | 0 / 0 / 0   | 0 / 0 / 0      | 1 / 1 / 1          |
| MaxSettleFail                | 0              | 0              | 0 (1 in C15)       |
| MaxVer (state constraint)    | 6              | 6              | 6                  |
| Readers                      | none           | none           | none (r1 in C18)   |
| Symmetry                     | Acct, PK, streams other than `s1` | same | same |

Every design guard is TRUE in all three.

The section 4 small profile has two accounts, two keys, three streams,
three runs and one each of loss, crash and failure. Its state space was
not measured on revision 4.1. `split` is much smaller, and it took
20 minutes on this host. Before `small` and `full` can finish, the model
probably needs more reduction, or more time than this lane had.

## What the model is

`StreamSync.tla` models one connector `c`. Each action maps to one
package function or host step; the module header lists the map. It
models:

- **Connections.** A namespace per account, or `""` for an
  identity-less connector. Each has a control row chain (`ctl`).
- **Streams.** One head row chain per stream (`hd`), with exclusive
  writes.
- **Storage.** Blobs stored by name (`store`).
- **Per device:** the session listing, `known`, `stopped`, `needsFull`,
  the checkpoint, one outbox entry (`ob`) and, optionally, the imported
  view.
- **Desktop.** `seedTarget` and the seed receipts.
- **Old raw file.** `rawF`, which can record an account identity.
- **Lost replies.** `inflight`, which can land late (`LateApply`).

Each guard in section 4 is a constant, and a control sets one of them to
FALSE. `configs.mjs` is the one source of the TLC configs in `cfg/`.
`check.mjs` regenerates the configs, checks them, and runs TLC.

Modelling choices the reader should check:

- **Records.** A line is `<<pk, run, account, origin>>`. Run ids follow
  run start order, so `(o, r)` order is run id order. Seed and raw-seed
  lines have run 0 and rank below run lines. A run emits a chosen subset
  of streams and collects a chosen subset of keys; a full run collects
  every key.
- **Delete.** A delete tombstones every active control row of the
  connector, as §2.11 says. It also purges the device's entry, checkpoint
  and view, and sets `stopped`.
- **Decide.** Each stream decides when it reaches publish, by the
  §2.4 table on (start snapshot, current control). A create or reconnect
  reply sends the stream back to decide (the re-read). `NeverInconsistent`
  checks that the `registry_inconsistent` row never applies.
- **Base.** The base is the latest head row if it has the target
  generation, else empty (§2.7). A no-op stream counts as committed. A
  stream planned only for the seed that gets no seed (generation > 1) is
  a no-op, and its receipt records "skipped".
- **Reads.**
  - Checked on every reachable registry state. Rows are append-only in
    the design, so a reader's snapshot is always some past state, and
    the current-state check covers it.
  - Checked against every legacy file: none, or any account's, older
    than every head or newer than every head. This stands for old
    installs that write at any time, also after a delete or after
    cutover, so those two section 4 scenarios hold by construction.
  - Only `C18` uses a lagging reader PS. It shows that deletion is
    eventual, not immediate.
- **Imports.** `Import` is one sync-loop pass per device. Only S12 and
  L2 read the view, so the other profiles turn it off (`Views = FALSE`).
- **Settlement failure.** It changes what a writer does only when
  `AckImmutable` is FALSE (C15). The other profiles leave it out.
- **Cleanup.** It removes the objects of all heads of a deleted
  generation, all streams at once.
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
| S1 | Every `(ns, s, g, run, keys)` commit, while generation `g` is current: each key has a line of that run or a greater one in the latest head of generation `g`. |
| S3 | Every run line in a head of generation `g` comes from a run that was bound to `g` while `decide(start, control)` gave `g`. Seed and raw lines appear only at generation 1. |
| S7 | A saved checkpoint `(ns, g, run)`: control was `active(g)` at the save, and every stream of the run committed at `g`. |
| S2a, S4, S9, S10 | Checked as described under Reads. |

## Earlier work

- **Revision 4 counterexample** ([traces/split-run.txt](traces/split-run.txt)).
  A `userConnect` run commits one stream at generation 1. A delete lands.
  The run's next stream reconnects and commits at generation 3. The
  checkpoint then has no single generation. Revision 4.1 closes it:
  `CE-split-run` passes.
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
  - The base branch's `package-lock.json` was out of sync with the
    workspace, so `npm ci` failed.

## What is not proven

- No positive profile larger than `split` has finished on revision 4.1.
- None of the 18 negative controls has run on revision 4.1. A guard that
  no control can break is not shown to be needed.
- Reachability of the section 4 scenarios has not been checked on
  revision 4.1.
- Liveness (L1–L4) has not been checked.
- The model is not replayed against package code.
