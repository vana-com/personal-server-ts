# Stream publish: read a frozen view, copy nothing

Status: prototype measured; build pending (Phase 2). Scope: one stream's publish,
`packages/core/src/localdb/{publish,encode,part-layout}.ts` and the
better-sqlite3 driver. Baseline: PS #690 (pipelined copy and upload), merged as
46cd4c55.

## Problem

A publish copies every changed prefix of `records` into `publish_spool` under
the connection's slot turn, so a write made during the transfer cannot enter
the published version. After #690 the transfer starts while the copy runs. The
copy is still 80% of the plan: it writes about as many bytes as the stream
holds (439 MB for the 198k-row proxy) into SQLite, under the slot, only to read
them back.

## Design

One read view per stream attempt, pinned in the slot turn.

1. In the slot turn, the snapshot opens a read-only connection and runs
   `BEGIN` plus one read. SQLite WAL gives that connection the database as of
   its first read for as long as the transaction stays open.
2. It reads `MAX(seq)` of `record_changes` in the view. If that differs from
   the watermark W the turn read, it releases the view and re-snapshots.
3. The row-size queries and the transfer both read `records` by prefix inside
   the view. The `replaceBelow` predicate is the one the copy used, so the
   rows are the same.
4. The transfer releases the view as soon as the last part is encoded, not at
   upload drain. The plan's `finally` releases it on every other path. Release
   is once-only.
5. A driver without `snapshot()` (the web host's TRUNCATE journal, `:memory:`
   databases, an unknown phone driver) keeps the copy. Nothing else changes.

The view is a new connection, not the shared `reads` connection. A long
`BEGIN` on `reads` would pin every HTTP read to a stale state. A reader worker
holds many views, one per stream attempt. Streams of a connection publish
concurrently, so views overlap.

### Why this view and not a watermark

A watermark (`seq <= W`) needs every row to carry the sequence that wrote it.
`records` is updated in place and is `WITHOUT ROWID`, so a row newer than W
looks like a row at W. A published version could contain a row it should not.
That changes what a version can contain. The view cannot: it is the database
at one instant.

Prior art: Litestream holds a long read transaction to replicate a consistent
database; Postgres `pg_export_snapshot` shares one snapshot across workers;
Linear's `lastSyncId` is a watermark, and works because its log is append-only.
`sqlite3_snapshot_open` would let several connections share one snapshot, but
better-sqlite3 does not expose it. Each stream opens its own view instead.

## What the view must keep true

`records` changes only inside slot turns, and the publish holds the slot when
it pins. So the view holds exactly the state at W, and the `MAX(seq) = W` check
makes that an observed fact, not an assumption: a write that ignored the slot
would show as a different `MAX(seq)` and force a retry. The `seen_*` columns are
not in `record_changes`, but they move only in slot merges, so the same
argument covers them.

`docs/formal/PublishSnapshot.tla` checks the property "a done publish is the
rows as of W" under TLC (1 job, 4 workers, `nice -n 19`; 2 rows, up to 4
writes):

| Mode / rogue writer in the turn | Result                                         |
| ------------------------------- | ---------------------------------------------- |
| copy, no rogue                  | holds (800 states)                             |
| view with check, no rogue       | holds (707 states)                             |
| view with check, rogue          | holds (1249 states): the check forces retry    |
| view without check, no rogue    | holds (707 states): the slot alone suffices    |
| copy, rogue                     | violated: the copy does not stop a rogue write |
| view without check, rogue       | violated                                       |
| read live during transfer       | violated (the control: why a view is needed)   |

So the view with the check is at least as safe as the copy, and the check is
not redundant against a write that skips the slot.

## WAL checkpoints during a long read

A read transaction pins the WAL's end mark. A checkpoint cannot recycle WAL
frames before it. Writes that commit during the read still append, so the WAL
grows by the bytes those writes commit. The auto-checkpoint is a threshold, not
a cap, and it is passive: it does not wait for readers. When the view
releases, the next checkpoint recycles the WAL.

Bound: WAL growth during a publish is at most the bytes committed by other
writers while the view is open, plus the WAL not yet checkpointed at pin time.
There is no fixed number in the design. The hold time is the transfer time
(25 to 45 s in the bench), because the send gate (D1) paces encoding. A
checkpoint that must wait is not stuck: the next one after release finishes it.
Phase 2 adds a metric for view hold time and WAL size at release, so growth is
observable per publish.

The bench has no concurrent writer, so it shows the base WAL, not the growth.
Peak WAL there was 51 MB with a view and 67 MB (median) with the copy.

## Interactions

| Part                               | With a view                                                                                                                    |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| D2 `seen_*` columns                | Read in the view with the rows; they match the turn's state (above).                                                           |
| Unchanged refresh (0 parts, #687)  | Still reads and encodes the changed prefixes, uploads nothing. Cheaper: no copy.                                               |
| D1 send gate (`holdMemory` budget) | Unchanged. It paces encoding, so it sets how long the view stays open.                                                         |
| Delete and fence                   | A delete or fence takes the slot after the commit. The view is already released at the last encode or in the plan's `finally`. |
| Purge, failure, abandon            | `finally` releases. A test asserts opened views equal released views on a failing PUT.                                         |
| Spool cleanup                      | With a view there is no spool attempt to drop. A copy-mode host is unchanged.                                                  |

## The row-size queries (16%)

The plan sizes each prefix with keyed lookups (397 queries of 500 keys). They
run in the view now. Two alternatives were measured and neither won:

- One grouped read of `records` (arm D). Plan wall time was not distinguishable
  from the keyed lookups (median 10.5 s against 9.1 s).
- A stored `records.body_bytes` column (arm C, backfilled; migration plus
  backfill about 9 s for 198k rows). It also did not win (median 10.9 s plan,
  30.6 s stored). `length(body)` counts characters, so it cannot stand in.

The spool stored `body_bytes` for the page-cut query; reading `records` needs
`LENGTH(CAST(body AS BLOB))`, which reads each body twice (13 to 20 s of
reader-thread time on a loaded host). That did not show up as a slowdown, so
Phase 2 keeps the keyed lookups and adds no column.

## Measurement

Workload: `packages/server/src/localdb/publish-pipeline.workload.ts`, the
198,001-row, 439 MB stream, fake storage with 1.2 s per PUT, width 16, one
publish per run, database restored from a pristine copy before each run.
Arms rotated within each of 4 rounds, so each round has one run of every arm
under similar load. Baseline arm A is #690's pipelined copy (the source of
64a132d6 is the merged source; the merge differs only in tests and docs).

Host load average at run start: 13.6 to 26.1. Absolute times move with load;
read the medians and the round pairs, not one run.

| Arm                          |   Plan | First PUT | Stored |  Total | WAL peak |
| ---------------------------- | -----: | --------: | -----: | -----: | -------: |
| A: #690 copy (baseline)      | 16.6 s |     5.9 s | 28.6 s | 34.7 s |    67 MB |
| B: view, keyed sizes         |  9.1 s |     9.2 s | 27.9 s | 29.3 s |    51 MB |
| C: view, stored `body_bytes` | 10.9 s |    11.1 s | 30.6 s | 32.1 s |    51 MB |
| D: view, grouped sizes       | 10.5 s |    10.6 s | 27.8 s | 28.9 s |    51 MB |

Per round, stored (A / B / C / D, seconds):
r0 37.0 / 31.9 / 29.4 / 25.5; r1 32.0 / 35.0 / 41.8 / 30.0;
r2 25.1 / 23.8 / 31.8 / 36.8; r3 21.4 / 20.6 / 23.8 / 20.8.

With no storage latency (`--put-ms 0`, A B B A, load 35 to 48): stored
A 35.1 and 33.5 s, B 31.4 and 19.4 s.

What the numbers say:

- Stored time is not distinguishable between A, B and D at this load. The
  median difference of B from A is about 1 s of 28 s; the round-to-round
  spread is 10 s or more. C is worse, with no known cause; it is one noisy arm.
- First PUT is later with a view (9.2 s against 5.9 s). The view's first PUT
  waits for the full plan. The copy's first PUT waited only for the size
  queries and the first prefix. This is a regression in one number.
- The plan (the slot turn) is shorter, 9 s against 17 s, and writes no
  rows. That frees the connection's slot sooner for other streams.
- WAL peak is 24% lower.
- With zero PUT latency the stored time is still 19 to 35 s. After #690 the
  long pole is not the copy and not storage. It is read, encode and encrypt of
  477 MB. The copy ran on the writer thread, beside the encode, so removing it
  adds little wall time. I did not profile the encode; that is the next
  measurement, not a claim.

So the change removes write load (about 439 MB of SQLite writes per large
stream, less WAL, a shorter slot turn) and does not, by itself, shorten
import-to-stored time on a multi-core host. It should shorten it on a host
where the writer and reader threads compete for one core or one disk, which
the bench cannot show. Do not promise a latency win.

## Risks

- A long read holds the WAL. Bounded by concurrent writes during the transfer;
  observed, not capped. Add the metric.
- First PUT is later than #690 unless the plan is pipelined too (below).
- A driver without `snapshot()` keeps the copy, so two paths exist. The part
  hashes of both paths are equal (test), so they are interchangeable.
- The phone driver's snapshot behaviour is not known; it stays on the copy until
  a test shows a view there.
- Many overlapping views multiply open file handles and page cache pressure;
  streams of one connection publish concurrently.
- Tests: the existing publish fixtures use `:memory:` and run the copy path
  only. The new tests use a file database.

## Phase 2 (after #690)

1. Rebase on 46cd4c55. Remove the prototype switches
   (`PUBLISH_PLAN_GROUPED`, `PUBLISH_BODY_BYTES`) and the grouped planner;
   keep the keyed planner. No migration.
2. Pipeline the plan: hand the transfer each prefix as soon as its size is
   known, instead of after the last. This recovers the first PUT.
3. Metric: view hold time and WAL size at release, per publish.
4. A WAL growth test: hold a view, commit writes of known size, release,
   checkpoint, check the WAL returns to its base size.
5. Phone driver: decide whether it offers `snapshot()`.
6. Profile the encode and encrypt path. That is where the time is now.

## Expect it to work because

The isolation does not depend on the copy. It depends on two facts the code
checks: the slot is held when the view pins, and `MAX(seq)` in the view equals
W. The model shows the check holds the property even against a write that
ignores the slot, and a mutation of the code (reading the live reader, not the
view) fails the isolation test. The likeliest wrong assumption, that
`records` changes only in slot turns, is what the check turns into an observed
equality, so a violation retries instead of publishing a wrong version. What
the evidence does not show is a latency gain; the design is justified by the
write load and slot time it removes, and the measurement says so.

## Scratch (not committed)

`~/.tmp/gap-snapshot-1115-{ps,data,scripts,install.log}`.
