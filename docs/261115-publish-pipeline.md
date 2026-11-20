# Stream publish: upload while the snapshot is still planning

Status: implemented. Scope: one stream's publish in `packages/core/src/localdb/publish.ts`
and `encode.ts`.

## Problem

A first publish of a large stream took `plan + transfer`. The plan (the
snapshot, one slot turn) finished before the first PUT started, so the network
sat idle for the whole plan.

## Measurement (before the change)

Synthetic stream of the ChatGPT 198k `memories` shape: 198,001 rows of about
2 KB, 439 MB, 128 parts of 4 MiB. Real SQLite, real encoder and AES-256-GCM,
real send gate. Fake storage with a fixed 1.2 s per PUT, width 16
(`packages/server/src/localdb/publish-pipeline.workload.ts --profile`).

Split of one run's `planMs` (25.9 s; the host ran at load 23 to 40, so absolute
times are noisy but the shares were stable over three runs):

| Part of the plan                                              | Time   |                                     Share |
| ------------------------------------------------------------- | ------ | ----------------------------------------: |
| Spool copy: 128 x `INSERT INTO publish_spool ... SELECT`      | 20.9 s |                                       80% |
| Row-size queries for part layout (`planBuckets`, 397 queries) | 4.2 s  |                                       16% |
| `record_changes` read                                         | 0.7 s  |                                        3% |
| Slot wait (queue)                                             | 0 ms   |                                        0% |
| Encode/encrypt, hashing                                       | 0 ms   | not in the plan; they run in the transfer |

So the plan is not slot wait and not one slow query. It is mostly a row copy
that must finish under the slot before anything leaves the machine. That is
what pipelining removes. The fix is to overlap, not to tune a query.

## Design

Before: `snapshot (slot) -> transfer -> commit (slot)`. The snapshot copied
every changed prefix into the spool, read the basis, and returned a candidate
holding all the frozen prefixes. Only then did the transfer start.

After: the same three phases and the same slot turn. The snapshot copies the
prefixes one at a time. After each prefix it announces a count (not rows) on a
`FrozenFeed`. The transfer is launched by the snapshot just before the first
copy. It encodes and uploads each prefix as the feed announces it.

```
snapshot (one slot turn)   plan -> launch -> copy p0 -> copy p1 -> ... -> basis -> end feed
transfer (no slot)                   \-> encode p0 -> PUT ... encode p1 -> PUT ... -> head part
commit (slot)                                                          after BOTH finish
```

- `newFrozenFeed()` (encode.ts): a one-producer, one-consumer async queue of
  `FrozenPrefix` (prefix, row count). It holds no rows. `end()` says the copy
  finished; `fail(error)` makes the consumer throw at once; `abandon()` is the
  consumer's "I stopped" so the copy stops.
- `snapshotStream` takes a `launch` callback. It builds `TransferPlan` (part
  layout, head fields, blobs, base parts, spool attempt id) after the last read
  that can still end the turn without a candidate (idle, deferral, retry), then
  calls `launch(plan, feed)`. The rest of the old `Candidate` (basis,
  watermark, run ids) is unchanged and returned when the turn ends.
- `publishAttempts` stores the launched transfer promise. After the snapshot's
  turn ends it awaits that promise instead of starting the transfer.
- `transferPlan` is the old `transferCandidate` reading `plan` and the feed. Its
  `finally` calls `feed.abandon()`.
- `readSpool` reads through the driver's read connection (`readerOf`), so the
  transfer's page reads do not queue behind the snapshot's batches on the single
  writer worker. They see committed spool rows only, which is all the feed
  announces.

## Invariants and why they hold

1. **The registry head is written only after every part is confirmed stored,
   including on retry, partial failure and cancel.** `transferOnWave` returns
   only after `wave.drain()` (every PUT stored) and the head blob is stored, and
   `publishAttempts` awaits the transfer before the commit slot turn. Nothing
   about that order changed; the transfer only starts earlier. A transfer error,
   a snapshot error or a purge ends the attempt through the same paths as
   before (the wave is settled, the spool is dropped), and the commit never
   runs. Tests: "posts the registry row only after every part and the head are stored,
   though the snapshot ended first", "posts nothing and stops copying when an
   upload fails while the snapshot is still copying", "ends the transfer and
   posts nothing when the snapshot fails after uploads started".

2. **Memory stays bounded by the governor's byte budget.** The feed holds counts.
   Each part still reserves its bytes with the send gate before it is encoded
   (`holdMemory`), and the encoder waits for the next prefix without holding
   memory. The spool is on disk. Test: "holds no more than the byte budget while the snapshot copies ahead of
   the uploads".

3. **Part order and content are deterministic.** The prefix order is the
   `changedPrefixes` order the planner produced; the feed delivers in that order;
   `encodeFrozenParts` consumes it in order. Rows within a part are read by
   `ORDER BY pk_hash` from the spool. None of that depends on timing. The
   existing `encode` and `publish` determinism tests pass unchanged.

4. **Small streams and unchanged refreshes behave as before.** A stream with no
   changed prefix gets a feed that ends at once and a transfer that uploads
   nothing; the `idle` and deferral paths return before `launch`. The D2 #687 rule holds: the refresh hashes the same
   head, the transfer finds every part present, uploads nothing, and the
   data-hash check returns before any head PUT or registry write. A one-prefix
   stream is a feed of one.

5. **The snapshot stays consistent: a write during the publish is not mixed
   into this version.** Isolation never came from the transfer; it comes from
   the slot and the copy. The snapshot still copies every prefix, reads the
   basis and ends inside one slot turn on the connection's queue, so an intake
   write (which takes the same slot) cannot run between prefix copies. The
   transfer reads only the spool (a private copy keyed by the attempt id), never
   `records`. The commit still compares the basis and defers or retries if local
   state moved. What changed is only that PUTs of already copied prefixes run
   while the slot is held. A write that arrives then waits in the queue, as it
   did before; it lands after the copy and is excluded from this version.
   Test: "leaves a run that ends during the copy out of this version" (an `end`
   fired when the copy starts is excluded). First-PUT timing: "starts the first
   upload before the snapshot has copied every prefix". On a database file with the production driver's separate read
   connection: "reads only prefixes whose copy has committed ... and leaves a write
   made during the publish out".

## Width of the upload (follow-up)

The pipeline above overlaps the copy and the uploads. What was left was the
width of the uploads. The send gate's window cap was 16 (64 MiB over 4 MiB), but
the byte budget counted each part twice, plain and ciphertext, until its PUT
settled. The same 64 MiB therefore held 8 parts, and 8 was the real width in
production. The gate never reached 16.

Two changes, no format change:

1. An upload keeps only its ciphertext while its PUT waits and runs. It drops
   the plain bytes once encrypted and `Reservation.shrink`s its reservation to
   the ciphertext's size, so a part in flight costs one part of the budget.
2. The width is a named constant, `PARTS_IN_FLIGHT = 16`, derived in
   `storage-retry.ts` from the storage guard's rate (10 PUT/s) and the measured
   time of one part's PUT (1.26 s): `ceil(10 * 1.26) = 13`, rounded up to the
   next step of the gate's slow start. The budget is the parts in flight plus
   the part being built (two parts): `(16 + 2) * 4 MiB = 72 MiB`, up from 64 MiB.

Bytes and order are unchanged. The part and head names are content hashes; a
run before and after stores the same set of names (`objectsDigest` in
`publish-pipeline.workload.ts`).

### Three more costs, in order (follow-up 2)

With the width at 13 under the guard, the upload phase still did not meet the
guard's floor (129 PUTs at 10 PUT/s is 12.9 s, plus one PUT time). Three
costs sat around it. Measured on the 198,001-row stream.

**1. The commit tail (0.7 to 4.5 s after the last PUT).** Cause: the WAL
auto-checkpoint, inside the commit's `COMMIT`. Evidence, from timing the commit
batch statement by statement (`--profile-statements`): the slot turn that
commits took 3.2 s, and 3.17 s of it was one statement, the compaction
`DELETE FROM record_changes WHERE seq <= W` (198,001 rows). On a copy of the
database the same DELETE alone takes 0.30 s (0.16 s with its per-row
`record_changes_compacted` trigger dropped), and its `COMMIT` takes 5.2 to 6.3 s
with SQLite's default `wal_autocheckpoint = 1000` and 23 ms with it off; the
checkpoint then costs 5.9 s when run on its own. The DELETE rewrites 12,417
pages, so the commit crosses the mark, and the connection that commits
checkpoints before `COMMIT` returns: the caller, and the slot turn it holds,
wait for 12,417 pages to be written and synced. The disk here is shared, so the
size is not portable; the mechanism is. Fix: the writer connection has
`wal_autocheckpoint = 0` and, after it has replied to any write on its own connection (a
`batch`, or a `query` that writes), runs the same PASSIVE checkpoint at the same
mark (1000 frames, read with `wal_checkpoint(NOOP)`).
The next call to the writer waits for it, so the log stays as short as before
and the work is the same; only the commit's reply no longer waits. The tail
fell from 0.8 to 2.8 s to 0.5 to 0.75 s: the DELETE itself.

**2. The slow-start ramp (about 4 s under the guard).** The ramp probes a rate
nobody has told us. vana-storage publishes its quota (`RateLimit-Policy`), so
the gate now takes it as the rate: the first published `put` quota opens the
window to `ceil(rate * partPutSeconds)` (13 for 10 PUT/s and 1.26 s), capped at
the window cap, and ends slow start there; from there the window grows by one,
and a 503 halves it as before. Tokens still pace every request, so a wider
window never sends faster than the quota. Two cases keep the ramp from 1: a
store that publishes no quota (nothing is known about it), and a gate that has
already seen a 429 or 503 (the service has answered). In production the quota
comes from a response header, so the window opens when the first response that
carries it arrives: one PUT time at window 1, not four ramp steps. The rate
limit feed replays the policy it has seen to a new subscriber, so later
publishes in the same process start open. The harness sets the quota up front,
so it shows the best case.

**3. The plan before the first PUT (1.2 to 2 s).** Left as it is. A bucket's
name does not strictly need the whole input: a prefix is a leaf when its own
range is at or under the target, and a prefix above it is split once the part
of its range already seen passes the target, so the buckets could be named in
order as the shards are sized. But the plan feeds `TransferPlan.changedPrefixes`
and the candidate's `changedPrefixes` as whole arrays, so naming them early
changes the hand-off between the snapshot and the transfer: a protocol change
that needs its model checked first, for a gain bounded by the sizing step
(0.3 to 0.5 s of it). The planning time splits into the changed-key read (0.25 s
in the worker, 0.5 to 1 s as the main thread sees it, because 198,001 rows
cross the thread boundary), 397 size queries of 500 keys through the view's
reader (0.3 to 0.5 s), and the planner. Folding the sizing into one SQL
statement per 16-bit prefix was measured and is slower (5.8 to 6.3 s: SQLite
drives it from `record_changes` with the correlated `NOT EXISTS`), so it is not
a cheap win either.

Result, guard 600/60 s and 1.26 s per PUT, three base/head triples run back to
back inside one slot (load 10 to 17): base 28.5 s median (27.1 to 31.2), #706
23.7 s (20.3 to 23.7), this change 16.1 s (16.0 to 16.1). Upload phase 14.2 s in
all three runs, against 129 PUTs at 10 PUT/s plus one PUT time (about 14.2 s):
at the floor. Tail after the last PUT 0.36 to 0.54 s (base 1.0 to 5.1 s).
`objectsDigest` is the same in all nine runs.

Attachments now shrink to their ciphertext as parts do: they were the one place
still held at twice their size until the PUT ended.

## What this does not change

- The send gate's window rules, quota and retry. Width is `PARTS_IN_FLIGHT`.
- The slot turn's length. The snapshot is as long as before (the copy is the
  same work), so a write to the same connection waits as long as before. The
  PUTs now run during that wait instead of after it.
- The spool format, the head format, the part format, the vectors.

## Bench

Same stream, 1.2 s per PUT, width 16, byte budget for 16 parts. Six runs per
side (two single runs, then four interleaved base/new pairs) on a host at load
21 to 40 on 24 cores, so single runs vary by 2x; read the medians. Seconds, from
the start of `publishConnection`.

| Median of 6                          | Before | After |
| ------------------------------------ | -----: | ----: |
| First PUT starts                     |   20.2 |   9.0 |
| Stream fully stored (last PUT ends)  |   53.0 |  40.0 |
| `totalMs` (adds commit + spool drop) |   56.9 |  52.1 |
| `planMs` (the snapshot's slot turn)  |   20.1 |  27.2 |

Quietest pair (before: `plan 20.0, first PUT 20.1, stored 35.3, total 38.1`).
After, in the interleaved pairs, stored time fell in all four pairs: 51.5 to
32.2, 62.6 to 41.1, 61.8 to 50.8, 43.7 to 39.0.

Reading it:

- The first PUT now starts 11 s earlier and the stream is stored about 13 s
  sooner at the median. The transfer no longer waits for the copy.
- `planMs` grows because the copy now shares the host with encryption and the
  transfer's reads. It is no longer a delay before the first upload.
- `totalMs` shows a smaller gain than "stored" because it ends with the commit
  and the post-commit spool `DELETE`, which are unchanged and vary most under
  load (up to 27 s in two base runs).
- The new floor is `max(copy, transfer)`: here the 20 to 27 s copy against a
  12.9 s transfer floor (129 PUTs at 10 PUT/s), so the copy is the long pole.

## Open risks and next levers

- The copy is 80% of the plan. If the copy gets faster, the overlap gets smaller but the total still falls. Reading straight from `records` under a read transaction would remove
  the copy, but it changes the isolation story above, so it is a separate
  design.
- The first PUT now starts inside the slot turn. A test or a driver that
  assumed no storage call inside the snapshot has to park on `probe` calls (see
  `publish-split.test-utils.ts`).
- The spool's post-commit `DELETE` (4 s for 128 prefixes) is still after the
  commit and still counts in `totalMs`.
- Timing on a loaded host is noisy; compare medians of interleaved runs.
