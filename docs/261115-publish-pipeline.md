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

Open: the plan before the first PUT (the record-changes read, the part-layout
sizes, `planBuckets`) still finishes before the transfer starts, about 1.3 to
2 s on the 198k-row stream. `planBuckets` needs the byte count of every
changed row's shard before it can name the first bucket, so it is a whole-input
step. Overlapping it would need a different planner. Not done here.

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
