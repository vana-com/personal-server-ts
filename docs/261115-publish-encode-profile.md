# Stream publish: where the time goes after #690

Status: measurement note on 46cd4c55 (PS #690). No product code changed. The
bench gained a `--cipher prod` switch so it seals parts with the production
construction (`sealBytes`, age STREAM over ChaCha20-Poly1305). Before, it used
node AES-GCM, which is about 6x cheaper than production in JavaScript.

Workload: `packages/server/src/localdb/publish-pipeline.workload.ts`, 198,001
rows, 439 MB, fake storage at zero PUT latency, one publish per run.
Host load average 10 to 48 during the runs. Absolute times move with load;
only interleaved medians and CPU seconds are comparable.

## What bounds the stored time

On 46cd4c55 the transfer starts while the snapshot copies rows into
`publish_spool`. The copy (INSERT...SELECT, about 11.7 s, then about 6.9 s of
row-size queries) runs on the writer thread and takes 17 to 18 s. The transfer
needs about 15 s from its first PUT. It chases the copy, so stored time follows
plan time. Making the transfer faster does not shorten stored time while the
copy is the long pole.

## Transfer cost, split (production cipher, load about 22)

| Stage                                 | Where         | Time                                         | Floor for same bytes                                        | Gap   |
| ------------------------------------- | ------------- | -------------------------------------------- | ----------------------------------------------------------- | ----- |
| Seal (ChaCha20-Poly1305 + HKDF)       | main thread   | 2.3-2.6 s                                    | 0.24 s native `chacha20-poly1305` (0.39 s AES-GCM)          | 10x   |
| SHA-256 of parts (noble)              | main thread   | 1.7-1.9 s                                    | 0.19 s `node:crypto`                                        | 9x    |
| Read (meta query + page query)        | reader thread | 5.8 s uncontended; 6.6 s SQL busy under load | 1.0-2.7 s synchronous `iterate()`; 1.7 s with 512-row pages | 2-6x  |
| Per-row `TextEncoder` + `frameOfBody` | main thread   | 0.7 s + 2.4 s                                | `JSON.stringify` of envelopes 0.24 s                        | n/a   |
| Part concat copy                      | main thread   | 0.75 s                                       | memcpy-bound                                                | small |
| GC                                    | main thread   | 1.3 s                                        | -                                                           | -     |
| Compression                           | none          | 0                                            | -                                                           | -     |

Main thread busy about 9 s of a 28 s run; reader thread busy about 9 s. Each is
idle about two thirds of the time because the encode loop and the reader
ping-pong: the loop asks for a page, waits, encodes it, asks again.
Total CPU per run is 26 to 35 s across threads.

## Design causes

1. Crypto and hashing run in pure JavaScript (`@noble`) on the main thread.
   Core shares one implementation with the browser, so node-native
   `chacha20-poly1305` and `sha256` are not used. Native ChaCha produced a
   byte-identical STREAM blob for the same key and nonce in a micro-bench.
2. The reader pages by 64 rows (`PAGE_ROWS`) with a separate meta query per
   page, so one 439 MB prefix costs about 6,200 queries. Larger pages cut the
   read from 5.8 s to 1.7 s in the micro-bench.
3. Read and encode do not overlap: no read-ahead.
4. Per-row string to `Uint8Array` conversion and per-row frame allocation.

## What I tried

Read-ahead, depth one page (`readAhead(readSpool(...))`), in the arm where the
transfer is the long pole (reading the live view instead of a copy; parked
branch `tnunamak/gap-snapshot-1115`). Interleaved A/B, 4 rounds, production
cipher, zero PUT latency, load 20 to 30:

| Arm           | Plan   | Stored (median) | Transfer after first PUT | CPU    |
| ------------- | ------ | --------------- | ------------------------ | ------ |
| no read-ahead | 7.9 s  | 22.1 s          | 14.6 s                   | 28.5 s |
| read-ahead    | 11.3 s | 31.2 s          | 18.7 s                   | 33.6 s |

Read-ahead is not faster. Plan time, which read-ahead cannot affect, differs by
3 s between the arms, so the difference is host noise (load 20 to 30 on a
shared machine) and CPU contention, not a gain. On a host whose cores are
saturated, overlapping two threads adds no wall time. I did not push it.

## Proposals, not built

Each is unverified against a quiet host.

- Native `sha256` and `chacha20-poly1305` behind a port that node hosts
  inject: saves about 3.5 s of main-thread CPU per 439 MB (4 s to 0.4 s).
  Blobs stay byte-identical, so existing blobs still decrypt and verify.
- Page by bytes (a few hundred queries per 439 MB, not 6,200): saves 2 to 4 s
  of reader time.
- Read-ahead: only after the above, when the reader is not the bottleneck, and
  only where the snapshot copy is gone. It reads one page outside the memory
  reservation (at most `PAGE_BYTES`, 2 MiB, per stream).

## Does the slot turn block a user?

From the code (`queue.ts` and its takers), not measured: the connection queue
runs one multi-batch operation per connection at a time. While a stream's
snapshot turn is open (17 s on the copy), same-connection work waits:
run-end merge of an import (`run-end.ts`), apply (`apply.ts`), delete and purge
(`delete.ts`, `purge.ts`), bootstrap, and the snapshot turns of sibling streams.
Other connections are not affected. `intake.batch` does not take the queue, so
writes during a run still land. A user sees this as an import that ends, or a
delete that completes, up to one turn later when it races a publish on the same
connection.
