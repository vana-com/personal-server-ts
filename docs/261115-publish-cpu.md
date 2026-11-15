# Stream publish: CPU per thread

Scope: one stream's first publish (`publishConnection`) of 439 MB (198,001
rows of about 2.2 KB), after #690. This records why the publish reads a frozen
view, takes its cipher from the host, and pages by bytes, and the numbers future
work should compare against.

## What changed

- **View.** The slot turn pins a read view instead of copying `records` to
  `publish_spool`. It needs `snapshot()` on the driver and a WAL database;
  otherwise the copy runs as before. `docs/formal/PublishSnapshot.tla` is the
  model: a finished publish holds the rows as of the watermark. TLC holds it for
  the copy and the checked view, and violates it for a live read and for an
  unchecked view under a writer that ignores the slot.
- **Crypto port.** `StreamCryptoPort` (`seal`, `open`, `sha256`) in core. The
  server injects `node:crypto`; noble stays the default for Lite, Web and
  Desktop. The blob format is unchanged; HKDF stays in noble.
- **Pages by bytes.** Row sizes are read 2,048 at a time and cut into pages of
  at most 2 MiB (a larger row is a page of its own). Before, each page was cut
  from the next 64 sizes.

## Method

Per-thread CPU: `Worker.cpuUsage()` for the reader and writer workers,
`process.threadCpuUsage()` for the main thread; `other` is the process total
minus those (GC and libuv threads). The harness is
`publish-pipeline.workload.ts` with a `--crypto node|noble` switch and the CPU
split; it is on branch `tnunamak/gap-encode-1115` (head `78f8e5f7`), not here.
Production cipher (ChaCha20-Poly1305 STREAM), zero PUT latency, the database
restored from one pristine copy before every run, `nice -n 19`, 4 rounds with
the arm order rotated each round. Host load was 19 to 48 before each run, so
absolute seconds are inflated; compare arms within one table.

## Numbers

Median CPU seconds over 4 rounds. The floor for the reader is 1.7 s.

| Arm                             | main | reader | writer | other | total | busiest thread |
| ------------------------------- | ---: | -----: | -----: | ----: | ----: | -------------: |
| `46cd4c55` (copy)               | 7.56 |   8.64 |  13.07 |  6.66 | 35.41 |          13.07 |
| view                            | 7.72 |  13.34 |   1.80 |  6.54 | 30.43 |          13.34 |
| view + node crypto              | 4.28 |  14.42 |   1.84 |  7.50 | 27.98 |          14.42 |
| view + node crypto + byte pages | 2.99 |   8.46 |   1.99 |  2.21 | 15.64 |           8.46 |
| copy + node crypto + byte pages | 3.33 |   2.59 |  15.09 |  2.68 | 24.15 |          15.09 |

The last row is the check that the view earns its place: with the same crypto
and paging, the copy costs 8.5 s more total CPU and 6.6 s more on the busiest
thread, in each of the four rounds (busiest thread, view against copy:
7.5/8.2/8.7/8.7 s against 14.3/15.9/16.2/12.1 s).

## What stays above the floor

The reader is the busiest thread at 8.5 s. The view has no stored row size, so
the plan's 397 keyed `LENGTH(CAST(body AS BLOB))` queries read every body once
(3.9 s wall in a profile), the transfer reads each page's sizes, and then the
bodies. The copy's reader is 2.6 s because `publish_spool.body_bytes` is
stored. Page queries and the structured clone of rows across the worker
boundary make up the rest.

Not wired: apply's part-hash check (`streamSyncHashes`) and `artifacts.ts` still
use noble's SHA-256 on the server, and Lite, Web and Desktop stay on noble for
everything.
