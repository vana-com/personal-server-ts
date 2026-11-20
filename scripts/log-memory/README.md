# Bounded log storage reproduction

Set `STREAM_SYNC_MEMORY_DIR` to a disk-backed scratch directory. Run this file alone with Node 22 and the installed workspace dependencies:

```sh
mkdir -p "$STREAM_SYNC_MEMORY_DIR"
STREAM_SYNC_MEMORY=1 \
  nice -n 19 ionice -c3 npm test -- log-bounded-memory --maxWorkers=4
```

Use Vitest's `-t` filter to select one gate. Set `STREAM_SYNC_MEMORY_LOCK` to the shared `flock` file used by other test lanes (default: `core-suite.lock` in the receipt directory). Each memory subprocess acquires that lock without blocking and rechecks admission inside it. A busy lock or failed recheck releases the slot and waits 60 seconds without consuming a killed-run attempt. Use the same lock around full core suites. Six gates intentionally fail on the materializing implementation: compaction, rebase, 10× scaling, progressive restore, covered replacement, and metadata. A seventh opt-in probe checks real encryption and calibrates allocations. Normal test runs skip all seven. Failed assertions are intended reds; process death, missing output, fixture failures and admission refusal are never reds.

The runner checks `free -g`'s available column and `/proc/pressure/memory` every 60 seconds while waiting. It admits a subprocess only with at least 12 GiB available and `full avg60 < 1.0`. It also records host health every 60 seconds during a subprocess. A killed subprocess retries at most three attempts, with another 60-second wait and the same admission checks. Other failures are not retried. Each subprocess has a fresh file SQLite database and disk blob store; every GET returns fresh bytes. SQLite uses an 8 MiB page cache and file temporary storage. Generated databases and bundles are removed in finally blocks. JSON receipts retain host samples, exit signals, measured quantities and query plans. Set `STREAM_SYNC_RECEIPT_NAME` to keep multiple runs separately. Snapshots publish by atomic rename, and health samples append to a journal. With `STREAM_SYNC_MEMORY_RESUME=1`, a completed case can be reused only when its bundle SHA-256 matches; a killed or incomplete case is never cached.

The bundle changes test adapters, documented eligibility-only compaction guards, and observation barriers at decoded-input, retained-operation-map and upload-candidate boundaries. Ordinary publication keeps the real eligibility policy except when the snapshot/slow-upload fixture explicitly arms the guard. Fetch, verification, fold, codecs, SQL merge and publication implementations are unchanged. GC/WeakRef barriers test reachability of distinct body objects, including bodies held through a new batch wrapper; their byte counter is retained logical JSON size, not an assertion about V8 object layout or string deduplication. Candidate/output lengths and actual encoded SQL request/reply lengths give structural evidence independent of GC scheduling. RSS is supporting evidence, sampled externally every 100 ms, rather than a portable threshold.

Compaction includes fixed-winner history inflation and delayed upload of an actual publication candidate. Metadata includes concurrent real planners behind connection queues, caller cancellation before queued work allocates a plan, 5,000 durable bootstrap receipts, 512 streams, and actual EXPLAIN plans. Heavy-plan admission must cover the planner path; the test does not require serializing ordinary light connection callbacks. Bootstrap is today's durable unit-receipt owner; the test resumes its persisted receipts rather than inventing an unimplemented workspace method. Its semantic checks require no receipt to be fetched again and cleanup to follow final cursor commit. The indexed-page control hashes every key against SQLite's row iterator, checks reply size, and forbids a temporary sort.

`log-workspace-vectors.test.ts` supplies passing equivalence checks for escaped string keys, omission fragments, truthful incomplete/completed states, full typed tombstones, first-seen fields, reference-backed bodies and unpublished local observations during rebase. `log-fold-reference.test.ts` predicts each receiver's complete raw tombstone table from its delivered operations, then compares rows/completion/effective deletions across compaction. Raw tables need not be equal: foldLog drops an omission tied by a surviving upsert, while receiver apply retains the greatest deletion receipt. The oracle documents that choice and does not discard arbitrary dominated receipts from its per-receiver assertions.

## Resource ledger

Each receipt includes Bdb (configured database cache), P (cursor page budget), H0 (protocol head bound), R (record bytes), C (resident unit), T (transport frame), Bcrypto (crypto allocation) and copy coefficients bR/bC/bT. The JSON ledger keeps other hosts unmeasured. Identity-crypto reds do not establish crypto bounds. C is a 2 MiB target in these fixtures; accepting existing 16 MiB wire units needs the separate protocol admission bound.

The real-encryption probe uses the production key port for scope-key derivation, STREAM parts and OpenPGP control values, and verifies a receiver including a referenced body. The test gateway keeps its fixed namespace/key-check binding; payload encryption is real. A separate single-unit calibration samples heap and array buffers at canonical record encode/parse boundaries and before/after each real cipher primitive. It also measures the production control encrypt/decrypt path with an incompressible 1 MiB value. It records:

- `bR`: observed record heap plus array-buffer allocation, divided by canonical record bytes.
- `bC`: the measured clear, cipher and reopened whole-buffer lengths, divided by C.
- `Bcrypto`: the larger observed scratch allocation of STREAM part and OpenPGP control roundtrips. Each subtracts retained clear/cipher/reopened buffer lengths from observed array-buffer allocation and adds observed heap allocation. This charges collectible scratch too.
- `bT=0`, `T=0`: this Node fixture calls SQLite directly and sends no serialized bridge frames. These values say nothing about phone or browser transport.

These are measured coefficients for the stated fixture and boundary samples, not universal high-water guarantees. Synchronous internal allocation between boundaries can be missed; other shapes/hosts require calibration. The red tests establish structural violations without relying on those coefficients or fitting a threshold to the large run. Keep database cache/index/sorter and external RSS evidence alongside the ledger; `temp_store=FILE` alone does not bound materialized replies.

Before consumer migration, the capability requires ordered append receipts, immutable value sealing after length/digest/encoding validation, atomic verified input/fold receipt commits, output sealing, upload confirmation, registry outcome reconciliation, atomic seed/cursor promotion, accepted publication finish and indexed cleanup. Admission, disk-full, corruption and stale-authority failures cannot advance a durable cursor. Process-loss recovery and native/browser conformance remain later implementation slices.

`MEMORY_REFERENCE_PUBLISH` selects a saved historical publisher source for a baseline bundle; the production source is unchanged. The default operation probe observes the bounded selected-operation array when the publisher uses a workspace. `MEMORY_GC_EVERY` defaults to 1 (collection at every barrier); a larger interval reduces instrumentation cost for structural replacement measurements. Such runs do not establish decoded-object liveness at each commit or calibrated host copy coefficients. Compare baseline and candidate with the same interval. Replacement intake uses increasing observation stamps and asserts that every changed record and omission reached canonical state.

## Progressive ownership probe

Hold the same exclusive lock used by other memory experiments and full core runs. With at least 16 GiB available, run:

```sh
STREAM_SYNC_PROGRESSIVE_MEMORY=1 \
  nice -n 19 ionice -c3 npm test -- progressive-workspace-memory --maxWorkers=1
```

This probe keeps its own WeakRefs to each decoded unit. Fresh subprocesses replay 8 and 80 verified snapshot parts, first with one surviving key and then with growing key counts. File SQLite and disk blobs carry the durable state. At canonical commit barriers, at most two decoded input arrays and 1,024 encoded bytes may remain reachable. These deliberately small records test ownership as history and key counts grow; they do not calibrate RSS or large-record copy coefficients. The test prints every receipt and removes its bundles, databases and worker files.

Progressive replay scans verified metadata into indexed removal and naming facts before showing rows. It then rereads one unit at a time, resolves referenced bodies individually and stages each record durably. A durable connection-to-pass owner resumes active work after a restart and gives completed or replaced work a fresh id. The body promotion, visibility, partial marker, applied receipt and cursor commit together. The snapshot cursor stays put until its last part. A changed registry identity fences the old facts before another prefix is adopted. This introduces a prerequisite scan and serial unit commits; first-row timing and total I/O differ from the former read-ahead path.

Record admission reserves `4R + 2*PART_LIMIT_BYTES + 2 MiB` from the fixed 128 MiB read lease before fetching referenced pieces. An oversized record leaves a retryable durable admission failure without advancing the applied checkpoint. This is admission accounting, not an achieved OS RSS ceiling. SQLite native overhead and codec/crypto coefficients still need host calibration. `progressive-workspace-crash.test.ts` replays process loss before and after pass-owner adoption, scan receipts, body staging, the first visible part and the final cursor/marker commit.
