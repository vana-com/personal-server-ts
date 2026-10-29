# PDPP import job (contract version 1)

A Personal Server-owned, resumable import of one connector run into the
canonical record store. It replaces whole-scope ingest for hosts whose storage
adapter implements the capability; hosts without it keep the old path.

Types: `packages/core/src/storage/pdpp-import-job/contract.ts`
(`@opendatalabs/personal-server-ts-core/storage/pdpp-import-job`).

## Why

On the phone, saving a 313 MB ChatGPT export parses every record three times,
sends the export over the WebView bridge three times and re-serializes every
item inside an in-process HTTP upload: about 36 times the export in allocation.
The job takes the records once, in byte-bounded batches, from an immutable
spool, and publishes them in one short transaction.

## Lifecycle

```
begin(jobId, binding, spool, streams)    -> status { job, resume }
append(seq, text, sha256, spoolStart/End) -> batch receipt (durable)
status(jobId)                             -> resume point after a restart
commit(batches, connectorState?, completion?) -> commit receipt (one transaction)
abort(jobId)                              -> nothing staged stays
```

- **Binding.** A job is bound to the server owner, one connection (PDPP
  instance), its source id, method and generation. Every operation reads the
  current owner and compares it with the job's stored owner (and
  `connectorState` with the owner of the job that wrote the state); while
  the owner is missing or empty every operation fails `owner_mismatch`. `begin` refuses a binding
  that differs from the store's current one. The adapter checks it again
  inside the publication transaction, so a connection reset or deletion
  during the run makes the job unpublishable (`binding_mismatch`).
- **Spool.** UTF-8 lines, one JSON record per line (`pdpp-ndjson-v1`):
  `{stream, key, data, emitted_at, op}`. The host writes the spool once and
  never changes it. A batch is a run of whole lines, exactly the spool bytes
  `[spoolStart, spoolEnd)`; `spoolStart` must equal the job's `spoolOffset`.
- **Open spool.** A job may begin on a spool the host is still writing:
  the handle has no `byteLength` or `sha256`. Batches stage while the
  connector downloads; each ends at a line break. The batch that ends the
  spool carries `seal: {byteLength, sha256}` and the job stores the sealed
  handle with it. A commit before the seal is `spool_incomplete`.
  `importSpool` with `available` appends only full batches that written bytes
  follow, so the cuts equal those of the sealed spool; with `seal` it appends
  the rest.
- **Batches.** Default 1 MiB, at most 4 MiB. A single record may exceed the
  budget up to 16 MiB, alone in its batch; a larger line fails with
  `record_too_large` before it is parsed. One batch per job is in flight,
  queued or running: a second append fails `job_busy` at once, before its
  text is held, and is safe to retry after the first settles.
- **Digests and receipts.** Each batch carries the SHA-256 of its bytes; the
  engine verifies it. Each staged operation carries
  `sha256(canonicalJson([stream, recordKey, op, data, emittedAt]))`. A batch
  receipt is durable. Sending a stored `seq` again with the same digest
  returns the stored receipt and writes nothing; another digest is
  `batch_conflict`; a gap is `batch_out_of_order`.
- **Resume.** `status` returns `{seq, spoolOffset}` of the last durable batch.
  After process loss the host reads the spool from that offset. No scope is
  replayed.
- **Commit.** `batches` must equal the durable batch count, so a lost append
  cannot publish a short job. The whole spool must be consumed: at least one
  durable batch, `spoolOffset == spool.byteLength`, and receipts that chain
  from byte 0 to the end; otherwise `spool_incomplete`, and no completion or
  cursor is written. `begin` refuses an empty spool. The adapter checks the
  offset again inside the publication transaction. A retried commit returns
  the stored receipt.
- **Abort.** Drops staged rows. A committed job stays committed.
- **Reset and deletion.** Erasing a connection erases its import data in the
  same transaction: open jobs abort (`connection_reset`), staged rows and the
  committed cursor go (the SQLite store runs adapter erasers registered with
  `onEraseInstance`). The engine also returns no connector state whose
  generation is not the binding's current one, for an adapter that has not
  erased it yet. A publication re-checks the job and binding at its commit
  point, so a reset or abort that lands while it runs wins.

## Rules the engine owns

The adapter never decides an outcome. The engine (`createPdppImportJobs`):

- refuses a record of another instance or an undeclared stream;
- validates each record with the existing `planIngest` (emitted time, op,
  key encoding, key against declared primary key, declared schema,
  append-only deletes). Refused lines are listed in the receipt and never
  staged;
- computes `recordKey = encodeRecordKey(key)` and the operation digest;
- refuses a batch whose record has `data.blob_ref` (`blob_ref_unsupported`).
  The blob claim is checked against the store at publication, after the
  index kept only the latest operation of a key, so an edit with an
  unclaimed blob would drop the earlier valid version that line-by-line
  ingest keeps. The job cannot pass that batch; the host aborts it and uses
  the old path until blob staging exists.

## Latest-operation index

The adapter keeps one staged row per `(job, stream, recordKey)`. For a
`mutable_state` stream a later operation replaces the row (`keep: "last"`);
for an `append_only` stream the first stays (`keep: "first"`), because the
first write of an append-only key stands. Publication applies rows in
ascending `order`. The published current state equals ingesting every line
in spool order; versions in between inside one job are not written as
history. Example: an upsert then a delete of a key the store does not hold
publishes nothing, where line-by-line ingest would leave a tombstone.

## Publication (adapter `publish`)

One transaction, all or nothing:

1. Re-read the job. Committed: return its receipt. Aborted: `job_not_open`.
   `nextSeq` changed: `batch_count_mismatch`.
2. Check the binding as ingest does.
3. Apply index rows in `order`, in pages bounded by rows and by the job's
   batch bytes (one row at least), through the host's ingest
   path (`planIngest` against current rows), with its history, arrival and
   blob-claim checks. When replication is enabled, its capture runs in this
   transaction; when it is disabled nothing is captured.
4. Check completion proofs against the resulting live set (the existing
   `completeStreams` rule) and store their receipts.
5. Store the connector state, the commit receipt and `committed`.
6. Drop the index rows.

Readers never see staged rows. Connector state is written only here, so a
cursor can never be ahead of the data it describes.

## Capability and version boundary

`PdppImportJobCapability.contractVersion` must equal
`PDPP_IMPORT_JOB_CONTRACT_VERSION` (1); the engine refuses another value
with `capability_version_mismatch`. Implementations:

- Node SQLite: `packages/server/src/storage/pdpp-import-jobs-sqlite.ts`, tables
  in the record store's database, publication through `ingestBatch` and
  `completeStreams` inside `writeTransaction`.
- In-memory oracle: `packages/core/src/storage/pdpp-import-job/memory.ts`.
  The native adapter should behave exactly like it.
- Lite: `createPsLiteRuntime({ importJobs })` exposes `runtime.importJobs`
  when the host supplies the capability; without it the runtime is unchanged.

`publication` (optional; absent means the version 1 behaviour above) says
how an adapter publishes:

- `mode: "native-staged-copy"`: `stageBatch` stores the batch's encoded
  canonical entries (`canonical.entries`) in an invisible staging table of
  the same database, in the receipt's transaction. `publish` is one native
  set-based copy (`INSERT … SELECT`) into the canonical tables, with
  connector state, completion and commit receipts, and deletion of the
  staging rows, in one transaction. The engine requires `encodeBatch` for
  this mode and refuses it for any other; it calls it once per durable batch.
  Each batch also carries `canonical.fence`, the clock value it was encoded
  against. Entries encoded against an older state would overwrite later
  writes, so `publish` refuses `canonical_moved` unless the committed clock
  still equals batch 0's fence and no other canonical transaction committed
  since batch 0 was staged; the host aborts and starts the job again.
- `outbox: "by-reference"`: an outbox entry names the committed operation
  (`{batchId, operationKey, sequence}` in the Lite canonical store) and
  carries no record bytes. `captured-in-transaction` is the Node SQLite
  behaviour.

The encoder is `createLiteCanonicalImportEncoder` in
`@opendatalabs/personal-server-ts-lite/import-job`, which also re-exports
this module, `planIngest` and `encodeLiveSnapshotDigestInput`. It runs the
real `commitLocal` write path over a read view (the host answers from the
job's staged entries over its committed entries) and captures the writes,
so its entries are the keys and values Lite would write, byte for byte
(`packages/lite/src/import-job.test.ts`). `importBatchParts` splits one
import batch into `commitLocal` parts of at most 192 KiB.

`readSpool` is optional; with it, `importSpool` pumps a spool in batches and
resumes from the job's offset. No whole-file read is reachable from the job:
an ESLint rule rejects whole-file read calls (`readFile`, `readEnvelope`,
`.text()` and similar) in these modules.

## Memory

Peak memory follows the batch and the largest record, not the export.
`pdpp-import-jobs-memory.test.ts` imports synthetic exports (small non-ASCII
messages, one 12 MiB conversation, append-only events, a delete-heavy second
half) through the Node SQLite adapter in a child with a 160 MB V8 heap cap.
Measured on 2026-10-28 (Node 24, default 1 MiB batches):

| Export | Records | Batches | Peak sampled heap | Peak RSS |
| ------ | ------: | ------: | ----------------: | -------: |
| 32 MB  |  34,555 |      26 |          100.1 MB | 325.3 MB |
| 128 MB | 163,222 |     123 |           81.0 MB | 355.8 MB |
| 313 MB | 410,744 |     308 |           58.7 MB | 353.7 MB |

Idle heap is 10 MB and idle RSS 81 MB. Without the giant record, peak heap is
about 41 MB and peak RSS about 243 MB. CI runs the 32 MB case; set
`PDPP_IMPORT_MEMORY_SIZES_MB=32,128,313` for the full run.

## Not in version 1

Full-refresh replace (tombstoning live keys a run lacks), parent/child join
indexes for bounded legacy projections, blob staging, and HTTP routes. These
are additive.
