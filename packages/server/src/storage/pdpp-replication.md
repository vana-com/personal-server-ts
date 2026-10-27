# Fenced PDPP replication export

This is the SQLite storage part of the Vana replica profile. It has no publisher,
receiver, DPv2 integration or production enablement. Existing local record reads,
query versions, history and completion receipts keep their existing contracts.

## Enablement and the fence

`store.replication.beginBaseline({ owner, declarations })` is an explicit internal
operation. The caller supplies the authenticated owner and retained declaration
bindings. This seam does not authenticate a caller, retrieve declarations or
verify their schema digests. Connector requests cannot set this configuration.
Missing source, method or declaration metadata fails the whole baseline. An
operator must resolve legacy orphan rows before enabling replication; the export
never guesses identity from a stream name or silently skips a row.

An immediate SQLite transaction persists the immutable owner/declaration binding,
allocates original replica revisions, writes pinned operation values and blob
bytes, records every baseline member, and commits a watermark. Other DB handles
cannot commit a write inside this fence. A writer that ran earlier is included;
a writer that runs later sees the persisted configuration and captures a tail
operation in its canonical transaction. Repeating enablement returns the same
watermark. A different configuration is refused. The original Slice 1 journal is
retained as local mutation evidence; its offsets do not become replica revisions.

The baseline includes all current rows, including record tombstones, all bound
connections, current verified blob claims, and stored completion receipts. Existing
registry generations are represented by generation-1 registration and the reset
chain through the stored generation; deleted bindings also emit connection-delete.
These are baseline state assertions, not recovered historical event IDs or times.
A baseline cannot reconstruct rows or operation evidence erased before enablement.

## Capture and retention

`pdpp_replica_operations` stores canonical profile operations with persisted
`(counter, writerId, operationId)` revisions and SHA-256 digests. Its counter is
separate from local query clocks and the Slice 1 journal. Every tail revision is
greater than the baseline watermark. Operations name the current derived
operation writer id from `pdpp_replica_writer_identity` (see the transport
document); before the first identity they keep the installation writer id and
never leave the device. The receiver advances this clock past observed remote
revisions. Clone/restore must call `rotateReplicaWriterIdentity` before new
writes.

Ingest and owner deletion capture full values or data-free tombstones. Replace
captures changed values and explicit deletions of every removed live key; absent
keys in a partial page never imply deletion. Registration, reset, deletion and
new generation-bound blob claims capture their own operations. Exact local retries
are inert, except a replace with source collection time can issue a new completion
assertion. Receipt removal emits `stream-invalidate`, including unchanged replaces
that drop their receipt. All capture runs inside the existing canonical transaction, so a failed
capture rolls back local rows, history, receipts, claims and revision allocation.

Pinned operation values, lifecycle evidence and verified blob bytes survive
canonical reset/deletion and history erasure. They are retained indefinitely in
this slice; no compaction or reclamation is implemented. Blob bytes are read through
`readPinnedBlobBytes`, separately from their wire descriptors. A descriptor alone
does not prove bytes were received or authorize a remote local claim.

## Completion dependencies

`stream-complete` carries the retained declaration binding, source collection time,
live count, snapshot digest and an exact list of `(writerId, operationId, digest)` dependencies. The dependency set
includes connection lifecycle evidence plus every captured record mutation for the
stream and blob claim in the current generation. Historical superseded mutations
remain dependencies so a partial delivery cannot masquerade as the completed run.
Native `completeStreams`, replace receipts and pre-existing baseline receipts use
this representation. `proof` preserves native snapshot proof and host-run time
basis, or the producer-asserted receipt's original null proof and time basis.
The top-level snapshot digest is exporter-computed integrity evidence and does
not promote a producer assertion to native proof. `selectStreamCompletion` uses
revision order over one stream/generation's completion and invalidation events;
reversed delivery cannot revive a removed receipt. Empty streams still depend on connection registration.

`hasCompletionDependencies` verifies the exact canonical operation hashes and
refuses missing or equivocated dependencies. It proves dependency coverage only.
A receiver must also validate declaration authority, lifecycle, merged live count,
snapshot digest, conflicts, and received blob bytes before claiming availability.
There is no remote-availability status in this slice. Dependencies use operation
IDs because transport batch IDs do not exist until the publisher frames operations.

## Paging and resume

`readBaselinePage` reads immutable membership and values. `readTailPage` starts
strictly above the watermark. Both use bounded keyset pages with exclusive sequence
offsets. Offsets identify local journal positions, never distributed winners.
Neither read advances durable progress. After a baseline page is durable at its
consumer, that consumer calls `acknowledgeBaselinePage(expected, next)`. This
compare-and-swap checkpoint accepts an identical acknowledgment retry and refuses
stale writers. The consumer owns its acknowledgment's truth; the storage API does
not attest remote persistence. Baseline reads without an explicit offset resume
from that checkpoint. A tail consumer must persist its own delivery checkpoint
with the eventual publisher; that publisher is outside this slice.

`rebaseline` (called when the writer identity changes) appends a new
current-state capture under the current writer, adds it to the baseline
membership, moves the checkpoint to just before it and the watermark to its
end. Earlier membership is never removed.

## Evidence and limits

`pdpp-replication-baseline.test.ts` exercises 1,205 live rows through frozen pages
while another SQLite handle updates, deletes, replaces, resets and deletes
connections. It checks every permutation of a small baseline/delete/new-upsert
fixture and reversed/interleaved large deliveries through the existing pure merge
planner. It verifies completion dependency omissions and altered hashes, unchanged
local state at enablement, and rollback for every capture hook. Subprocess SIGKILL
before and after baseline, update, replace, lifecycle, blob, completion and
checkpoint commits verifies WAL recovery and stable resume.

These tests do not prove power-loss durability, disk-full recovery, real device
replication, receiver authorization, transport completeness, or production-scale
latency and storage cost. Baseline construction holds the SQLite write fence for
the entire scan and stores full pinned values and bytes. That cost must be measured
before production enablement.
