# Experimental Lite record replication

`createLiteReplicaWorker` connects the canonical outbox and import port to the
shared DPv2 fragment codec, finalized evidence and immutable-slot delivery rules.
It is disabled unless `enabled: true`. Constructing a disabled worker performs
no persistence or network work. The normal Lite bootstrap binds a host sidecar
only when `replication.enabled === true`; it adds no implicit scheduler.

The trusted host supplies the same owner, signing, storage and feed capabilities
as existing Lite sync. `createLiteReplicaHostTransport` composes them with the
finalized-evidence adapter. The host supplies bounded HTTP/RPC transports. No
collector credential, wallet fallback, grant replication or issuer change is
introduced. Both devices still need trusted connection provisioning and retained
declarations before their imported records become readable.

## Durable handoff and interruption

All transport metadata and retained fragment frames use `transport/*` keys in the
same owner-partitioned native database as canonical rows. Retention stores a batch
manifest and advances its source cursor atomically. Removing acknowledged source
outbox pointers happens later; a lost acknowledgment cannot lose the manifest.

Preparation replays immutable native blob streams and checks the retained payload
digest and length. Each prepared fragment is persisted before the batch's prepared
marker. No network call runs until that marker commits. Retries use the committed
ciphertext and immutable version-one scope. Shared delivery helpers reconcile
Gateway responses against finalized chain commitments before any retry or import.

Inbound fragments remain in bounded native values. Assembly, SHA-256 and payload
decoding stream through those values; a blob is inspected completely before a
second pass stages it through the native blob port. Canonical import, blob attach,
predecessor check, writer/sequence uniqueness and the transport receipt share one
native transaction through the trusted `withinTransaction` import hook. A rejected
fork leaves neither canonical rows nor a transport receipt.

A durable 30-second lease fences overlapping WebViews. A replacement can resume
after expiry. An older runtime cannot write after the replacement takes the lease,
including after an outstanding encryption or network call returns. The transport
writer rotates when the native installation watermark changes the canonical writer.
Pending batches retain their original writer, sequence and exact prepared bytes.
After finalized publication, the worker removes its redundant ciphertext copy.
After import, canonical operations, attached blob bytes and the transport receipt
commit together with deletion of the redundant inbound content. Failed staging is
discarded through the existing native `canonical.stage.abort` operation, which
preserves published references. Quarantined evidence remains available for repair.

## Bounds and remaining limits

- Native blob frames are at most 128 KiB. Outbound plaintext chunks are 32 KiB;
  actual encrypted fragments must fit 128 KiB. Native JSON values remain below
  256 KiB, with large inbound fragment content split into 64 KiB base64 strings.
- Each worker phase advances one native keyset page per cycle, at most 100 entries
  and 512 KiB of values. Durable rotating cursors prevent early completed or failed
  rows from hiding later work. Completed metadata remains in the scanned prefixes,
  so delivery latency grows with retained history; a pending-work index is still
  needed before promotion. A cycle can defer work; it does not establish that
  the owner's complete inventory has been discovered.
- The host caps incoming encrypted fragments at 8 MiB. This admits the existing
  Node worker's default 4 MiB payload chunks, including base64/encryption overhead.
  A fragment is buffered for SDK decryption and codec validation; a source record
  collection or complete blob payload is not assembled. Phone peak heap remains
  unmeasured. Fragments above the supported bound are quarantined explicitly.
- Replica envelopes remain bounded by the canonical store's 192 KiB admission
  contract. Lite packs outbox operations with their wrapper and revision overhead.
  When transport admission is enabled, a single oversized local operation is
  refused before acknowledgment. An older operation saved with transport disabled
  can exceed the wrapper-inclusive limit and stop outbound progress with an error;
  migration or quarantine policy remains unresolved. A Node envelope above that bound remains pending
  and is reported; fragmentation does not make it admissible. General streaming
  record imports and changing Node batch packing are separate work.
- Packing also respects the existing native staging limits: four blob handles
  and 256 MiB per batch. Local oversized blobs are refused before staging. Remote
  batches above those limits are quarantined before staging, and sequence forks
  are quarantined before payload replay. At most four blob-read passes follow
  inspection; this cost has not been measured on a phone.
- The existing 100,000-fragment wire limit, lifecycle merge bound and pathological
  equivocation limits still apply. Original canonical history is not compacted or
  deleted when the worker removes redundant transport copies.

## Proof

`pdpp-lite-replication-transport.test.ts` runs Lite over the crash fake matching the
native transaction/value/frame contract, against the real Node SQLite store and
receiver. It covers both directions, restart, lost PUT/register/GET responses,
interrupted preparation/import commits, sequence forks, installation writer
rotation, a stalled runtime losing its lease, streamed binary data and default
Node fragments larger than one native value. A case uses real SDK encryption and
the finalized-evidence adapter. The existing Node transport suite stays unchanged.

`scripts/pdpp-replica-lite-live.ts` registers fresh dev servers for a random owner,
exchanges records over the real dev Gateway/storage/chain and checks rows and
versions after restarting both runtimes. It reads no account or environment files.
The Lite persistence in that script is a Node fake; it does not prove Android
process kills, WebView memory, native filesystem durability or Account grant reads.
