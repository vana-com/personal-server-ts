# Internal PDPP replica receiver

`createReplicaReceiver` is an internal SQLite port. It is not mounted in the server bootstrap. The host supplies the database's owner, a replica-specific credential verifier, and retained declaration bindings with validators for their exact schemas. The verifier must establish the owner independently of the envelope and must refuse collector credentials. This slice supplies no credential issuance or network transport.

Call `store.replication.beginBaseline` before importing. Its immutable owner binding must match the receiver. The receiver combines original local baseline/tail operations with durably retained imports, then calls the core `planReplicaMerge`. Imported operations retain their original writer, operation ID, counter and payload. They never enter either outbound journal. The local Lamport clock advances beyond observed imports before a later local mutation.

## Local authority

The export profile uses the canonical instance ID as the logical connection ID. Import requires a locally registered connection with the same source and acquisition method. Imported registration evidence cannot create that mapping or change its method. An absent mapping or declaration remains pending. After the host provisions a mapping, call `retry` with replica credentials. After trusted declaration documents or validators change, call `reconcileDeclarations` instead (see below). A source or method mismatch rejects the transaction. A complete reset chain can advance the registered connection's generation; older record operations remain suppressed. Connection deletion dominates record operations.

The declaration resolver is trusted host configuration, not connector metadata. It must bind source, declaration digest, version, stream, primary key, semantics and schema digest to the retained document and exact validator. The receiver does not fetch declarations or accept schemas from incoming operations.

## Commit and retry

Schema migration 14 adds an append-only received-operation set and retained content-addressed bytes. Imports use an immediate SQLite transaction: operation retention, Lamport observation, lifecycle changes, canonical versions/history, blob claims and completion receipts commit together. Failed writes roll back the entire import. An acknowledgement is the return from the port; a caller that crashes before recording it can replay the envelope after restart. Unchanged winners allocate no record version, history entry or outbound mutation.

All operation variants are retained, including losing values, pending dependencies and integrity conflicts. The core merge policy selects mutable winners and tombstones, permits later resurrection, and quarantines conflicting append-only keys. Quarantine removes the current value from canonical reads while preserving the operation evidence. Durable corruption-quarantine fences also refuse ordinary collector writes to the affected key in the same generation or to the affected connection. Source-binding ambiguity uses the separate retained-fact read policy described below when composed with hardening. Reconciliation recomputes the plan from the retained set; it has no destructive compaction.

Blob-bearing winners require an exact same-connection/current-generation claim, matching record reference, descriptor, SHA-256, byte count and verified bytes. Missing dependencies leave the record unavailable and pending. Corrupt supplied bytes reject the transaction. The canonical blob table and reverse index are populated so existing grant-relative record and blob authorization remains authoritative.

Completion receipts require exact dependency IDs and operation digests, a valid declaration/current generation, no relevant merge issues, matching live count and a recomputed snapshot digest. JSON row arrival alone cannot prove completion. Native and producer-asserted proof provenance remains distinct.

## Compatibility and remaining work

`packages/core/src/sync/pdpp-import.ts` is unchanged. Its `$pdpp` metadata path still lacks method authority and cannot acquire replica authority by adding fields. Its transient/permanent compatibility decisions remain in place.

The tests use fresh on-disk SQLite databases, existing HTTP grant reads, and process termination around transaction commit. They do not establish real DPv2 delivery, credential issuance, mobile or lite persistence, retention bounds, or production readiness. Publication/download belongs to Slice 6. The provisional core conflict policy remains unchanged.

## Provisional visibility

`enabled: true` opts this internal receiver into staging and preview. The transport worker explicitly sets this switch from its own existing `enabled` flag; an omitted receiver switch alone does not enable staging. A disabled worker never downloads, stages, promotes, or acknowledges a batch. The original trusted `import` API retains its existing confirmed-import semantics.

`stage({credential,id,envelope,blobs})` persists an immutable pending batch in `pdpp_replica_pending_batches` with binary bytes in separate BLOB rows. It checks envelope structure, owner/mapping and supplied content hashes. The transport caller must first decrypt, validate fragment/payload bindings and validate blob descriptors. No pending operation enters the received operation set, canonical tables, export journals, history or convergence/Lamport clocks.

`readVisibleRecords({reader,connectionId,stream})` returns stored-record models and explicit pending removals. A pending removal has `deleted: true`, its deletion time, and an empty internal data object. HTTP responses omit that empty data object. `reader` defaults to `grant`. One core `ReplicaVisibilityPolicy` governs record, page, stream-summary and blob reads via `readStore({reader})`. The default owner mode includes pending; the default grant mode is confirmed-only. Change either policy member to `include-pending` or `confirmed-only` without changing the merge engine. Quarantined copies never appear in ordinary record or blob reads; owner diagnostics are separate (below). The authenticated host chooses reader identity; request parameters must not choose it.

The owner view is a sparse overlay on canonical rows, maintained when evidence or canonical state changes. It persists only keys whose owner-visible state differs from canonical: pending values, marked pending removals, and keys that operation-ID equivocation hides. Without pending evidence or an operation-ID variant among a key's merge inputs, owner preview equals canonical by definition and nothing is stored for that key. A compatible registration already in force counts as no change. The overlay uses the same core merge policy and validates binary availability before exposing a pending winner. Retained operations are read in place through expression indexes on `pdpp_replica_operations` and `pdpp_replica_received`; the view stores no copy of operation JSON or canonical rows. Pending operations live in `pdpp_replica_view_pending` only while their batch is pending. A canonical write or retained record operation marks a key for reconciliation only when the key has an overlay row, its connection has pending work or a variant, or its binding is deleted. Point reads check the overlay key and then the canonical key. Pages merge one bounded canonical keyset page with one bounded overlay keyset page per connection; both are index seeks. A canonical row that an overlay row replaces is consumed but not returned, so a page can be short or empty while `hasMore` is true. Stream summaries read the owner preview's latest row from the summary table: flush derives it at write time for streams whose overlay rows or canonical rows changed. A summary over a stream with quarantined keys still recomputes it at read time. Reads do not replay the operation log or rebuild pending batches. Pending upserts and removals obtain `confirmation: "not yet confirmed"` and `visibility: "pending"` from the core visibility-policy component. A summary affected by pending removals remains present with its live count and the same marker, even if that count is zero. Canonical responses omit pending metadata.

Replica-facing pagination binds the reader, the scope, and for each connection: its read mode (canonical, preview, local projection or hidden), its reset fence, its integrity epoch when the store provides `replicaIntegrityEpoch(connectionKey)`, and the revisions of the requested stream in that mode. The mode's summary triggers advance a stream revision only when a stored row of that stream changes. Preview pages bind the canonical and overlay revisions; confirmed-only pages bind only the canonical revision, so pending-only churn never moves them. Writes to another stream or connection preserve a cursor. A binding or lifecycle change advances every stream revision of its connection. Without the epoch capability, the reset fence alone covers integrity changes; the synthesis lane's epoch covers quarantine facts without view triggers on those tables. The cursor revision carries the view layout version, so cursors from an older layout expire, and a view cursor never continues on the canonical store path. A continuation after a view change expires explicitly; it must not silently claim the previous snapshot while reading the current one. Local lifecycle evidence, concurrent edits and #426 ordering remain inputs to materialization. Preview does not advance canonical history or convergence clocks.

`retry({credential})` reconciles canonical state and drains the view's dirty queues. With no new evidence it rewrites no overlay row and advances no cursor revision. `reconcileDeclarations({credential})` is the explicit host call after trusted declaration documents or validators change: it reconciles canonical state and re-derives every overlay key of connections with overlay rows, pending work or variants. Neither call is a periodic full rebuild. The canonical reconcile inside `retry` still reads the retained operation set; making it incremental belongs to the transport scheduling lane.

The view layout is derived state. Construction drops an older layout (including the 70d52db0 full-copy view) and rebuilds the sparse view inside its write transaction: canonical stream summaries, active pending batches, confirmed operation-ID variants and deleted bindings. Reads never build or migrate it.

`promote({credential,id})` is a **trusted host finality hook**, not a standalone proof verifier. The transport host must recheck every retained fragment against pinned finalized #433 evidence before calling it. Promotion imports the stored batch, updates clocks/history/canonical state, marks it confirmed and removes redundant pending binary rows in one SQLite transaction. The transport wraps promotion and its durable acknowledgement in the same transaction. A failed commit leaves the pending preview available; repeated promotion does not allocate more history. `quarantine({credential,id,reason})` removes provisional visibility without importing. Finalized divergent commitments and later finalized versions use this hook.

Canonical store reads, export APIs, authorization selection and change feeds continue to read canonical state. Resource reads go through the host's reader capability (below). This change does not enable production bootstrap scheduling or expose an endpoint to call the trusted hooks. Cardinality tests bound read work as retained data and pending backlogs grow. Native-device memory and crash behavior remain separate enablement checks.

## Reader capability

`createApp` requires `pdpp.reads(reader)`. It is the one reader port for every canonical-derived response; its type (`PdppReplicaReadStore`) requires every method a surface calls, so a host cannot leave one surface on the raw store. A host without a receiver passes `() => store` (bootstrap does this today, so default-off behaviour does not change). A host with a receiver passes `(reader) => receiver.readStore({ reader })`. The app derives the reader class from the authenticated token; query parameters cannot select owner visibility. Each `readStore` call selects its read branch and reads its rows inside one SQLite read snapshot. Bytes served through the adapter pass one integrity check against the visible descriptor, whether they are canonical, received or pending.

```ts
const reads = (reader: ReplicaReader) => receiver.readStore({ reader });
createApp({ ...appDeps, pdpp: { ...pdppDeps, reads } });
createLegacyScopeView({
  ...viewDeps,
  records: legacyScopeRecords({ ...pdppDeps, reads }),
});
```

| Surface                                                                            | Reader path                                                                                                                                                | Test                                                                         |
| ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `GET /v1/streams` (existence, counts, recency)                                     | token reader `listStreams`                                                                                                                                 | `app.replica-reads.test.ts`                                                  |
| `GET /v1/streams/:stream/records` pages                                            | token reader `listRecords`                                                                                                                                 | `app.replica-reads.test.ts`, `pdpp-replica-visibility-sparse.test.ts`        |
| same path, `changes_since`                                                         | token reader `changesSince`                                                                                                                                | `app.replica-reads.test.ts`                                                  |
| `GET /v1/streams/:stream/records/:id`                                              | token reader `getRecord`                                                                                                                                   | `app.replica-reads.test.ts`                                                  |
| `GET`/`HEAD /v1/blobs/:blobId` (metadata, references, bytes)                       | token reader `getBlobMeta`, `findBlobReferences`, `getRecord`, `getBlobBytes`; canonical bytes from the host's `readBlobBytes` after the reader authorizes | `app.replica-reads.test.ts`, `pdpp-pending-visibility.test.ts`               |
| `GET /v1/data`, `GET /v1/data/:scope` (latest canonical body, listing, completion) | confirmed (grant) reader for every caller, through `legacyScopeRecords`                                                                                    | `app.replica-reads.test.ts`                                                  |
| `GET /pdpp/instances/:instance/binding` `empty`                                    | excluded: store emptiness                                                                                                                                  | `app.replica-reads.test.ts` pins `empty: true` for a pending-only connection |
| file surfaces (see below)                                                          | excluded: no replica data                                                                                                                                  | none needed                                                                  |

The legacy compatibility view cannot tell owner from grantee, and it records durable coverage verdicts and takeover receipts. It therefore reads canonical rows through the confirmed reader: pending rows never feed it, and a source-conflicted connection projects nothing (`/v1/data/:scope` refuses with `no_synced_data`). Registry facts (binding, connection list, arrival order) stay on the store; they select the connection, not what it shows. Completion receipts describe canonical rows, so `readStore` returns none for a reader that sees a preview, a local-only or a hidden connection.

The binding route's `empty` is the binding/reset precondition that the store enforces: no canonical row or history for the instance. It is not visible existence. A pending-only connection reports `empty: true`, and a source conflict does not change it. Making it reader-aware would let the route disagree with the fence that the store applies to method binding.

File surfaces read the file `DataStoragePort` (data files and the index), the additions ledger, lineage and coverage-verdict ledgers: `/v1/data/:scope?fileId|at|view=stored`, versions, lineage, additions, takeover diagnostics, MCP and enclave MCP, enclave raw-read jobs, fleet readiness, derivative source reads and sync. The receiver cannot put received, pending or conflicted data into those stores. Its dependencies are the SQLite database, the record store and its own credentials; every write statement in the receiver, the view, the replication SQLite module and the transport targets a `pdpp_*` table. Coverage verdicts are written only by the legacy view, which now reads through the confirmed reader.

The record and blob route factories take the same capability as `reads`. `createApp` always supplies it. A factory mounted without a host (tests) reads its `store` for every token class.

The list route reads another store page only while the grant filter drops rows. A grant cursor must stay on a row the grant may see, so that loop rebinds the cursor to the last visible row. Its work therefore still grows with rows outside a grant's `time_constraint` or `resources`; that is unchanged here. When the last store page dropped nothing, the route returns the reader's page, which can be short, with the reader's own cursor. List and single-record JSON responses expose `confirmation: "not yet confirmed"` on provisional rows. Change feeds continue to report confirmed durable history; owner previews allocate no history positions.

Preview tuple ordering and cursor comparisons use SQLite-compatible UTF-8 BINARY
comparison, including case, non-ASCII and supplementary-plane keys. They do not
apply locale collation or normalize timestamp text; this matches canonical SQL
ordering even for equivalent timestamps with different permitted encodings. Replica-facing pages add the connection instance as a final tie-breaker so equal timestamps and keys across connections cannot skip a record.

## Scheduling and conflicting copies

Visibility reads consume local snapshots. They do not refresh evidence, schedule network work, or own retry counters. The transport worker owns durable due selection, waiting/error outcomes, cooldowns and complete-batch progress. Head hints may wake waiting work but cannot bypass an error deadline or authorize promotion. Finalized members, predecessor checks and atomic acknowledgment remain host requirements.

Distinct-writer edits retain the provisional tuple order. `receiver.copies` retains distinct copies of a batch and promotes only a copy whose commitments match eligible finalized facts. Multiple unproven copies become `copy_conflict`; contradictory finalized facts make the batch terminal. The legacy pending row mirrors the single pending copy, and bytes use `(id, blobId)` custody. A bare batch ID cannot select among multiple retained copies. See the owner diagnostics below and [the original pending-copy decision](../../../../docs/261021-replica-pending-copy-decision.md) for context.

## Account conflict visibility

The shared policy includes `conflicted`. An externally recorded source-binding ambiguity hides the entire connection from grant readers. Owners see only the latest known local journal values in their current local generation, marked `visibility: "conflicted"` and `status: "account conflict"`. Received winners and pending values do not establish local provenance. Latest local tombstones suppress older local data; unknown legacy provenance is hidden.

The hardening lane owns the monotone conflict fact and its cursor fence. Recording ambiguity retains stored rows, blob claims and all received evidence. This reader adapter performs no selective withdrawal and supplies no owner-resolution operation. Authenticated corruption quarantine remains separate and always hides the affected content, even from the local owner projection. Both paths consume the store's shared quarantine predicate.

The hardening migration must run before receiver construction. The standalone adapter detects the fact-table capability once; an absent table means there are no facts to read in that checkout. It is not a way to resolve a conflict.

The replica read port also owns `changesSince`. Canonical history lacks authoritative local provenance for an ambiguous connection, so its change feed is hidden for both readers. Owners use the marked current local projection through point reads and pages. The canonical store validates the original scoped reset fence before the adapter narrows the history instances; pre-conflict cursors expire. When the store exposes `replicaIntegrityEpoch`, the adapter binds the epoch of every requested connection into changes page cursors and session tokens, so an epoch move (a connection quarantine, a terminal batch) expires both with HTTP 410. This does not delete history or add pending records to the change feed.

## Owner copy-conflict diagnostics

The owner reader exposes two paginated methods:

- `listCopyConflicts({ instanceIds?, connection?, stream?, limit?, cursor? })`
  discovers conflicts without decoding values.
- `readCopyConflicts(id, instanceIds?, { limit?, cursor? })` reads one batch's
  conflicts with bounded values.
  It also accepts `{ idDigest, copyKey }` instead of the full `id`, returning that
  one conflicting copy. `idDigest` is the lowercase SHA-256 hex digest of the full
  ID's UTF-8 bytes; `copyKey` is the existing fixed-size copy hash.

Both return `{ data, hasMore, nextCursor? }`. Each entry has
`{ id, copyKey, reason, visibility: "conflicted", status, connections, streams }`.
Connections and streams are sorted, distinct arrays. For `copy_conflict`, status
is `"copy conflict"` and diagnostic `values` contains every decoded operation,
including connection lifecycle, blob claims, stream invalidation and completion,
and record upserts and deletes. For `finalized_conflict`, status is
`"integrity conflict"`; values and omission flags are absent. Corrupt rejects are
separate and never appear. Grant readers expose neither method at runtime.
Grant and union reader types expose neither method. Each call uses the adapter's
SQLite read snapshot.

The owner HTTP routes are:

- `GET /v1/replica/copy-conflicts?connection=…&stream=…&limit=…&cursor=…`
- `GET /v1/replica/copy-conflicts/:id?limit=…&cursor=…`
- `GET /v1/replica/copy-conflicts/:idDigest?copyKey=…`

URL-encode the batch identity as one path segment. Both return
`{ object: "list", data: [...], has_more, next_cursor? }`. Filters are optional.
Every connection touched by a copy must be within the token's currently owned
scope, for discovery, diagnostics and counts alike. A connection filter does not
narrow this whole-copy authorization check. Paired connection and stream filters
must match the same connection's effects. A missing or out-of-scope batch returns
an empty page. Both routes require `AppDeps.pdpp.reads("owner")` with both methods;
a host without that capability returns 404. Client/grant and foreign-owner tokens
get 403. Missing or inactive authentication uses the existing PDPP errors.
The same server-owner gate controls stream counts, including stream entries that
exist only because of conflicting copies.

Pages default to 25 entries, with limits from 1 to 100. Ordering is by
`(idDigest, copyKey)` using SQLite binary text order. The bounded keyset cursor is at
most 4096 bytes and binds the query, endpoint, whole token scope, declarations and
view layout. Invalid or mismatched cursors get HTTP 400; an expired layout gets 410
with `"Copy conflict cursor has expired"`. Malformed digest references get HTTP 400
`invalid_request`. Authorization is checked anew on every page. This is a live catalog, not a
snapshot across requests: new keys before the cursor require a new walk, and
state changes can remove entries between pages. Cursors contain only the two
fixed-size hashes, so even a long batch identity cannot enlarge them. The digest
index supports direct reference lookup and continuation without loading long IDs
into the reader.

Every listed identifier is limited to 1024 UTF-8 bytes. A longer batch ID is
represented by `id: idDigest` with `idTruncated: true`; use that `id` and the listed
`copyKey` on the reference route. The same owner scope check applies to both forms.
Connection and stream arrays contain at most 64 names each. A longer name keeps a
UTF-8-safe prefix plus an ellipsis within the same byte limit, and truncated names
or arrays set `metadataTruncated: true`. These are display limits: whole-copy
authorization, stream filters and counts use the complete effects. Decoded values
retain complete operations under their separate per-copy byte limit.

Each value-bearing copy is limited to 512 operations, 4 MiB of UTF-8 JSON values,
and an 8 MiB encoded envelope. A normal fifty-record batch with 6 KiB records fits.
An oversized copy keeps its marker with `valuesOmitted: true` and
`valuesOmittedReason: "operation_limit" | "byte_limit"`; it does not cause a 413
or hide other copies. Operation count, stored values size and envelope size are checked before loading or parsing
values. Diagnostic pages use an 8 MiB response budget, reserving space for the
cursor and wrapper; full values continue on the next page. Finalized markers
never load former payloads.

Owner `listStreams` entries have `copyConflicts: n` (HTTP: `copy_conflicts`). This
counts distinct whole copies visible to the same token whose effects touch that
stream. Core's `replicaOperationAffectedStreams` defines the effect of each kind:
record upserts/deletes and stream invalidation/completion affect their own stream;
connection reset/delete affect every currently declared stream of that connection;
blob claims and connection registration affect no stream for counting. All kinds
remain listed under their connection. A copy with several operations or connections for one stream
counts once. This is the number of distinct discovery entries returned by a walk
filtered to that stream, including finalized markers and omitted-value markers.
A connection with no declared streams still has discoverable copies through the
unfiltered or connection-filtered catalog; no stream is invented for its count.
Conflicts can produce a stream entry with zero records and null recency. Ordinary
streams report zero; grants and non-server-owner tokens never receive this field. Disabling pending previews
does not disable diagnostics.

View layout 12 stores one per-copy projection of sorted `(connection, operation)`
effects, retaining only kind and declaration stream, plus reason and
size facts. One owner projection interprets these facts for scope, paired filters,
markers, values and counts. The visibility policy supplies the SQL reason list and
the production visibility decision. Triggers maintain grouped counts and reverse
connection indexes in the write transaction, with `NOT EXISTS` insertion guards.
Counts include only projections with non-null ID digests, exactly the set that
catalog seeks can return. A digest becoming available adds the copy to its count;
deleting an unready projection does not decrement it. Thus a write that skips
flush cannot create a counted but undiscoverable copy.
The receiver transaction fills new ID digests through `view.flush`; the digest
index also serves its null-digest work queue. Construction fills rebuilt digests
before exposing the reader. No read hashes retained IDs or mutates the projection.
Listing uses bounded indexed seeks per eligible effect group; counts read each
group once. Neither scans retained copies nor decodes envelopes for discovery or
counts. Work grows with requested connections and distinct effect groups, not
repeated copies in a group. Construction rebuilds the projection from retained
copies when upgrading. Composite primary keys avoid duplicate rowid indexes. The
catalog and digest indexes add two fixed 4 KiB pages to the empty sparse view (33 pages total),
independent of the canonical record count.

Conflicting values never enter the reducer or canonical materialization. Page and
point reads retain the confirmed predecessor until promotion. A terminal batch
withdraws the affected connections through the existing integrity fence, so both
readers lose those record values and blob references. Diagnostic markers and
counts remain available to the owner.
