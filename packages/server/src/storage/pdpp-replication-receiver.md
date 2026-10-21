# Internal PDPP replica receiver

`createReplicaReceiver` is an internal SQLite port. It is not mounted in the server bootstrap. The host supplies the database's owner, a replica-specific credential verifier, and retained declaration bindings with validators for their exact schemas. The verifier must establish the owner independently of the envelope and must refuse collector credentials. This slice supplies no credential issuance or network transport.

Call `store.replication.beginBaseline` before importing. Its immutable owner binding must match the receiver. The receiver combines original local baseline/tail operations with durably retained imports, then calls the core `planReplicaMerge`. Imported operations retain their original writer, operation ID, counter and payload. They never enter either outbound journal. The local Lamport clock advances beyond observed imports before a later local mutation.

## Local authority

The export profile uses the canonical instance ID as the logical connection ID. Import requires a locally registered connection with the same source and acquisition method. Imported registration evidence cannot create that mapping or change its method. An absent mapping or declaration remains pending; provision the dependency through the host and call `retry` with replica credentials. A source or method mismatch rejects the transaction. A complete reset chain can advance the registered connection's generation; older record operations remain suppressed. Connection deletion dominates record operations.

The declaration resolver is trusted host configuration, not connector metadata. It must bind source, declaration digest, version, stream, primary key, semantics and schema digest to the retained document and exact validator. The receiver does not fetch declarations or accept schemas from incoming operations.

## Commit and retry

Schema migration 14 adds an append-only received-operation set and retained content-addressed bytes. Imports use an immediate SQLite transaction: operation retention, Lamport observation, lifecycle changes, canonical versions/history, blob claims and completion receipts commit together. Failed writes roll back the entire import. An acknowledgement is the return from the port; a caller that crashes before recording it can replay the envelope after restart. Unchanged winners allocate no record version, history entry or outbound mutation.

All operation variants are retained, including losing values, pending dependencies and integrity conflicts. The core merge policy selects mutable winners and tombstones, permits later resurrection, and quarantines conflicting append-only keys. Quarantine removes the current value from canonical reads while preserving the operation evidence. Durable quarantine fences also refuse ordinary collector writes to that key in the same generation, or to a connection with conflicting identity evidence. Reconciliation recomputes the plan from the retained set; it has no destructive compaction.

Blob-bearing winners require an exact same-connection/current-generation claim, matching record reference, descriptor, SHA-256, byte count and verified bytes. Missing dependencies leave the record unavailable and pending. Corrupt supplied bytes reject the transaction. The canonical blob table and reverse index are populated so existing grant-relative record and blob authorization remains authoritative.

Completion receipts require exact dependency IDs and operation digests, a valid declaration/current generation, no relevant merge issues, matching live count and a recomputed snapshot digest. JSON row arrival alone cannot prove completion. Native and producer-asserted proof provenance remains distinct.

## Compatibility and remaining work

`packages/core/src/sync/pdpp-import.ts` is unchanged. Its `$pdpp` metadata path still lacks method authority and cannot acquire replica authority by adding fields. Its transient/permanent compatibility decisions remain in place.

The tests use fresh on-disk SQLite databases, existing HTTP grant reads, and process termination around transaction commit. They do not establish real DPv2 delivery, credential issuance, mobile or lite persistence, retention bounds, or production readiness. Publication/download belongs to Slice 6. The provisional core conflict policy remains unchanged.

## Provisional visibility

`enabled: true` opts this internal receiver into staging and preview. The transport worker explicitly sets this switch from its own existing `enabled` flag; an omitted receiver switch alone does not enable staging. A disabled worker never downloads, stages, promotes, or acknowledges a batch. The original trusted `import` API retains its existing confirmed-import semantics.

`stage({credential,id,envelope,blobs})` persists an immutable pending batch in `pdpp_replica_pending_batches` with binary bytes in separate BLOB rows. It checks envelope structure, owner/mapping and supplied content hashes. The transport caller must first decrypt, validate fragment/payload bindings and validate blob descriptors. No pending operation enters the received operation set, canonical tables, export journals, history or convergence/Lamport clocks.

`readVisibleRecords({reader,connectionId,stream})` returns live stored-record models. `reader` defaults to `grant`. One core `ReplicaVisibilityPolicy` governs record, page, stream-summary and blob reads via `readStore({reader})`. The default owner mode includes pending; the default grant mode is confirmed-only. Change either policy member to `include-pending` or `confirmed-only` without changing the merge engine. Quarantined batches are never visible. The authenticated host chooses reader identity; request parameters must not choose it.

Owner preview calls the same core `planReplicaMerge` over canonical and pending operations, combines its decisions with current canonical rows, and validates binary availability. It does not clone the database or write scratch canonical/convergence state. Pending winners carry `confirmation: "not yet confirmed"` and `visibility: "pending"`; canonical responses omit those fields. Preview-only rows have version zero until canonical history allocates their first version. Local lifecycle evidence, concurrent edits, and #426 ordering remain inputs to that merge. Preview pagination uses the existing tuple cursor format and validates canonical epoch/order/reset fences. Hidden-pending and disabled page reads return the original store page exactly.

`promote({credential,id})` is a **trusted host finality hook**, not a standalone proof verifier. The transport host must recheck every retained fragment against pinned finalized #433 evidence before calling it. Promotion imports the stored batch, updates clocks/history/canonical state, marks it confirmed and removes redundant pending binary rows in one SQLite transaction. The transport wraps promotion and its durable acknowledgement in the same transaction. A failed commit leaves the pending preview available; repeated promotion does not allocate more history. `quarantine({credential,id,reason})` removes provisional visibility without importing. Finalized divergent commitments and later finalized versions use this hook.

Canonical store reads, export APIs, legacy projections, authorization selection and change feeds continue to read canonical state. Hosts that explicitly want policy-driven resource reads supply the receiver's read adapter. This change does not enable production bootstrap scheduling or expose an endpoint to call the trusted hooks. Pending backlog latency and large-device memory limits have not been measured by these focused tests.

The Node record and blob route factories accept the same optional adapter:

```ts
const replicaReads = (reader: ReplicaReader) => receiver.readStore({ reader });
pdppRecordsRoutes({ ...recordDeps, replicaReads });
pdppBlobsRoutes({ ...blobDeps, replicaReads });
```

Each factory derives the reader class from the authenticated token. Query parameters cannot select owner visibility. The adapter preserves the route's existing instance, field, resource and time restrictions. List and single-record JSON responses expose `confirmation: "not yet confirmed"` on provisional rows. Blob authorization and bytes use that same reader view. With no adapter, the factories retain their existing canonical reads. Change feeds continue to report confirmed durable history; owner previews allocate no history positions. The separate consent acceptance lane must inject these adapters into its test host before claiming RS pending-visibility coverage.

Preview tuple ordering and cursor comparisons use SQLite-compatible UTF-8 BINARY
comparison, including case, non-ASCII and supplementary-plane keys. They do not
apply locale collation or normalize timestamp text; this matches canonical SQL
ordering even for equivalent timestamps with different permitted encodings.
