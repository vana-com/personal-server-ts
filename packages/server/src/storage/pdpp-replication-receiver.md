# Internal PDPP replica receiver

`createReplicaReceiver` is an internal SQLite port. It is not mounted in the server bootstrap. The host supplies the database's owner, a replica-specific credential verifier, and retained declaration bindings with validators for their exact schemas. The verifier must establish the owner independently of the envelope and must refuse collector credentials. This slice supplies no credential issuance or network transport.

Call `store.replication.beginBaseline` before importing. Its immutable owner binding must match the receiver. The receiver combines original local baseline/tail operations with durably retained imports, then calls the core `planReplicaMerge`. Imported operations retain their original writer, operation ID, counter and payload. They never enter either outbound journal. The local Lamport clock advances beyond observed imports before a later local mutation.

## Local authority

The export profile uses the canonical instance ID as the logical connection ID. Import requires a locally registered connection with the same source and acquisition method. Imported registration evidence cannot create that mapping or change its method. An absent mapping or declaration remains pending; provision the dependency through the host and call `retry` with replica credentials. A source or method mismatch rejects the transaction. A complete reset chain can advance the registered connection's generation; older record operations remain suppressed. Connection deletion dominates record operations.

The declaration resolver is trusted host configuration, not connector metadata. It must bind source, declaration digest, version, stream, primary key, semantics and schema digest to the retained document and exact validator. The receiver does not fetch declarations or accept schemas from incoming operations.

## Commit and retry

Schema migration 14 adds an append-only received-operation set and retained content-addressed bytes. Imports use an immediate SQLite transaction: operation retention, Lamport observation, lifecycle changes, canonical versions/history, blob claims and completion receipts commit together. Failed writes roll back the entire import. An acknowledgement is the return from the port; a caller that crashes before recording it can replay the envelope after restart. Unchanged winners allocate no record version, history entry or outbound mutation.

All operation variants are retained, including losing values, pending dependencies and integrity conflicts. The core merge policy selects mutable winners and tombstones, permits later resurrection, and quarantines conflicting append-only keys. Quarantine removes the current value from canonical reads while preserving the operation evidence. Reconciliation recomputes the plan from the retained set; it has no destructive compaction.

Blob-bearing winners require an exact same-connection/current-generation claim, matching record reference, descriptor, SHA-256, byte count and verified bytes. Missing dependencies leave the record unavailable and pending. Corrupt supplied bytes reject the transaction. The canonical blob table and reverse index are populated so existing grant-relative record and blob authorization remains authoritative.

Completion receipts require exact dependency IDs and operation digests, a valid declaration/current generation, no relevant merge issues, matching live count and a recomputed snapshot digest. JSON row arrival alone cannot prove completion. Native and producer-asserted proof provenance remains distinct.

## Compatibility and remaining work

`packages/core/src/sync/pdpp-import.ts` is unchanged. Its `$pdpp` metadata path still lacks method authority and cannot acquire replica authority by adding fields. Its transient/permanent compatibility decisions remain in place.

The tests use fresh on-disk SQLite databases, existing HTTP grant reads, and process termination around transaction commit. They do not establish real DPv2 delivery, credential issuance, mobile or lite persistence, retention bounds, or production readiness. Publication/download belongs to Slice 6. The provisional core conflict policy remains unchanged.
