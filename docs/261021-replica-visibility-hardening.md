# Replica visibility hardening

Scope: #438 F1–F3 against `deebf29d303d5c5ef08a8e1b54f3869400708636`, and the Opus r1 review of `70d52db0` (P1-1, P2-2 to P2-6, Lite nits). This remains a draft on #437. #426's provisional ordering and single-issuer authority are unchanged.

## Design

F1 and F3 had the same owner: read-time reconstruction combined current canonical rows, retained operations and pending batches after a different cursor had already been validated. The replacement maintains visibility state on writes. One page implementation owns query ordering, reader/scope binding and revision validation. It expires a changed view rather than silently combining snapshots. Confirmed-only cursors do not track hidden pending churn.

Both platforms keep a sparse durable overlay over canonical rows. The overlay holds only keys whose owner-visible state differs from canonical: pending values, marked pending removals, and keys hidden by operation-ID equivocation. Without pending evidence or an operation-ID variant among a key's merge inputs, owner preview equals canonical by definition, so nothing is stored for that key. Reads merge a bounded canonical keyset page with a bounded overlay page and never run the reducer.

Node reads retained operations in place through JSON expression indexes on `pdpp_replica_operations` and `pdpp_replica_received`. It stores no copy of operation JSON or canonical rows. Active pending operations live in `pdpp_replica_view_pending` while their batch is pending. Canonical writes and retained record operations mark a key for reconciliation only when that key has an overlay row, its connection has pending work or a variant, or its binding is deleted. Reconciliation runs the core merge only for keys that pending evidence or a variant reaches; every other dirty key resolves to "no overlay". Lifecycle changes can affect every key in a connection and therefore fan out at write time. The local journal projection exists only for connections with a durable binding-conflict fact.

Lite keeps its sparse overlay, merges bounded persistence pages, and runs the existing reducer during atomic writes. Existing Lite databases require authenticated reconciliation before preview-mode reads; canonical point and page reads remain available before that upgrade.

F2 is an explicit pending removal, carrying the same metadata as an upsert from `packages/core/src/replication/visibility-policy.ts`. Record deletion, reset and connection deletion expose a marked tombstone to the owner. HTTP tombstones omit record data. Stream summaries retain the marker even when their live count becomes zero. Grants retain confirmed values until promotion. Quarantine restores the eligible prior view. Promotion commits confirmed absence and acknowledgment atomically.

Distinct device writers retain the `(counter, writerId, operationId)` order, including tied counters. Pending counters never advance the local convergence clock. See [the pending-copy decision](261021-replica-pending-copy-decision.md) for the separate unresolved case of two payloads claiming the same batch identity.

F4 is assigned to the hardening lane built on #439. The agreed scheduling contract retains `stage`, `promote` and `quarantine`; visibility reads consume local snapshots and own no network refresh, retry timer or backoff counter. The worker must select bounded due work, respect error cooldowns, allow eligible complete batches past parked backlog, and require every pinned finalized member and predecessor before atomic promotion and acknowledgment.

## Read contract

- **Surfaces.** The Node record and blob routes accept `replicaReads(reader)`, the receiver's `readStore({reader})`. The routes derive the reader from the authenticated token. The adapter serves all five grant-relative read surfaces: stream listing and summaries, record pages, single records, `changes_since`, and blob metadata, references and bytes. Each adapter call reads in one SQLite read snapshot. Bytes served through the adapter pass one integrity check against the visible descriptor.
- **Host calls.** `retry` reconciles canonical state and drains dirty view work. With no new evidence it writes no overlay row and advances no revision. `reconcileDeclarations` is the explicit call after trusted declarations or validators change; it re-derives every overlay key of connections that have overlay rows, pending work or variants.
- **Cursor.** A Node cursor binds, for each connection: read mode, reset fence, integrity epoch, and the revisions of the requested stream in that mode. The integrity epoch comes from the optional store capability `replicaIntegrityEpoch(connectionKey)`, read in the same snapshot; without it, the reset fence alone applies. A stream revision advances only when a stored row of that stream changes in that mode. Preview cursors bind the canonical and overlay revisions. Confirmed-only cursors bind the canonical revision only. Binding and lifecycle changes advance every stream revision of the connection. The revision carries the view layout version, so 70d52db0 cursors expire. A view cursor never continues on the canonical store path. Quarantine facts get no view triggers; the epoch covers them.
- **Pages.** An owner preview page reads at most `limit + 1` rows from each keyset, so its work does not grow with the number of canonical rows that overlay rows replace. Replaced canonical rows are consumed but not returned. A page can therefore hold fewer than `limit` rows, or none, while `hasMore` is true; its cursor continues after the last consumed position. When an overlay row and the canonical row it replaces share a position, the overlay row sorts first.
- **Blob bytes.** Arrival or removal of blob bytes (received, canonical or pending, and pending batch state changes) marks every reachable key whose upsert references that blob, so a pending record becomes visible when its bytes arrive through any path.
- **Layout upgrade.** The view is derived state. Construction drops an older layout and rebuilds the sparse view inside its write transaction. Reads never build or migrate it.

## Identity ambiguity

The owner explicitly decided that a genuine received source-binding conflict hides the whole connection from grant readers, including stored local rows. Owners may see only known local writes, marked `visibility: "conflicted"` and `status: "account conflict"`. Received winners and pending payloads cannot supply those owner values. This is a visibility rule in the same core policy component, not a storage-withdrawal rule.

The hardening lane owns migration 18, the monotone `pdpp_replica_binding_conflicts(instance)` table and `markReplicaBindingConflict(instance)`. Its first insert advances the existing write clock/reset fence without writing history or an outbound journal entry. Hardening retains all source-binding evidence and stored rows/claims. This branch consumes the durable fact; it does not add migration 18 or an owner-resolution operation. The policy API was published separately at `db0fd079` for composition.

The Node adapter derives latest local values from `pdpp_mutation_journal.value_json`, using the current local generation and matching known source/method/installation writer. Latest local tombstones suppress old values. Unknown or unbound legacy provenance fails closed. An indexed local projection supplies bounded ordered pages for conflicted connections only; a fact insert builds that connection's projection. Stored corruption-quarantine predicates still win for both readers, including local blob authorization. Canonical history cannot establish authoritative local provenance, so both readers fail closed for conflicted connections in `changes_since`. The receiver adapter narrows history instances only after the canonical store validates the original scope and reset fence; old page, change-page and change-session tokens expire with HTTP 410. Pending values never enter the history feed. Normal composition must migrate before constructing the receiver. A standalone checkout without the conflict-fact capability has no facts to read; that absence never clears a stored conflict.

## Red evidence

Run with Node 22.23.3 and `TMPDIR=$HOME/.tmp`:

```sh
./node_modules/.bin/vitest run packages/server/src/storage/pdpp-replication-receiver.test.ts \
  -t 'F1|F2|F3|two devices resolve' --maxWorkers=1
./node_modules/.bin/vitest run packages/server/src/routes/pdpp-pending-visibility.test.ts --maxWorkers=1
./node_modules/.bin/vitest run packages/lite/src/canonical-pending.test.ts -t 'bounds point and page'
./node_modules/.bin/vitest run packages/server/src/storage/pdpp-replica-visibility-revisions.test.ts \
  packages/server/src/storage/pdpp-replica-visibility-sparse.test.ts --maxWorkers=1
```

Before production edits, the three Node findings failed: stale cursors continued, pending deletion returned `undefined`, and point/page reads loaded pending batches and retained operations. Strengthening the two-device regression to continue a page after winner withdrawal produced four expected failures. The original tuple-selection assertion already passed and was preserved. HTTP reproduced a 404 for pending deletion and an empty stream summary. A later HTTP integration regression exposed a missing connection tie-breaker during cursor rebinding: three equal timestamp/key records returned only the first and third connections. Updating the cursor from the last visible record preserves all three. Lite's two cardinality cases failed; a point read with 120 pending batches made 247 scans, including the pending-batch metadata scan.

The r1 relaunch recorded each item red before its production edit:

- Lite nits: six cases failed against `70d52db0` (an empty native page with a continuation threw; old-database canonical pages threw before the index upgrade).
- Receiver snapshot and byte repairs: eleven cases failed against `70d52db0`, including byte corruption on canonical, received and pending blobs and four two-connection snapshot races.
- Idle retry: at 1 and 120 keys, `70d52db0` rewrote view rows and expired both cursors.
- Cursor scope: unchanged declaration reconciliation wrote 8 view rows; a write to another stream expired the cursor; bumping a fake store's integrity epoch did not expire owner, grant or local-mode cursors.
- Sparse view: the view held 100 and 1,000 overlay rows for 100 and 1,000 canonical rows; staging one pending key left 120 rows; constructing over 300 rows ran the reducer 300 times; the local projection covered unconflicted connections.

A differential run forced the full reducer for every key that the sparse fast path skips and logged any disagreement with canonical. Across 1,651 storage and route tests it logged none.

Local raw logs are `~/.tmp/438-red.log`, `~/.tmp/438-node-strengthened-red.log`, `~/.tmp/438-http-red.log`, `~/.tmp/438-http-red-summary.log`, `~/.tmp/438-http-cursor-red.log`, `packages/lite/.evidence/pending-cardinality-red.log`, and the r1 logs under `~/.tmp/ps438-relaunch-logs/`. The evidence directory is ignored; this document records the failure mechanisms rather than checking generated logs into source control.

## Measurements

File-backed SQLite, Node 22.23.3, one connection, `mutable_state`, about 200 bytes of data per row, one active pending batch during reads. Two interleaved rounds per size; ranges show both rounds. The host was shared and noisy, so compare within a round.

|                                             | 1,500 rows before (70d52db0)         | 1,500 rows after                | 3,000 rows before                    | 3,000 rows after                     |
| ------------------------------------------- | ------------------------------------ | ------------------------------- | ------------------------------------ | ------------------------------------ |
| Derived view bytes                          | 5,608 KiB                            | 428–436 KiB                     | 9,740–9,744 KiB                      | 668–676 KiB                          |
| Whole database                              | 11,192–11,200 KiB                    | 6,020–6,024 KiB                 | 19,340–19,344 KiB                    | 10,280–10,288 KiB                    |
| Receiver construction over existing rows    | 1,336–1,812 ms                       | 39–65 ms                        | 3,036–3,509 ms                       | 40–42 ms                             |
| Ingest 500 rows, plain / with receiver      | 249–298 / 868–1,719 ms               | 271–332 / 355–438 ms            | 277–368 / 892–1,329 ms               | 232–327 / 343–382 ms                 |
| Owner p95 first page / continuation / point | 0.22–0.24 / 0.28–0.32 / 0.06 ms      | 0.36–0.38 / 0.43–0.44 / 0.13 ms | 0.20–0.24 / 0.25–0.31 / 0.05–0.06 ms | 0.29–0.35 / 0.36–0.42 / 0.10–0.12 ms |
| Grant p95 first page / continuation / point | 0.22–0.26 / 0.27–0.32 / 0.05–0.06 ms | 0.25–0.26 / 0.30–0.32 / 0.07 ms | 0.21–0.28 / 0.26–0.34 / 0.05–0.06 ms | 0.27 / 0.33 / 0.07 ms                |

Derived bytes after the change are the four expression indexes on the retained-operation table plus a few pages of overlay, pending and summary tables. Owner reads now merge two keysets, which costs about 0.1 ms per call at these sizes. Rebuilding a 70d52db0 database with 3,000 rows took 64 ms, expired its cursor, and kept its pending batch visible.

Idle `retry` no longer touches the view. It still costs 1.4–2.6 s at these sizes because the receiver's canonical reconcile reads the whole retained operation set; it did so before #438 as well. Making it incremental belongs to the transport scheduling lane.

## Verification

Final suite, review and live receipts are recorded after closeout. A small benchmark is separate from publication/finality latency and does not establish native-device memory or crash behavior.
