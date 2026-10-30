# Lite canonical persistence (slice 7a)

Experimental and disabled unless `enabled: true`. No runtime, producer, route,
transport worker or Unity pin changes. Base: transport slice #429 at `401adfb85`.
The provisional single issuer and Lamport/writer/operation ordering from #426
remain unchanged. Whether those provisional policies become final remains open.

## Backend decision

Use the existing owner-partitioned **native SQLite database**, with chunked BLOB
staging and atomic reference publication in that same database. This extends
`PsNativeStore`; it adds no database engine or browser persistence dependency.
Canonical rows, original operations, the local operation log, clock and import
receipt share one serializable commit. Native blob staging is
invisible until that commit publishes a verified descriptor and chunk reference.

Evidence is the read-only Unity `origin/dev` tree at
`9fd58b7beb46832ff6d788d48715e6eaca14d6b0` (paths below are relative to that repo):

- `apps/mobile-shell/lib/ps/native_ps_store.dart:9,161-162,189-237` already uses
  sqflite, Application Support, owner/environment/network partitions, verified
  WAL mode and interrupted-write cleanup. `:56-84` derives the namespace from the
  host-resolved owner; JavaScript does not select a path or namespace.
- `native_ps_store.dart:306-317` runs record operations in one SQLite transaction.
  `:11,256-270` caps individual existing JSON values at 1 MiB and stores file
  metadata separately. `:348-393` provides bounded record pages/point reads.
  `:765-774` limits native keys/prefixes to 512 characters; the new port hashes
  internal identity keys to fit that bound without truncating record identity.
- `native_ps_store.dart:444-478,505-571` stages files, renames one immutable body,
  then commits its file metadata in a separate transaction. `:547-556,725-732`
  describes orphan cleanup. This is **not** a combined record+journal+file commit.
  WAL alone does not prove durability under kill or power loss; the inspected
  initialization does not explicitly set `synchronous=FULL`.
- `apps/mobile-shell/ps_bundle/src/native-persistence.js:30-35,134-149` dispatches
  `psNativeStore` and uses `records.transact`. `:38-69,81-105` bounds bridge frames
  but stringifies a whole envelope and reassembles a whole read before JSON parse.
  `:169-193` persists files and the storage index separately.
- `apps/mobile-shell/ps_bundle/src/harness.js:680-692` selects this native bundle;
  `:761-764` deliberately avoids mixing it with the browser file store.

Alternatives: the current file store cannot atomically publish canonical metadata
with file visibility; OPFS/IndexedDB would add a second lifetime and eviction
boundary. SQLite chunk tables avoid a filesystem/SQLite two-resource commit and
whole-body materialization. Existing raw-envelope files remain separate until
7b explicitly migrates/adopts canonical producers. The reported 150–300 MB phone
OOM and external storage's 100 MiB request cap are task constraints, not device
measurements produced by this PR. The request cap remains enforced by #429's
fragmentation code; it is not a maximum native blob size.

## PS implementation

`canonical-persistence.ts` is the native adapter contract. `canonical-store.ts`
provides trusted host connection provisioning, local operation drafts with a
persisted installation writer/clock, replica-authenticated import, canonical point
reads, bounded log/outbox reads and cumulative outbox acknowledgment. Local
record decisions call the existing `planIngest`; all replica winner/conflict
selection calls `planReplicaMerge`. Imported operations never enter the local
log or outbox. A receipt acknowledges **durable retention**, not stream availability.
It does not issue or replicate grants.

The caller supplies a stable local request id. Its fingerprint prevents a changed
retry from adopting another request's receipt. Reopening after a lost commit ack
returns the original local receipt and original operation ids. Import retries
also attach newly supplied bytes and re-evaluate retained operations. Missing
local connections never get guessed or provisioned by import.
After trusted declaration/validator changes, call replica-authenticated `retry`
and continue its connection keyset pages until `after` is absent. Connection
provisioning also retries that connection's retained records.

Indexes retain every original variant and detect cross-key operation-id
collisions and connection binding conflicts before partitioned materialization.
The shared `createReplicaRecordReducer` feeds bounded evidence back through the
existing planner while streaming one key's variants. This reduces memory, not
history: losers remain on disk. Ordinary record changes read only affected keys;
lifecycle, blob-claim, equivocation and provisioning changes can scan all keys in
a connection, with bounded pages. Native transaction duration for that scan is
not yet measured.

Each local operation writes one `log/<sequence>` entry,
`{batchId, operationKey, sequence, rowVersion?}`. `operationKey` points at the
retained operation, so the log holds no operation or row bytes; `rowVersion` is
the record row's version after that write. The outbox is the log after the
`outbox-ack` sequence, so a new request whose id sorts before an old cursor
cannot disappear. Only a trusted
publisher may acknowledge a contiguous prefix **after** #429's persist-before-I/O,
immutable-fragment and authoritative-settlement requirements hold. CAS ack moves
`outbox-ack`; it deletes no log entry. `readLogPage` reads acknowledged entries
too; `readOutboxPage` never does.

`canonical-layout-version` is 2. Layout 1 stored a full copy of each local
operation under `journal/`, a pointer under `outbox/` and a row copy under
`mutations/`. A store whose layout is not 2 refuses every call with an error
that names the layout; it never reads both layouts. No production database
holds layout 1, so there is no migration: clear a development store and import
again. This PR does not wire a Lite
publisher or claim that an envelope pointer is an encrypted DPv2 fragment.

## Exact native contract for slice 7b

Implement `LiteCanonicalPersistence` in the existing `psNativeStore` dispatch,
bound to the host's current owner/environment/network namespace. No user-supplied
SQL, filesystem paths, namespace or grants. Keep the canonical key namespace
separate from current runtime state/token/MCP keys.

1. **Read/write transaction token.** A JS adapter implements
   `transaction(callback)` through begin, get/put/delete/scan/attachBlob and
   commit/rollback operations on an opaque session token. Hold one native SQLite
   transaction (`BEGIN IMMEDIATE` equivalent) throughout the callback. Await every
   operation, see prior writes in that transaction, serialize writers across
   WebViews, and return commit success only after SQLite commit completes. On JS
   exception, bridge/WebView closure, timeout, logout or process interruption,
   roll back an open transaction. A dropped response after commit is an uncertain
   ack: retry the same request id. Never re-execute individual puts outside the
   transaction or deadlock on the existing serial executor.
2. **Bounded JSON and keyset reads.** `get` returns absent or the exact stored
   UTF-8 JSON string. `scan(prefix, after)` uses an exclusive BINARY key cursor,
   prefix matching without wildcard interpolation, at most 100 entries and at
   most 512 KiB of values, except that a page always holds its first entry. It
   sees transaction-local writes and deletions. Keys and continuation are opaque
   strings. Values above `LITE_CANONICAL_MAX_VALUE_BYTES` throw; pages never
   truncate a value. Local inputs are bounded to 192 KiB per operation batch,
   or one operation alone up to `LITE_CANONICAL_MAX_OPERATION_BYTES` (its
   operation entry and row are the only values over 256 KiB); 7b must enforce
   that before constructing/parsing a bridge body. Split batches at record
   boundaries; do not split record identity or alter declared data. A received
   replica envelope has no whole-size bound: the store keeps it in 128 KiB
   parts, keeps each pending blob descriptor in its own value, and bounds its
   header, operation count and each operation
   (`LITE_CANONICAL_MAX_OPERATION_BYTES`) before parsing it.
3. **Staged, verified blob chunks.** `stageBlob(descriptor, chunks)` sends
   backpressured frames of at most 128 KiB into native staging chunk rows. Hash
   incrementally natively and verify exact length, SHA-256, content-derived id,
   MIME metadata and frame order before returning a sealed opaque staging id.
   Staging ids are namespace/session-bound. No whole-body JS, Dart or SQL result
   buffer. Total native blob size may exceed 100 MiB. Transport requests still
   use #429's encrypted-size cap and fragment codec.
4. **Atomic blob visibility.** `attachBlob(stagingId, expected)` verifies the
   sealed descriptor, refuses conflicting existing bytes/metadata and publishes
   the immutable blob-id→chunk-set reference inside the canonical transaction.
   A retry may attach the same immutable bytes. Rollback must expose neither
   descriptor nor bytes. `blob(id)` returns only a committed or transaction-local
   verified descriptor. `readBlob(id)` streams only published chunks; missing
   blobs throw. Staging cleanup must never delete a published chunk set. Use
   WAL plus `synchronous=FULL` (or prove an equivalent durability setting).
5. **Host adoption and proof.** Supply retained declarations and schema validators,
   trusted source/connection/method mappings and a replica-specific authenticator.
   Collector credentials must never reach the import port. Convert supported
   producers to canonical drafts instead of same-name raw PDPP writes; preserve
   local delivery while remote publication waits. Adapt canonical reads to the
   existing async read/projection boundary with account ambiguity refusal. Keep
   writer identity stable across normal restarts; rotate it on copied/rolled-back
   backup restore before writes. Run this PR's shared fixtures through the actual
   Dart bridge, then kill the WebView/process at each commit boundary and test
   both device directions with exact bytes.

The native adapter may choose its transport operation spelling, but it must
implement every method and visibility guarantee above. The in-memory fake and
SQLite port test adapter are oracles, not mobile implementations.

## Evidence and remaining limits

The shared store fixtures execute the existing Node canonical SQLite receiver,
Lite with the crash fake, and Lite over a real disk SQLite port. They cover the
same mutable vectors, deletes/resets, generation gaps, append-only conflict,
equivocation, owner checks, duplicate delivery and received blob bytes after
restart. Lite fault cases inject record/blob/log/import failures,
before-commit rollback and after-commit lost acknowledgment. A multi-write case
checks each log entry's row version. `canonical-layout.test.ts` pins the
publisher's outbox pages and every non-log entry for a fixed write sequence to
digests recorded on layout 1. Reducer differential tests compare
bounded evidence with the full planner across deterministic permutations; a
retained history above 4 MiB still materializes without deleting losers.
The shared lifecycle cases also check invalid resets, same-content new-generation
withdrawal/recreation, original tombstone metadata and delayed declarations.
An actual Node local journal feeds Lite, whose local outbox then feeds Node again
after both adapters restart; this is a store fixture, not a device/gateway proof.

Not proven: the Dart adapter, actual process/WebView kills through that bridge,
phone peak RSS/latency for a 150–300 MB scope, >100 MiB native blob assembly,
two-device/gateway transport, or Account grant-relative reads on the receiving
phone. The SQLite adapter uses small test BLOBs, not native chunk staging. Native
restore/writer rotation is a host requirement, not implemented here.

This is a canonical write/import persistence port, not a complete
`PdppRecordStore`/HTTP reader. Public list/change cursors and stream completion
availability are not implemented by this port. Completion operations are retained
as evidence and never advertised as available. 7b must use the existing shared
completion dependency/digest rules before exposing completion. Inline JSON records
larger than the batch bound need a separate streaming-record solution before
adoption; silently transforming them into blobs would change the declaration.
Lifecycle evidence currently has a 4 MiB fail-closed merge-window bound; pathological
reset histories need a bounded lifecycle reducer before promotion. No compaction,
loser deletion, ordering-policy change or issuer-topology change is authorized.

## Phone adoption read port (slice 7c)

`readConnectionPage(connectionId, after?)` returns `{rows, after}` from current
canonical rows for exactly that connection, including tombstones. It uses the
persistence port's bounded keyset scan and rejects a cursor from another
connection. Version-two cursors bind the connection, read mode and its durable
view revision. Canonical commits, provisioning and reconciliation advance the
canonical and preview revisions of affected connections. Pending-only
stage/quarantine advances affected preview revisions, so grant cursors survive
pending churn. Changes to an unrelated connection preserve both modes' cursors.
Global operation-id collisions also invalidate every connection whose canonical
or preview view is affected. A changed revision expires the cursor explicitly;
restart the listing from its first page. Continue until `after` is absent; a page
boundary is not stream completion. A native empty page can carry a continuation;
continue from it without treating the empty page as completion. The caller filters
streams/tombstones and owns its read budget.
This is an internal trusted-host API, not a grant-relative PDPP list route,
public query cursor or completion proof. It makes no identity/issuer decisions.

Compared with the Node receiver's grant-relative pages: a Lite connection page
spans every stream of one connection, so its revision is scoped to the
connection and read mode rather than to a stream. Lite has no integrity-epoch
capability; its cursors bind the connection's revisions only. Like Node, the
preview is a sparse overlay on canonical rows, and only write-side calls build
or upgrade it.

## Pending replica visibility hooks

`stagePending({id, envelope, credential, blobs?})` retains an authenticated,
structure-checked batch under `pending-batches/`, separate from canonical operation
indexes, rows, convergence counters and the log. It returns the canonical
JSON SHA-256 `fingerprint`. The transport host must decrypt and verify incoming
transport hashes before this call. Blob attachment verifies staged bytes through
the persistence port; a separate pending visibility gate hides those immutable
bytes from grant reads. Pending batch retries preserve the original fingerprint.

After independently checking finalized commitment evidence, the trusted host calls
`promotePending({id, credential, fingerprint})` with the fingerprint of the exact
finalized envelope. Canonical import, blob visibility and pending-to-confirmed
state change share one transaction. A mismatching fingerprint persists quarantine
and throws. `quarantinePending({id, credential, reason})` handles a later finalized
version or an independently detected divergence. These hooks do not fetch or verify
chain evidence themselves; the Lite publisher/receiver host is not wired here.

`readRecord(connection, stream, key, {reader?})`,
`readConnectionPage(connection, after?, {reader?})` and
`readBlob(blobId, {reader?})` default to `grant`. Trusted owner hosts explicitly pass
`reader: "owner"`. Store-level `visibilityPolicy` uses the shared core policy:
owner includes pending and grant sees confirmed only by default. Both classes can
be changed to either mode through that one policy. Quarantined batches are hidden
in every mode. Preview-derived rows, including record-delete, reset and
connection-delete tombstones, carry `confirmation: "not yet confirmed"` and
`visibility: "pending"` from core's `replicaPendingMetadata()` helper.

Pending operation partitions and batch references are durable indexes. Stage,
promotion and quarantine update them and the affected preview rows in the same
transaction. Canonical commits, host provisioning and declaration reconciliation
also refresh those rows. Each refresh uses the current canonical baseline and
the existing record reducer over canonical plus active pending evidence; local
resets/deletes and concurrent edits retain #426 ordering. For a provisional
lifecycle removal of pending-only data, the same reducer derives the eligible
source value from active evidence before that removal, preserving canonical
lifecycle suppression. Quarantining the source withdraws the marker; quarantining
the removal restores the source. No stale preview row is used as source evidence.
Multiple batches can retain the same operation until their last active reference
is removed. Withdrawing an equivocation variant clears its connection's marker
when that connection no longer participates, even if two other variants remain.

Point reads use direct row lookups. Connection pages merge one bounded canonical
row page with one bounded preview row page: at most 200 native input entries and
1 MiB of input values. Visible output is at most 100 rows and 512 KiB, including
pending metadata. Pages reuse scanned values without row point re-reads. A
byte-trimmed page continues after its last returned key, without skipping the
unreturned rows. Reads do not load pending batches or
reconstruct operation history. Pending blob bytes need two independent facts: a live visible reference and an
active batch that carries the bytes. The preview materializer keeps
`preview-blob-refs/<blob>/<row>` in the same write as each preview row, for
every live preview row whose `blob_ref` names a blob. Only preview rows can
reference pending-only bytes, because a canonical upsert commits its bytes and
marks the blob confirmed. `readBlob` authorizes against that index and then
requires any active carrier in the per-blob active-batch index; one batch can
stage the record and another the bytes. A pending deletion, an operation-ID
variant or quarantine removes the reference or the carrier, and the bytes with
it. Both checks are prefix lookups. Confirmed bytes are refused when every
connection that claims the blob is quarantined, that is, has a binding-conflict
fact or an equivocation marker. Bytes another live connection claims still serve. Pending index version 3 adds the reference
index; `retry` builds it from existing preview rows of a version-two database,
and preview reads refuse until then. Ordinary record writes reconcile affected keys; lifecycle, blob-claim,
equivocation and provisioning writes may fan out across a connection's keys.
Native write latency and large-backlog write costs remain unmeasured. An older
database below the current pending-index version requires authenticated `retry`
(continue its pages) before preview-mode reads. Canonical point and connection-page
reads remain available before upgrade. Canonical pages use revision zero until
receipts are initialized; the first write-side upgrade expires those cursors.
A first state-changing hook also upgrades the database atomically. The upgrade
initializes per-connection canonical and preview revision receipts, including
when version-one derived indexes already exist.
This one-time write-side upgrade reads retained pending-batch metadata;
preview-mode reads fail explicitly until it completes.
Pending work never advances the canonical clock. Log and outbox reads see
canonical state only.

The pending tests exercise the public store API with the crash fake, including
reopen, interrupted promotion rollback, all four reader policy combinations,
local edits/reset/delete, quarantine, blob visibility and disabled operation.
Cardinality checks bound point/page read scans at 1 and 120 active batches,
including mixed canonical/preview pages at entry and byte boundaries. Ordinary
one-key stage/commit cases assert equal row work, native scan calls and scanned
entry counts with 1 versus 120 unrelated pending keys.
Further cases cover two-device tuple ordering in both arrival orders, provisional
tombstone markers, shared operation references, atomic stage/quarantine rollback,
and cursor expiry on affected writes, cursor stability across other-connection
writes, global operation-id collision invalidation, and version-one snapshot
receipt migration. They do not prove native mobile persistence or actual
process-kill durability.
