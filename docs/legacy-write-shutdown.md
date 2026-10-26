# Legacy write shutdown contract

`legacyWriteShutdownEnabled` defaults to `false`. The Node runtime supplies
**no shutdown or restore qualification adapters**. Enabling the flag does not
make a scope eligible. Missing dependencies return
`503 LEGACY_SHUTDOWN_UNAVAILABLE`; they never become an empty grant proof.

## When the gate is active

The gate is active for an index handle when the host opts in
(`optInLegacyPublicationGate`, which the Node bootstrap calls when the flag is
true) or when the root has durable enrollment history: any row in
`legacy_publication_policy` or `legacy_publication_transitions`, in any state,
including `mirroring` after rollback. The additive gate tables alone are not
enrollment. `legacyPublicationGateActive` in
`packages/server/src/storage/legacy-publication-fence.ts` owns this rule.

On a never-enrolled root with the flag off, behavior equals the pre-gate
runtime (ddd2b8d1). Bootstrap installs the raw gateway, signer, remote storage
and deletion ports, no download hold and no owner policy API. Storage keeps its
earlier write, commit, block-sidecar, chunk-finalize and stage-recovery paths
and lock modes. No issuance journal row is written. A direct or recovered
import records no producer unless it is an authorized restoration, so
history-only and upload-queue predicates select the same rows. SQLite
`recursive_triggers` stays off. Direct storage (`createNodeDataStorage`
without the host opt-in) is off in the same way.

Enrollment needs the flag, so a never-enrolled process with the flag off cannot
become enrolled while it runs. An enrolled root stays gated with the flag off:
its fences, retention, holds and rollback route remain. Disabling the flag
stops only new enrollment.

`scripts/legacy-gate-differential/compare.mjs` proves the off equality by
running the same operations against a pre-gate tree and a candidate tree. These
operations are HTTP JSON, binary and chunked writes, a durable owner import,
grant signing and registration, encrypted upload and registration, direct
appends under canonical authority, boot recovery of a prepared import and of a
leftover stage, and a final sync. A candidate run with a failing gate journal is
compared too. Each run must pass positive checks (successful statuses, signed
grant and data-point registrations, encrypted uploads, recovery), so two equal
failures prove nothing. Only the authorized differences are removed: the
converged stamp (16 to 17), empty gate tables and the default-off config key.
Gate rows, producers, queues, uploads, signatures and registrations are
compared. `--expect-different` runs a negative control; the first gate build
(fca7e255) fails the comparison. Build both trees first:

```sh
node scripts/legacy-gate-differential/compare.mjs \
  --baseline <pre-gate tree> --candidate <tree> --work <scratch dir>
```

## Owner API

These routes are mounted only while the gate is active. They use the existing
owner authentication, CORS and JSON error handler:

- `GET /v1/legacy-publication-policy/:scope` returns `policy`, `capabilities`
  and `canonical`, the current native canonical assessment (see below), or
  `null` when no record store is mounted. `capabilities.nativeCanonicalCoverage`
  reports that reader; `capabilities.shutdown` stays false until the trusted
  qualification adapter also exists.
- `POST /v1/legacy-publication-policy/:scope/stop` accepts only
  `{ "expectedEpoch": 0, "ownerOptIn": true }`.
- `POST /v1/legacy-publication-policy/:scope/rollback` accepts only
  `{ "expectedEpoch": 2 }`.

Scopes must be exact names, such as `spotify.profile`. Wildcard enrollment is
refused. Evidence is accepted only from trusted host adapters, never request
bodies. An epoch conflict requires policy readback. Opt-in belongs to the owner,
server-key generation and exact scope. Changing identity does not transfer
consent, clear an earlier fence or permit a new default-mirroring policy.

The serving generation is `server-key:<lowercase server address>:legacy-publication-v1`.
The server-key identity survives restart. Another serving key needs an explicit
handoff/recovery protocol; this implementation refuses that transition.

## Local stop barrier

The state sequence is `mirroring -> quiescing -> stopped -> restoring -> mirroring`.
Policy epochs, evidence and transition receipts live in `index.db`. SQLite
`BEGIN IMMEDIATE`, the existing CAS revision, and persistent insert triggers
serialize local admission with shutdown. Disabling the flag stops new enrollment;
it never removes an existing fence. Rollback remains available while disabled.

Before entering quiescing, the gate refuses prepared owner imports and queued
versions eligible for remote publication. They must finish while mirroring.
Chunk upload acceptance is staging, not version acceptance; finalize competes at
the writer barrier and returns `legacy_scope_retired` when shutdown wins.
After quiescing, a qualification error leaves the scope fenced. Retrying uses
the same barrier epoch. No timeout or feature flag releases it.

Enforcement covers ordinary JSON/binary writes, durable owner imports, replica
commits, index recovery inserts, chunked finalize, and block-sidecar publication.
It applies to both legacy producers and PDPP projection producers. Canonical
record ingestion through the dedicated canonical routes remains separate and
continues. The older `$pdpp`-in-legacy-envelope ingest path and sync-download
import run only after a legacy commit; a stopped scope fences those paths too.
Clients must use the dedicated canonical routes to keep canonical ingestion
working during shutdown. Local grant signing/registration,
renewal by re-registration, AddData signing/registration, sync blob uploads and
remote deletion retries are fenced too. Unknown scope grammar blocks issuance
when it might reference a fenced scope. Known unrelated scopes remain independent.

Signatures, submissions and blob uploads leave durable intent identities before
remote effects. A signature whose submission timed out remains a possible
credential. Local receipts do not mark it expired, revoked or remotely settled.

## Native canonical coverage

`createLegacyCanonicalCoverage` in
`packages/server/src/storage/legacy-publication-canonical.ts` reads real facts
from this server's own record store, over the policy's SQLite connection. The
Node bootstrap supplies it when the PDPP record server is mounted. The policy
requires it: without it, stop returns `503 LEGACY_SHUTDOWN_UNAVAILABLE` with
`native_canonical_coverage` in `missing`.

For one exact scope it:

1. Takes the reviewed bindings that serve the scope (`scopeMethods` and
   `legacyBindingsForProfile`, the same tables the legacy view uses). Like the
   view, it counts every live connection of any method of the scope that holds
   data, configured on this boot or not. A live connection of a configured
   method counts even when it holds nothing. It needs exactly one such
   connection, and its method must be configured for a retained declaration.
   No connection, several connections (`ambiguous_connection`), an unconfigured
   method, an unbound scope or duplicate declarations of the source block.
2. Binds identity: the declaration `source@version#digest`, the binding's
   digest-pinned provenance (artifact), the view contract plus a hash of the
   reviewed binding shape (projection), the connection
   `instance:method:generation:resetClock` (binding) and the serving generation.
   A binding without a pinned digest blocks. Each bound stream must be declared
   with the binding's primary key. The declaration and artifact are labels of
   what this boot serves, not producer attestations: no receipt or row binds
   the declaration digest or the artifact that produced it. Producer-artifact
   attestation stays with the adapter. The projection identity hashes the
   binding shape, not the projection code; a behavior change needs a contract
   bump.
3. Requires a current native full-stream receipt for every bound stream
   (`assessStreamCompletion`): host-run digest of the live set, same method and
   generation. An empty stream qualifies only with its own receipt. Missing,
   invalid, quarantined or unknown completion blocks, whatever the row counts.
4. Reads every live row through `listRecords`, checks the count against the
   receipt, and verifies the bytes of every `blob_ref` with `getBlobBytes`.
   The completion digest covers references, not bytes.
5. Refuses an eligible latest legacy head unless a parity read covered it for
   this exact connection and generation: a takeover recorded for that instance
   and generation (`hasCoveredHead`; a takeover without an instance, from the
   v13 migration or a confirmation without a legacy reader, never counts), and
   a `covered` verdict for that head whose cursor still matches the current
   write clock, arrival revision and receipts (`currentVerdictCursorPrefix`,
   the rule the view's listing uses). A missing, stale or `not_covered` verdict
   blocks. The fix is a fresh parity read through the view, not inheritance.
6. Requires a first-addition tracking start. It is an observed window only; it
   does not certify history before it, retention or metrics recovery.

The input digest covers the identity, the full receipts (a receipt-only
completion does not advance the data clock), verified blob hashes, arrival order
for arrival-ordered bindings, the legacy head, its full verdict row and the
tracking start. A re-recorded verdict therefore refuses at the barrier.

Stop uses it three times. Before quiescing, a synchronous assessment refuses
with `409 LEGACY_SHUTDOWN_BLOCKED` and `blockers`, and the scope stays mirroring.
After quiescing, `qualify` runs the complete reviewed projection
(`readCanonicalLegacyScope`, method profile, completion receipts and Claude raw
blobs required) inside the same read snapshot as a matching assessment. Any
refusal, omission, partial or unproven row blocks; the scope stays quiescing.
The result (`projectionRevision`, `watermark`, `inputs`, `identity`) is passed
to `freezeAndQualify` as `context.canonical`. At the final barrier, in the same
`BEGIN IMMEDIATE` transaction that writes `stopped`, the evidence must echo that
identity, watermark and inputs exactly, and `isCurrent` reassesses every native
input with no await. A changed receipt, row, blob, declaration, reset, legacy
head or verdict refuses. The retained canonical inputs are therefore the real native ones.

These facts do not prove grant inventory, global issuance or writer fences,
durable canonical retention, owner/history reader or metrics recovery
qualification, restart readback or rollback compatibility. The owner-native
endpoints are not substitutes either: `selection-status` `ready` without
`require_complete` can mean only a count threshold, and additions coverage
`complete` covers only the requested window after `tracked_since`.

Known limits:

- Selection is conservative: a configured but empty connection, or data held
  by a method that is not enabled, can make the scope ambiguous even while the
  view serves it. Resolve the extra connection before qualification; the gate
  never ignores its data. Any native write also makes the global verdict clock
  stale, so qualification then needs a fresh parity read.
- Cost: an assessment reads and hashes every live row and every referenced
  blob synchronously, with no byte budget. It runs on every owner
  `GET /v1/legacy-publication-policy/:scope`, which blocks the event loop, and inside the
  stop `BEGIN IMMEDIATE`, which blocks writers. Bound it before large scopes
  (for example Claude) enroll.
- Additions metadata (`pdpp_record_first_added`, `pdpp_additions_coverage`) is
  not protected by the retention triggers. Its retention and metrics recovery
  stay external (`metricsRecoveryQualified`).

## Trusted shutdown adapter

`LegacyShutdownQualification` in
`packages/server/src/storage/legacy-publication-policy.ts` is an internal host
port. Its `freezeAndQualify` operation must be idempotent by identity, scope and
barrier epoch. It must acquire a durable global fence before inventory readback,
including every issuer, renewal path, writer and pending remote publication or
cleanup. The fence must survive a lost response, restart and server handoff.

Qualification binds contract version 1, owner, serving generation, exact scope,
epoch, local CAS revision and all relevant local intent identities. It requires:

1. Authoritative inventory with a revision, complete pagination and resolved
   aliases, wildcards and delegations. Every effective credential is finally
   expired/revoked; pending, submitting, reorged, active and unknown block.
   Publication intents need authoritative final settlement instead.
2. The canonical section echoing `context.canonical` exactly (identity,
   watermark, inputs), plus its attestation of what native coverage cannot
   show: deletion/incremental semantics beyond the full-stream receipts, no
   failed ingest elsewhere and no foreign heads.
3. Readable legacy versions/blobs/indexes/receipts and durable canonical revision
   history, plus qualified owner/history readers, metrics recovery, restart
   readback and rollback compatibility for this exact contract.

`assertCurrent` must synchronously recheck its own facts at the final SQLite
snapshot, including the durable global fence receipt. The policy rechecks the
native canonical inputs itself in that transaction. A stale cached check cannot implement it. Declarations, success counts,
local grant bindings and `listGrantsByUser([])` cannot implement this contract.

The gate retains legacy index identities and prevents their cleanup. For local
canonical inputs it prevents deletion/update of retained record history and
historical blob metadata/bytes/claims. These guards supplement qualification;
the presence of tables is not retention or reader qualification evidence.
Takeover reset cannot change this policy. The independent index repair fence
(`closeScopeForWrites`) is never cleared by rollback.

Retention intentionally survives rollback: **all history remains retained and
readable; no history is removed**. Owner scope deletion returns
`409 legacy_history_retained`; canonical connection deletion/reset and protected
history mutation return `409 canonical_history_retained`. Rollback reopens
publication, not erasure. `recursive_triggers=ON` is required so SQLite's implicit
deletes in `INSERT OR REPLACE` cannot bypass either retention trigger.

While any non-mirroring policy exists for a scope, every local deletion or drop
in that scope returns `409 legacy_history_retained`, for retained and unretained
rows alike. This covers scope deletion, version deletion, file-id deletion and
the upload worker's missing-file drop. A restored head is retained in the same
transaction that accepts it. After reopening, individual cleanup checks only the
targeted version: a new unretained row whose file is missing still self-heals,
and a retained row is refused. Scope deletion stays refused while the scope has
any retained version.

A retained NULL generation can be filled only by storage after verifying the
published envelope twice inside the writer transaction. Direct generation edits
and later changes remain forbidden. Storage callers also check identity before
any effect (`409 legacy_history_retained`, or `legacy_scope_retired` while the
scope is fenced): replica repair needs the same generation, registered version
and data-point id, and the index row is not changed. These caller checks are
defence in depth. The file owner below decides.

## Retained version files

`packages/server/src/storage/hierarchy.ts` owns every file effect under a data
directory, and it enforces retained-version immutability itself. Every write,
staged or synchronous publication, stage consumption, block sidecar write,
first-seen ledger write, temp file, directory creation and deletion goes through
its checked primitives, using the effect's actual absolute path. A caller with
fresh options, a parent data directory, a symbolic-link alias or only paths
reaches the same rule. The rule applies in every policy state, including
mirroring after rollback and with the flag disabled, and on a restarted root.
The table-driven test `retained-version-files.test.ts` lists every exported
function of the owner and of node storage, and every storage-port method. A new
export fails that test until it is classified, and every mutation has refusal
and no-op cases.

Sealing (`retainLegacyVersions` in
`packages/server/src/storage/legacy-publication-fence.ts`, used by the stop
barrier, by reopening and by restored-head acceptance) first writes byte records
under `<dataDir>/.legacy-retained/`, then inserts the retained rows in the same
SQLite transaction. Records are never replaced or removed. There is one record
for the envelope at the row's indexed path, one for the canonical path its scope
and time name if that path differs, and one for the block sidecar directory:
the SHA-256 of each file, or `absent`. Stop seals only history that is really
there. A missing indexed envelope, or bytes that are not the row's generation,
make the seal fail, and the transaction does not commit. Indexed versions cannot
be sealed without storage bound to the same index database
(`503 LEGACY_SHUTDOWN_UNAVAILABLE`, `missing: ["retained_version_files"]`). The
record root is admitted like any other effect: a data directory that is, or
resolves through a link to, a path inside a retained set is refused.

For a retained file set:

- Removal, replacement, renaming, and consumption as a publication stage are
  refused. This includes any directory that holds retained files or a data root.
- Writing bytes identical to an existing retained file is a no-op.
- A missing retained file is created only from bytes with its recorded SHA-256.
  Equal content in other bytes (for example, another key order) is not the same
  file. A sidecar recorded `absent` stays absent, so derived sidecars are never
  added after sealing.
- Nothing is created inside a retained set.

Refusals are `409 legacy_history_retained`, raised before any lasting effect.
The first-seen ledger is scope-level, not a version file. It is written and
deleted freely at its own path, but if that path resolves inside a retained set
it is refused like any other effect.

Races: after writing its records, a seal reads the files again and fails if
they changed. A removal first moves the path aside, then checks again. A
creation checks again after it links. If a seal and a mutation overlap, in this
process or another, either the seal fails or the mutation is undone and
refused. Sealed bytes are never removed. A removal that moved a file aside
before the seal read it wins, and the seal fails because the file is missing.
Record existence counts as absent only on ENOENT or ENOTDIR. An unreadable
record or record directory throws, so it is never treated as unretained.

Migration and limits:

- Roots retained by earlier gate builds have retained rows but no byte records.
  Opening storage or boot recovery gives each such version an unknown-bytes
  record and infers nothing from current bytes. Its files cannot be changed,
  and the identical bytes stay a no-op. A lost file cannot be restored, even
  from its old bytes, because they cannot be proven.
- A raw SQL insert into `legacy_publication_retained_versions` is not a sealing
  path. Until storage next opens the root, such a row has no file records, so
  only the caller checks protect it. After storage opens, it fails closed as
  above. All runtime sealing uses `retainLegacyVersions`.
- A seal that fails after it wrote records leaves them in place. The files stay
  protected even though no row was committed. This over-protection cannot be
  undone through the runtime.
- A crash inside a race window can leave a moved-aside `.retiring.*` file or an
  extra link. It never deletes a retained byte.
- Code that writes to the filesystem directly, outside this module, is not
  fenced. Neither is another operating-system user.
- Sealing reads and hashes every file of the scope synchronously inside the stop
  transaction.

A leftover `.pending` stage for an indexed version whose file is missing is
published only through `publishIndexedStage` in
`packages/server/src/storage/node-data-storage.ts`, at boot and on chunked
finalize replay. While the gate is active, it reads the stage bytes, checks
them against the row's exact known identity and publishes those checked bytes
in one `BEGIN IMMEDIATE` transaction. It publishes for a retained version in any
state, or for an unretained version in an unfenced scope. The file owner still
publishes a retained version only from its recorded bytes. Any other stage,
including a NULL generation, is held as `recovery-stage` with its bytes and
stays in place. Boot continues; a replay returns `409`. Chunked finalize does
not index a generation, so a retained chunked version can be repaired from a
stage only after a read has filled its generation.

Boot recovery holds fenced finalized orphans and prepared imports without
publishing or discarding their bytes. Sync holds fenced remote heads (ciphertext
plus the exact feed record) and tombstones before advancing the page cursor;
unrelated scopes continue. The hold reads through the unfenced remote reader, so
a foreign occupant of a pinned restore key is captured, not refused. If the
blob of a fenced remote head is proven absent (404/410 by the existing sync
failure classification), the hold records a durable `remote-head-missing-blob`
blocker with the feed record and no bytes, and the cursor advances. A transient
or unknown download failure, or a failure to persist the hold, keeps the cursor
retryable. These dispositions do not import canonical data or claim coverage.

The download hold recognizes this server's own current restoration without the
local data-point id. A registration whose response was lost leaves that id
unset. Recognition needs all of: the pinned restore version, data hash and
metadata hash; the current restore authorization and restoring policy for the
record owner; the accepted journal row; the latest local head with the pinned
generation; and readable local head bytes that hash to the same commitments.
The hold also recognizes a superseded restoration of this server. Rollback
retries supersede an earlier operation when canonical data changed; if the
earlier registration was accepted but its response was lost, the feed can list
it as the remote head until the current operation registers. Recognition needs
all of: the pinned restore version, data hash and metadata hash; a `superseded`
restore version with the same operation and data hash; the accepted journal row
and local row with the pinned generation; a restoring policy for the same owner
and serving generation; and remote ciphertext that decrypts under the scope key
to exactly the readable local bytes, with the journaled body digest. The
superseded row stays history-only: it is not queued, uploaded, signed or
registered, and gets no data-point id. Reopening still needs the current
operation's own remote confirmation, so the stale head is never acknowledged.
Any mismatch, including another owner, other commitments at the pinned version,
foreign ciphertext or unreadable bytes, records a foreign-head blocker.
Recognition never removes an existing hold.

While any record of a feed page is held or recognized, that page does not mark
the read-side deletion memory synced, for any scope. A stopped scope's known
retained head is recognized on every pass, and a single-page owner re-lists from
no cursor each cycle. For such an owner, the memory is therefore not marked
synced on any pass while any of its scopes is stopped or restoring with a fenced
head listed, and reads of every scope fall back to per-scope registry lookups for
that whole period. Each pass also downloads, decrypts and compares the head blob
of every such scope again. This continues until the scope reopens or a recovery
adapter resolves its holds. Holds persist in `legacy_publication_holds` and
policy readback exposes `blockers` by id/kind. Any unresolved hold blocks new qualification and reopening.
An operator/recovery adapter must resolve it explicitly; there is no automatic
discard or release API.

## Restore and reopen

`LegacyRestorationAdapter` must enumerate the full current canonical projection,
including unchanged streams and hydrated blobs. It supplies the reviewed
projection identity and revision, and must verify historical recovery. The
runtime has no implementation and remains restoring with
`503 LEGACY_RESTORE_UNAVAILABLE`.

The implemented state machine derives one operation identity from owner, serving
generation, exact scope, restoring epoch and canonical revision. It commits via
the existing owner-import journal. A narrowly bound restoration authorization
persists the operation, authority and body digest; unrelated imports remain
fenced. The ordinary encrypted upload adapter verifies the complete restored
head against that authorization and the accepted journal row, then pins one
remote version and its data/metadata commitments. Signing and registration each
recheck that binding, current epoch/operation and latest head. Ciphertext conflict
retries re-verify the stored occupant; no unfenced restore uploader is provided.
A different pinned remote version remains blocked and requires explicit recovery.
One exception releases a pin: a gateway `409` whose next valid version is below
the pinned version. Registry versions are sequential, so that refusal proves the
pinned version is not registered. The publisher then rebases and pins the
registry's version. A lost response or any other failure keeps the pin. A host
without a data-point feed starts at the local version, so a superseded attempt
can put the current head ahead of the registry; the release lets it register
once at the registry's version. The refused ciphertext stays at its key. That is
the existing no-feed hazard: a later publication at that key needs the fenced
publication port. Production bootstrap supplies a feed.
The journal's prepare and publish transactions remain separate so a
crash after file publication can recover the same operation. Retries reconcile
its immutable receipt. The timestamp advances beyond the current head even
when the clock moves backward. A changed body at the same revision conflicts.

Remote confirmation must identify that operation, body digest, persisted head
generation and canonical revision. It must establish actual delivery and the
required historical recovery contract. The gate rechecks the current canonical
projection and legacy head after confirmation. If either changed, it stays
restoring and a retry restores the new revision. It does not replay raw exports
or a pre-cutover file.

A new restore operation durably supersedes every earlier unconfirmed restore of
the scope before it is authorized. A superseded version keeps its row, file,
accepted journal and retention, and stays readable. It becomes history-only: the
upload queue and the shutdown drain check exclude it, and blob upload, AddData
signing and registration refuse its exact data hash after reopening too. This
also stops a queue entry captured before reopening. A superseded operation
cannot become current again; a later restore needs a new canonical revision, so
the adapter must not reuse a revision id for different content. Reopening also
refuses while any other publishable unsynced version exists in the scope.

`commitReopen` must record the issuer reopening decision in the same SQLite
transaction that clears restoring, for example through a globally honored
transactional outbox. It must return synchronously and issuers must not reopen
before that transaction commits. A network notification cannot implement it.
The final transaction retains the restoration receipt/confirmation and all old
history. Offline delivery, hydration failure, size limits, stale projections,
clock errors, remote uncertainty or unavailable reopen coordination keep the
fence closed. Restoring a current head does not manufacture intermediate legacy
snapshots; readers that need them require the qualified recovery adapter.

## Missing production dependencies and limits

The gateway/Account/other-server owners still need complete credential inventory,
finality and cross-issuer/writer fencing. Native canonical coverage is now real
(see above), but canonical-store owners still need durable retention, history
reader and metrics recovery qualification and remote restore delivery.
The global coordinator needs durable recovery/readback and transactional reopening.
None is inferred from existing list, takeover, import or sync APIs.

Independent roots and Lite browser snapshots do not share this SQLite authority.
Lite has no shutdown enrollment or restoration capability here. Multi-tab/device
coordination, external issuers, external canonical readers and app-owner acceptance
remain unqualified. The nine catalog scope sets in tests come from the supplied
design snapshot; those tests make no external UI or canonical authorization claim.

`packages/server/src/storage/schema-versions.ts` owns the shared, monotonic
`user_version` stamps. Version 17 is the converged runtime (#475), and version
18 is a root with durable gate enrollment history. Both openers
(`initializeDatabase` and `createSqliteRecordStore`) read both counters before
any change, including the WAL switch. A newer index or PDPP stamp is refused
and the database and sidecars stay unchanged. Every never-enrolled root,
including a #475 root, gets the converged stamp 17 whether or not gate tables
exist. The first durable enrollment raises the stamp to 18 in the same
transaction as quiescing, including when later qualification fails. It stays
18 after rollback. The first gate build (fca7e255) stamped enrolled roots 17.
On open, any policy or transition row moves such a root to 18 in one
transaction, and no history row changes.

`scripts/legacy-gate-differential/schema-crossline.mjs` checks these rules with
real builds of each line. Each root holds a seeded legacy version, and an
enrolled root also holds its retained identity. Every successful open must keep
both unchanged. Older runtimes refuse these roots.
The conformance line (ddd2b8d1) shares PDPP 25, so its legacy counter is its
only guard. It refuses 17 and 18, but only after its own WAL switch, because it
predates the preflight. The convergence line (#475) refuses through its
preflight with no change: PDPP 25 is above its 16, and 18 is above its 17. So
the gate stamp is not #475's only guard. Stop old processes before enrollment;
a schema stamp cannot evict an already
running binary or fence code writing directly to the filesystem. Back up the
whole root, database/WAL, policy/receipt tables and retained data together. Never
discard policy tables to rebuild the index or downgrade. Cross-server policy
handoff is unavailable, so absence of its evidence must block enrollment.
