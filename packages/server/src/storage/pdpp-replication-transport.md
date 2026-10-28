# PDPP replica transport (experimental, disabled)

`createReplicaTransportWorker` is an internal, manually driven worker. Its
`enabled` option defaults to false. It is absent from server bootstrap, HTTP
routes and Lite. This change does not enable production replication.

## Wire and authority

A device sync is one batch, up to the batch bounds below, and one batch costs
one registration.

- **Scope.** Each writer has one stable scope, `pdpp_replica_v1.<writer-token>`.
  The writer token is the derived transport writer id (see "Writer identity
  and batch authority"), without source, account or connection names. The prefix is reserved from grants, ordinary inventory,
  MCP and the upgraded legacy upload/download workers. Honest devices never
  share a scope, so their versions never contend (but see "Known limits").
  Each batch appends a version: a
  reader of only the latest version would see only the last batch, so the
  receiver discovers and reads every version.
- **Fragments.** A batch payload is cut into fragments (default target 4 MiB).
  Each encrypted fragment is stored **unregistered** at its content address,
  `<scope>/fragments/<sha256 of the encrypted bytes>`. A fragment is never
  registered and is never trusted on its own.
- **Manifest.** The batch has one manifest. It names the owner, writer,
  batch, sequence, predecessor batch and digest, collection time, payload
  digest and length, and lists every fragment, in index order, by digest and
  encrypted size. It carries the batch statement that the server key signed
  over all of these and the version it registers at (see "Signing"). The
  manifest is the only registered object: a
  DPv2 AddData at the next version of the writer scope, stored at
  `<scope>/<version>`. The version is a publication slot, not the batch
  sequence. The slot is claimed when the batch is prepared, so a batch that
  cannot be framed takes no slot and its successors still publish. A manifest
  at version _v_ publishes only after version _v−1_ is published, because
  DataRegistryV2 accepts only `expectedVersion = current + 1`.
- **Bounds.** One batch covers at most `maxBatchOperations` operations
  (default 10,000) and about `maxBatchBytes` payload bytes (default 32 MiB).
  One operation always fits, so a single larger blob makes a larger batch. An
  operation that only references blobs already in the batch is bounded by its
  JSON bytes: cutting it into the next batch would send the blob twice.
  Every payload carries the bytes of every blob its operations reference, so
  a blob whose claim and record fall in different batches is sent in both.
  When one commit writes all its blob claims before its records and is
  larger than the bound, most of its blob bytes go out twice. Removing that
  needs a payload that can refer to bytes an earlier batch carried.
- **Ordering.** One unresolved registration holds later source operations in
  the journal; no successor version is claimed yet. The current manifest
  reports a typed wait with its slot and intent age. After that slot resolves,
  the worker retains the waiting operations as the next batch. It never skips a
  version.

Every object uses the existing per-scope key derivation, OpenPGP encryption,
plaintext keccak commitment, metadata commitment and AddData signature. The
worker never calls the legacy uploader or its file-head recovery/rebase path.

Manifest and fragment plaintexts are standard version-1.0 data-file envelopes,
with the replica object under `data.manifest` or `data.fragment`. Exact legacy
scope lookups do not select them. This compatibility promise means old app
reads remain stale or absent. It does not mean an unmodified old runtime skips
downloading internal objects, or that its wildcard grants gain the upgraded
runtime's private-scope policy.

vana-storage overwrites on PUT without checks, and GET and HEAD need no auth.
So storage contents are never trusted. A receiver fetches a manifest only
after its registration is finalized, and checks the fetched bytes against the
finalized commitment. It then fetches each fragment and checks the exact
encrypted bytes (length and sha256) against the manifest entry **before it
decrypts them**. A fragment that differs is quarantined as
`fragment_mismatch`; a fragment that storage definitively does not have is
quarantined as `fragment_missing`. Nothing of that batch becomes visible.
`readmitFragments()` re-admits such fragments for another fetch after storage
is repaired; the finalized manifest still decides which bytes are accepted.

Reassembly verifies each chunk and the cumulative length and digest while
streaming. It does not allocate the advertised total. The canonical payload
contains the existing replica envelope plus content-addressed binary bytes.
Existing retained source/declaration bindings validate operations before
receiver import. Binary digest/length, MIME and generation-bound claims remain
receiver requirements.

## Writer identity and batch authority

This implements host contract §3 (docs/replication/host-contract.md and ADR
0001). The worker takes an `authority` dependency: the device's registered PS
server key (Node: `key.json`; Lite: the server identity account, not the owner
signer), an uncached roster port over gateway `GET /v1/servers/:address`, the
chain id and the environment.

**Writer ids.** `pdpp-replica-writer-identity.ts` keeps an append-only table of
incarnations. Each row holds the owner, server address, gateway registration id,
a 128-bit writer nonce and the two ids derived from them: the first 16 bytes of
a length-prefixed SHA-256 over the domain, role (`transport` or `operation`),
owner, server, registration id and nonce. The highest incarnation is current.
Derivation uses no fragment scope, so it does not depend on the carrier layout.

- Each step first reads the server's own roster record. The step waits (a
  `roster` dependency on its own address) until the server is registered under
  the owner and not revoked. If the roster is unavailable, a server that already
  has an identity continues with it; a server without one waits.
- The first identity requires an empty replica journal. A database that
  captured operations under the old random installation writer id fails with
  `replica_identity_requires_fresh_journal`: **dev databases start fresh.**
  Operations captured before the first identity keep that local id; receivers
  refuse them, so they never leave the device.
- A new registration id for the same address (re-registration) starts a new
  incarnation with a new nonce at the next step.
- After a replication reset, a new database, or a restore or clone, the host
  must call `rotateReplicaWriterIdentity` before the first new write. It keeps
  the registration and draws a new nonce. PS cannot detect a copied database.
  A restored copy that does not rotate reuses its old writer, scope and
  versions. Whichever device registers a version first keeps it; the other
  device's batch at that version is `immutable_registration_conflict` on that
  device and never reaches a peer. A copy batch that a peer does receive on an
  already imported sequence is `batch_equivocation` there.
- On a writer change the worker starts a new chain at sequence 1, and its
  first publication is a full current-state baseline. In the same transaction
  as the switch, the journal's `rebaseline` re-captures every connection
  lifecycle, blob claim, record, tombstone and completion under the new
  operation writer and pins them as the new baseline; the tail resumes after
  it. The new writer publishes in its own scope from version 1. The old
  writer's unpublished batches, fragments and manifests are abandoned, so its
  scope gets no new version, because no receiver accepts the old operation writer from the new
  signer; the baseline carries their effect. A peer that missed the old
  writer's batches (refused after re-registration, never published, or
  written between a gateway change and the next step) therefore converges.
  Each re-issued record and completion takes the order of the highest
  retained operation, own or received, with the same key and effect (record
  data, tombstone, or completion snapshot): its counter, plus that
  operation's writer and operation id as `revision.origin` (or its origin, if
  it was itself a re-issue). `compareRevisions` orders by counter, then the
  origin's ids, then the operation's own, so the re-issue wins and loses
  exactly where the original does. A state no retained operation explains
  takes a new counter. The rebaseline runs inside the door's capture guard. A
  crash during the baseline resumes from its durable cursor.
- Every step checks the replication door first. The roster read writes
  nothing; the identity write (establish or rotate) checks the door in its own
  transaction and refuses once it is closed, and the writer switch and
  rebaseline check it again in theirs. So a door that closes during the roster
  read leaves no new identity, rebaseline or publication.
- Completion dependencies and blob-claim reuse consider only the current
  operation writer, so every dependency a completion names is in a batch the
  current writer publishes.

**Signing.** Each manifest carries an `authority`: an EIP-712
`PdppReplicaBatch` statement (domain "Vana PDPP Replica", version "1",
chainId) signed by the server key. It names the owner, server, registration
id, environment and writer nonce, which derive the writer and so the scope,
and the scope version the manifest registers at. It also names the batch,
sequence, predecessor batch and digest, collection time, payload digest, total
bytes, fragment count, and the SHA-256 of the ordered fragment list (each
entry's 32-byte digest, then its length as 8 bytes, big-endian). So no field
that a receiver reads from a manifest, and not its slot, is outside the
signature. Prepare claims the scope's next version, signs, and keeps the claim
only if the version is still next when the manifest commits. Fragments (format
version 3) carry no statement: the signed manifest names their exact bytes.

**Receiver checks**, in §3.4 order. The receiver waits for finality, then
passes the manifest through `receiveReplicaManifest` and fragments through
`receiveReplicaFragment`. Both use the same read/decrypt/parse boundary,
`receiveReplicaJson` (`core/src/replication/receive.ts`), and return typed
receipts. Every object read has a 30-second deadline and propagates
cancellation, including fragment existence probes. The read stops at the storage cap (`maxBlobBytes`); the DPv2 transport refuses a
storage adapter without `downloadBounded`, so no read is unbounded. Before any
KDF runs, decryption refuses any message outside the profile the SDK writers
emit: one v4 password packet with iterated, salted SHA-256 S2K at count byte 224 or less, then one v1
integrity-protected data packet. Compression inside the encrypted packet is
refused during decryption before inflation. The plaintext is then scanned
without recursion, and nesting deeper than `REPLICA_MAX_JSON_DEPTH` (16) or more
structural tokens than `REPLICA_MAX_JSON_TOKENS` is refused before
`JSON.parse`. No writer makes any of these bytes, and none can be checked
against the commitment, whose data hash is over the plaintext and whose
metadata hash needs the parsed `collectedAt`, so all are `manifest_invalid`.
The receiver then checks the plaintext's hash pair against the finalized
commitment. A mismatch, plaintext that is not JSON, or JSON without a string
`collectedAt` is `commitment_mismatch` and retries, and a read or decrypt
error retries as `download_failed`, so replaced storage bytes that pass the
checks above cannot get a real manifest quarantined. Only matching bytes are
classified: any throw while classifying them is a typed refusal,
`manifest_invalid` unless a check below names another, and each refusal is
terminal for that slot. Only an authorized manifest's
fragments are fetched. Each fragment read stops at its manifest entry's
length and is charged against the step's byte budget; its sha256 is checked
before it is decrypted. The same packet-profile and bounded-JSON checks
apply to fragments. Once their ciphertext matches the signed entry, a decrypt,
parse or binding failure is `fragment_mismatch`. Definitive absence is
`fragment_missing`; a transient failure, abort or deadline retries. Existence
probes use zero-byte bounded reads, since `StorageAdapter.exists` can hide a
full SDK download.

| Check                                                                                                                                                                                                                                    | Refusal                 |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- |
| Wrapper is the canonical envelope; fragment lengths are positive safe integers; hashes are unique; all numeric fields are finite safe integers in range; sequence, predecessor and `collectedAt` agree; entry bytes fit the framed bound | `manifest_invalid`      |
| Statement parses, signs this manifest at this version, recovers to `server`                                                                                                                                                              | `signature_invalid`     |
| Owner, chain id and environment match this receiver                                                                                                                                                                                      | `partition_mismatch`    |
| Roster has a record for the server                                                                                                                                                                                                       | `server_not_registered` |
| Roster owner is the statement owner                                                                                                                                                                                                      | `roster_owner_mismatch` |
| Record is not revoked and has the statement's registration id                                                                                                                                                                            | `server_not_registered` |
| The slot's scope writer is the transport writer the statement derives                                                                                                                                                                    | `writer_mismatch`       |
| Every operation names the operation writer the statement derives (at import)                                                                                                                                                             | `writer_mismatch`       |

Each refusal is a typed quarantine of that slot. The framed bound ties the
sum of entry bytes to the signed `totalBytes`: each fragment is encrypted
JSON holding the base64 of its chunk, so the sum is at most
`replicaFramedBytesBound(totalBytes, count)`. That bounds what one manifest
can make a receiver fetch without capping what a user stores. A manifest
without a well-formed statement is `signature_invalid`. A signed manifest registered
again at another version is `signature_invalid`; registered in another scope it
is `writer_mismatch`. A roster that cannot answer is a `roster` wait, never a
refusal. A re-registered server's old incarnation names the old registration
id, so its unimported batches are refused; imported data stays. A deregistered
server's unimported batches are refused the same way.

**Staleness.** The worker caches roster answers, including proven absence, for
at most `REPLICA_ROSTER_MAX_AGE_MS` (5 minutes) on its own clock, bounded in
entries, with one read in flight per address. An expired answer is never used,
even when the gateway is down. Removal therefore takes effect within 5 minutes
plus the gateway's own cache time; until then a peer can still import a
removed server's batch. A batch admitted at download is
authorized again on every import attempt, so an import that waits (finality,
mapping) past the cache age is revalidated before it is staged or promoted.

**Known limits.** Any party that can register under the owner, such as
another registered server, can register its own manifest at a device's next
scope version first. Receivers refuse it, but it holds that version, so the
device's own manifest there is `immutable_registration_conflict` and the
device's sync stops at that version (host contract §3.6). A rebaseline re-issues the whole current state, including
records that peers wrote, as content-equal operations, so its size is the
database's live state. Its capture runs in one transaction, like the first
baseline, and keeps one revision per record key and effect in memory. The roster is the
gateway's current view; there is no history of past registrations.

## Durable progress

A single canonical SQLite database owns transport state, outbox, inbox and
imported batch identities. One worker per database is the host contract.

1. Stream a pinned baseline or journal tail into hidden 64 KiB payload
   chunks, up to the batch bounds. After the encoder verifies the complete
   source digests, one immediate transaction retains the batch identity,
   sequence and predecessor and advances the independent export cursor.
   Baseline acknowledgment transfers responsibility to the durable local queue;
   it does not claim publication. No source history is removed.
2. Encrypt the fragments and the manifest and atomically retain **all exact
   ciphertext bytes, digests and commitments, and the claimed version, before
   network I/O**. A restart before that commit can encrypt again; a restart
   after it reuses the committed bytes. The actual encrypted request must fit
   the effective cap, which may be configured lower than the vana-storage
   100 MiB default. Adaptive splitting handles both large JSON records and
   binary payloads.
3. Store every fragment. A fragment PUT is safe to repeat: the address is the
   content, and nothing refers to it until the manifest is finalized. Then
   store the manifest and persist a registration intent containing the owner,
   scope, version, encrypted manifest hash, local request id and attempt time
   before calling `register()`. The request id is for local correlation; the
   DataPoint AddData endpoint has no
   idempotency-key field, so an unresolved intent is not resubmitted until
   authoritative evidence confirms it or proves absence after the bounded
   five-minute intent timeout. A pending Gateway head or chain registration
   remains a typed Wait and does not expire into a second submission. After
   authoritative absence and timeout, the worker reuses the same slot and
   exact manifest bytes. Confirmed evidence must match the owner/scope/version
   head to a finalized DataRegistryV2 commitment at that version and Active
   status. Only a finalized commitment at the slot that differs from the
   durable expected hash pair quarantines. A later version is normal: versions
   append. A registration response alone does not acknowledge publication; a
   crash or lost acknowledgement is resolved from the durable intent and
   evidence. SQLite and the Gateway do not share a transaction. A crash
   between fragment upload and registration leaves only unregistered
   fragments, which no receiver can reach.
4. Repeated paginated owner scans list each writer scope with its current
   version. Discovery retains new slots, at most 256 per writer scope per pass,
   before it advances the scan cursor. End-of-scan restarts at page one. A
   slot's manifest is downloaded only under confirmed evidence; its fragments
   are then fetched, checked and persisted independently.
5. A complete batch waits for its exact predecessor. Complete batches run in
   sequence order. A canonical parser writes decoded binary chunks into hidden
   staging and verifies the complete payload before import. Operations,
   received bytes, canonical bytes and the batch receipt commit together on the
   receiver's database, and the fragment bodies are then dropped. Missing local
   authority remains durably retained by the receiver, whose retry method runs
   each cycle. Imported operations never enter the local journal or become
   fresh outbound operations.
6. Imported slots are revalidated round-robin against finalized evidence
   (`revalidateIntervalMs`, default 0: every step). A finalized commitment
   that differs from the imported one is a terminal copy decision: the
   writer is quarantined from that sequence on and the batch's data is
   withdrawn.

Due outbox/inbox entries are selected by retry deadline, then insertion order.
Each step processes at most 50 inbox manifests, even when the host requests a
larger download quantum. This bounds each step independently of inbox depth.
The server defaults each attempt to a 30-second deadline (`deadlineMs` can
override it); object reads retain their own 30-second limit.
Expected finality waits have a separate durable state and do not increment the
error counter. The optional `finality.head()` hint polls the finalized height at
most once per two seconds. Parked waits are filtered before the 50-row budget;
a new finalized height makes them eligible for the full independent evidence
check. The verified checked height never moves backwards. A hint supplies no
commitment authority. A hint ahead of verified evidence uses a 30-second
non-error cooldown, and waits older than ten minutes use that slow cadence.
Without hints, waiting rows use a two-second cadence. Actual errors and Gateway
head disagreements retain exponential backoff (1 second through 1 hour).
Successful waiting or confirmed evidence clears the error streak. One failed
address cannot monopolize the oldest 50. Preparation has its own durable retry
state; impossible framing is quarantined. A pending predecessor blocks later
source batches on that writer's chain, while other writers can advance. The
current slot's typed wait remains visible; authoritative absence after the
intent timeout retries that same version and ciphertext. A successor is
retained only after the predecessor is confirmed.
Each cycle attempts every phase even if an earlier phase fails, then reports
collected errors so retained imports can advance during a feed outage.
New large canonical, pinned and received bytes use the same 64 KiB chunk store.
Receiver reconciliation re-hashes actual chunks on every retry. Existing
single-BLOB rows remain readable; their native SQLite memory use is not bounded
by the JavaScript chunk reader. Explicit whole-value read APIs still assemble
bytes for their callers. Hidden abandoned stages are reclaimed by the next
worker cycle under the single-process database-writer contract.
All verified payloads, fragments, failures and receipts remain retained; no compaction,
retirement or sole-history deletion is implemented.

## Host integration and remaining promotion gates

`createDpv2ReplicaTransport` uses the existing SDK gateway, feed, signer and
storage ports. Supply `createReplicaEvidenceAdapter` from
`@opendatalabs/personal-server-ts-core/replication/evidence` as its mandatory
`evidence(scope, version)` port:

```ts
const evidence = createReplicaEvidenceAdapter({
  owner,
  registry,
  chainId,
  rpc,
  gatewayUrl,
  maxFinalizedAgeSeconds: 1800,
});
```

`rpc` can be a viem PublicClient or the exported `ReplicaEvidenceRpc` port.
`fetch` and millisecond `now` are injectable.
Hosts must supply a timeout-bounded fetch and RPC transport, as the dev
preflight does; the adapter does not install network timeouts itself.
The adapter checks configured chain identity, reads a `finalized` block with
number/hash/timestamp, and pins
`currentVersion(owner, scope)`, `dataCommitment(owner, scope, version)` and the exact
nine-field `dataPoints(owner, scope)` tuple to that block number. It rechecks
the block hash and freshness after I/O. The default freshness limit is 1,800
seconds, including normal chain finality lag; hosts can choose a tighter bound
that fits their chain. There is no `latest` fallback. Wrong chain, bad config,
unavailable/stale finality, inconsistent registry reads, malformed responses
and network failures throw `ReplicaEvidenceUnavailableError` with
`retryable: true`. They never become absence.

The Gateway supplies only the current head, fetched explicitly with
`includeDeleted=true`. Only its JSON `Data point not found` 404 means no head;
a generic route or Vercel 404 throws retryably. A 410 body is decoded and
retained as deletion evidence;
a bare/malformed 410 remains retryable. No versions/history HTTP API is used.
Chain evidence carries the actual bytes32 commitment, current version, status,
configured chain/registry, and finalized block coordinates. It never invents
`dataHash` or `metadataHash` preimages.

Confirmation of a slot requires a live Gateway head at or above the slot,
finalized `currentVersion` at or above the slot, Active chain status, and a
slot commitment equal to
`keccak256(abi.encode(bytes32 dataHash, bytes32 metadataHash))`. A head at
exactly the slot must also carry that pair. A later head says nothing about
the slot's preimages; the finalized commitment binds them. Only one finalized
fact quarantines: a commitment at the slot that differs from the known
durable expected hash pair. This includes a finalized tombstone pair that
differs from the prepared manifest. Gateway-only contradictions remain
pending: wrong owner/scope, mismatched hashes at the slot, a missing head,
tombstones, or lifecycle refusal (`inactive`, `unavailable`, or a `deleted`
signal). They can roll back or heal and never cause PUT or registration
refresh fights. Non-Active chain status is a Wait, not an error, because
status can reactivate; a receiver that has not fetched the slot yet waits
on any finalized commitment, because it fetches nothing until the status is
Active. A downloader without local expected hashes holds a head/chain
mismatch pending rather than quarantining it.

A slot is absent only when no head is at or above it, the finalized
commitment at it is zero, and the chain either holds earlier versions or has
the contract's default None tuple. Any head with chain version 0 stays
pending. Unavailable finalized evidence stays pending or throws retryably;
explicit `pending: true` prevents confirmation or absence.

The trust boundary is the configured RPC, chain identity, registry deployment,
and freshness policy. Gateway HEAD proof verification is unnecessary for
hash-pair authenticity: the independent chain commitment binds the exact
head preimages. The Gateway remains trusted for discovery availability and
can withhold a head or report an optimistic mutation to delay progress.
The finalized snapshot does not prove that no mutation occurred after that
block. The downloader hashes the fetched manifest plaintext and its
scope/collectedAt/encrypted-size metadata, combines the pair and compares it
directly to the finalized commitment at the slot; the chain is the authority.
A registration timeout reuses the durable ciphertext and the claimed slot; it
never rebases or treats the registration response as settlement.

The read-only dev prerequisite check uses a random in-memory owner and reads
no `.env` or account files:

```sh
./node_modules/.bin/tsx scripts/pdpp-replica-dev-preflight.ts
```

It checks dev Gateway/storage health and finalized registry absence of
version 1 of a fresh writer scope. It does
not publish, write storage, register data, or verify the complete two-device
journey. Live acceptance must still verify repeated PUT of identical
ciphertext at an existing key after registration failure, and one
registration per sync against the dev Gateway. Preparation currently
quarantines any `RangeError`, including a possible allocation failure;
distinguish runtime errors from impossible framing before promotion.
Runtime scheduling and Lite publisher wiring remain outside this change.

The in-process oracle uses two file-backed SQLite stores and real receiver
imports, an encrypted storage fake with a size cap, and independent fake
head and finalized-chain stores with the contiguous-version guard. Real SDK
OpenPGP and signing-adapter behavior are exercised; high-cardinality fault
tests use a fast authenticated codec. Tests cover one registration for a sync of many
fragments, byte-exact resumed retries, a lost registration acknowledgement,
a crash between fragment upload and registration, fragmented JSON/binary
reassembly, tampered and missing fragments, predecessor and local-authority
delays, late feed entries, false heads, pending/deleted registrations,
starvation and atomic import checkpoints.

Live gateway/storage write acceptance, 100 MiB boundary memory use, real
process termination during I/O, and mobile persistence are unproven. Pages and reassembled payloads are
buffered in memory; large-device/phone memory measurements are required before
promotion. A restored or cloned database must call
`rotateReplicaWriterIdentity` before producing new batches; automated clone
detection is not part of this experimental worker. A copy that skips it
keeps the original's writer and contends for the same scope versions. Hosts must keep owner identity encoding consistent
between baseline configuration and authoritative evidence.

## Databases from the per-fragment carrier

The earlier carrier registered every fragment under its own scope and kept
its state in `pdpp_transport_outbox`, `pdpp_transport_inbox` and
`pdpp_transport_preparing`. This worker cannot read that state. If any of
those tables exists, the worker throws `ReplicaCarrierMismatchError` before
it creates or changes a table. Testers start such a database fresh.
