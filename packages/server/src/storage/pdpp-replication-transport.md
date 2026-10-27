# PDPP replica transport (experimental, disabled)

`createReplicaTransportWorker` is an internal, manually driven worker. Its
`enabled` option defaults to false. It is absent from server bootstrap, HTTP
routes and Lite. This change does not enable production replication.

## Wire and authority

Each address is `pdpp_replica_v1.<writer-token>_<batch-token>.<fragment-index>`.
Writer and batch tokens are independent 128-bit random identifiers, without
source, account or connection names. This three-part name passes the current
SDK `ScopeSchema`. The first component is reserved from grants, ordinary
inventory, MCP and the upgraded legacy upload/download workers.

Every object uses DPv2 version **1**, the existing per-scope key derivation,
OpenPGP encryption, plaintext keccak commitment, metadata commitment and
AddData signature. Storage keys are `<scope>/1`. The worker never calls the
legacy uploader or its file-head recovery/rebase path.

The plaintext is a standard version-1.0 data-file envelope, containing a
version-1 replica fragment under `data.fragment`. PS-Lite 1.33.2's downloader
can validate/cache this envelope; exact legacy scope lookups do not select it.
This compatibility promise means old app reads remain stale or absent. It does
not mean an unmodified old runtime skips downloading internal objects, or
that its wildcard grants gain the upgraded runtime's private-scope policy.

Each fragment binds owner, writer, batch, sequence, predecessor batch/digest,
collection time, total payload digest/length, fragment count/index/offset,
chunk digest and base64 bytes. Reassembly verifies each chunk and the cumulative
length/digest while streaming. It does not allocate the advertised total. The canonical payload contains the existing
replica envelope plus content-addressed binary bytes. Existing retained
source/declaration bindings validate operations before receiver import. Binary
digest/length, MIME and generation-bound claims remain receiver requirements.

## Durable progress

A single canonical SQLite database owns transport state, outbox, inbox and
imported batch identities. One worker per database is the host contract.

1. Stream a pinned baseline or journal tail page into hidden 64 KiB payload
   chunks. After the encoder verifies the complete source digests, one immediate
   transaction retains the batch identity/sequence/predecessor and advances the
   independent export cursor.
   Baseline acknowledgment transfers responsibility to the durable local queue;
   it does not claim publication. No source history is removed.
2. Encrypt fragments and atomically retain **all exact ciphertext bytes and
   commitments before network I/O**. A restart before that commit can encrypt
   again; a restart after it reuses the committed bytes. The default chunk target
   is 4 MiB. The actual encrypted request must fit the effective cap, which may
   be configured lower than the vana-storage 100 MiB default. Adaptive splitting
   handles both large JSON records and binary payloads.
3. Before every upload attempt, reconcile the exact address. Confirmed evidence
   must match the owner/scope/version-1 head to a finalized DataRegistryV2
   version-1 commitment and Active status. Absence retries the same address
   and bytes; pending settlement waits. Only finalized later versions or a
   commitment mismatch against the durable expected hash pair quarantine. Gateway disagreement stays pending.
   Registration responses alone do not acknowledge publication.
4. Repeated paginated owner scans retain discovered addresses before advancing
   their scan cursor. End-of-scan restarts at page one. Independently retry due
   downloads, verify settled commitments and decryption, then persist fragments.
5. A complete batch waits for its exact predecessor. Complete groups run in
   sequence order. A canonical parser writes decoded binary chunks into hidden
   staging and verifies the complete payload before import. Operations, received
   bytes, canonical bytes and the batch receipt commit together on the receiver's database. Missing local authority remains
   durably retained by the receiver, whose retry method runs each cycle. Imported
   operations never enter the local journal or become fresh outbound operations.

Due outbox/inbox entries are selected by retry deadline, then insertion order.
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
state; impossible framing is quarantined. A missing predecessor intentionally
blocks descendants on that writer's chain, while other writers can advance.
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
`evidence(scope)` port:

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
`currentVersion(owner, scope)`, `dataCommitment(owner, scope, 1)` and the exact
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

Confirmation requires a live version-1 head, finalized currentVersion 1,
Active chain status, and exact
`keccak256(abi.encode(bytes32 dataHash, bytes32 metadataHash))` equality.
Only finalized immutable-slot facts quarantine: currentVersion greater than 1,
or a version-1 commitment that differs from the commitment of the known
durable expected hash pair. This includes a finalized tombstone-at-version-1
pair that differs from the prepared replica. Gateway-only contradictions remain pending:
wrong owner/scope, version 9 while chain is still 1, mismatched hashes,
missing head, tombstones, or lifecycle refusal (`inactive`, `unavailable`,
or a `deleted` signal). They can roll back or heal and never cause PUT or
registration refresh fights. Non-Active chain status also remains pending
because status can reactivate. A downloader without local expected hashes
holds a head/chain mismatch pending rather than quarantining it.

Only a missing head together with currentVersion 0, zero commitment and the
contract's default None tuple is absent. Any head with chain version 0 stays
pending. Unavailable finalized evidence stays pending or throws retryably;
explicit `pending: true` prevents confirmation or absence.

The trust boundary is the configured RPC, chain identity, registry deployment,
and freshness policy. Gateway HEAD proof verification is unnecessary for
hash-pair authenticity: the independent chain commitment binds the exact
head preimages. The Gateway remains trusted for discovery availability and
can withhold a head or report an optimistic mutation to delay progress.
The finalized snapshot does not prove that no mutation occurred after that
block. The downloader retains the verified head and compares downloaded
plaintext plus scope/collectedAt/encrypted-size metadata to that exact head.
Before import it also combines the downloaded hash pair and compares it
directly to the finalized chain commitment; the chain is the authority.
A registration timeout reuses durable ciphertext and scope/version 1; it
never rebases or treats the registration response as settlement.

The read-only dev prerequisite check uses a random in-memory owner and reads
no `.env` or account files:

```sh
./node_modules/.bin/tsx scripts/pdpp-replica-dev-preflight.ts
```

It checks dev Gateway/storage health and finalized registry absence. It does
not publish, write storage, register data, or verify the complete two-device
journey. Live acceptance must still verify repeated PUT of identical
ciphertext at an existing key after registration failure. Preparation currently
quarantines any `RangeError`, including a possible allocation failure;
distinguish runtime errors from impossible framing before promotion.
Runtime scheduling and Lite publisher wiring remain outside this change.

The in-process oracle uses two file-backed SQLite stores and real receiver
imports, an encrypted storage fake with a size cap, and independent fake
head and finalized-chain stores with the contiguous-version guard. Real SDK
OpenPGP and signing-adapter behavior are exercised; high-cardinality fault
tests use a fast authenticated codec. Tests cover byte-exact resumed retries, fragmented
JSON/binary reassembly, reversed/duplicate/tampered fragments, predecessor and
local-authority delays, late feed entries, false heads, pending/deleted
registrations, starvation and atomic import checkpoints.

Live gateway/storage write acceptance, 100 MiB boundary memory use, registry
cardinality/cost, real process termination during I/O, and mobile persistence
are unproven. Pages and reassembled payloads are
buffered in memory; large-device/phone memory measurements are required before
promotion. A restored or cloned database must rotate its persisted writer
identity before producing new batches; automated clone detection is not part
of this experimental worker. Hosts must keep owner identity encoding consistent
between baseline configuration and authoritative evidence.

## Retained inbox upgrade

When an enabled worker opens an older inbox, a ready row with retained
`fragment_json` but a missing `data_hash` or `metadata_hash` is requeued for
validation. Startup clears the fragment, both hash preimages, finality flag,
retry deadline and old error. Normal download/decrypt/hash/structure checks
regenerate the preimages; every fragment still needs finalized commitment
verification before promotion. Imported and quarantined rows are untouched.
A disabled worker does not requeue these rows. The upgrade deliberately requires
storage to be available again; old decoded JSON alone cannot establish the
missing commitment preimages.
