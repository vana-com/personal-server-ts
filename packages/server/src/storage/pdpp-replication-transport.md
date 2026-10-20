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
chunk digest and base64 bytes. Reassembly checks actual retained length before
allocating the advertised total. The canonical payload contains the existing
replica envelope plus content-addressed binary bytes. Existing retained
source/declaration bindings validate operations before receiver import. Binary
digest/length, MIME and generation-bound claims remain receiver requirements.

## Durable progress

A single canonical SQLite database owns transport state, outbox, inbox and
imported batch identities. One worker per database is the host contract.

1. In one immediate transaction, export a pinned baseline or journal tail page,
   retain its complete payload and binary bytes, allocate its immutable batch
   identity/sequence/predecessor, and advance the independent export cursor.
   Baseline acknowledgment transfers responsibility to the durable local queue;
   it does not claim publication. No source history is removed.
2. Encrypt fragments and atomically retain **all exact ciphertext bytes and
   commitments before network I/O**. A restart before that commit can encrypt
   again; a restart after it reuses the committed bytes. The default chunk target
   is 4 MiB. The actual encrypted request must fit the effective cap, which may
   be configured lower than the vana-storage 100 MiB default. Adaptive splitting
   handles both large JSON records and binary payloads.
3. Before every upload attempt, reconcile the exact address. Confirmed evidence
   must agree across owner/scope/version-1 head, version history and finalized
   chain commitments. Absence retries the same address/bytes; pending settlement
   waits; inconsistent commitments, deletion or any later version quarantine.
   Registration responses alone do not acknowledge publication.
4. Repeated paginated owner scans retain discovered addresses before advancing
   their scan cursor. End-of-scan restarts at page one. Independently retry due
   downloads, verify settled commitments and decryption, then persist fragments.
5. A complete batch waits for its exact predecessor. Import and the batch receipt
   commit together on the receiver's database. Missing local authority remains
   durably retained by the receiver, whose retry method runs each cycle. Imported
   operations never enter the local journal or become fresh outbound operations.

Due outbox/inbox entries are selected by lowest attempt count, then insertion
order, with persisted exponential backoff (1 second through 1 hour). One failed
address cannot monopolize the oldest 50. Preparation has its own durable retry
state; impossible framing is quarantined. A missing predecessor intentionally
blocks descendants on that writer's chain, while other writers can advance.
Each cycle attempts every phase even if an earlier phase fails, then reports
collected errors so retained imports can advance during a feed outage.
All payloads, fragments, failures and receipts remain retained; no compaction,
retirement or sole-history deletion is implemented.

## Host integration and remaining promotion gates

`createDpv2ReplicaTransport` uses the existing SDK gateway, feed, signer and
storage ports. Its mandatory `evidence(scope)` port is deliberately stronger
than `getDataPoint`: the host must fetch authoritative version history and
finalized chain evidence, including absence, and distinguish pending settlement
from contradictions. The current SDK's head-only lookup cannot supply that
proof. There is no fabricated production implementation or head-only fallback.
The evidence adapter and production scheduling remain promotion work. During
history/chain propagation lag, the adapter must return `pending: true` or throw;
a partial evidence set with `pending: false` is a permanent conflict. Live
acceptance must verify repeated PUT of identical ciphertext at an existing key
after registration failure. Preparation currently quarantines any `RangeError`,
including a possible allocation failure; distinguish retryable runtime errors
from impossible framing before production promotion.

The in-process oracle uses two file-backed SQLite stores and real receiver
imports, an encrypted storage fake with a size cap, and independent fake
head/history/chain stores with the contiguous-version guard. Real SDK OpenPGP
and signing-adapter behavior are exercised; high-cardinality fault tests use a
fast authenticated codec. Tests cover byte-exact resumed retries, fragmented
JSON/binary reassembly, reversed/duplicate/tampered fragments, predecessor and
local-authority delays, late feed entries, false heads, pending/deleted
registrations, starvation and atomic import checkpoints.

Live gateway/storage acceptance, finalized-chain evidence acquisition, 100 MiB
boundary memory use, registry cardinality/cost, real process termination during
I/O, and mobile persistence are unproven. Pages and reassembled payloads are
buffered in memory; large-device/phone memory measurements are required before
promotion. A restored or cloned database must rotate its persisted writer
identity before producing new batches; automated clone detection is not part
of this experimental worker. Hosts must keep owner identity encoding consistent
between baseline configuration and authoritative evidence.
