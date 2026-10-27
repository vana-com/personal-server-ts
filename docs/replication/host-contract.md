# Replication host contract (internal testers)

Status: proposed (D0). Date: 2026-10-27.
Decision record: [ADR 0001](adr-0001-transport-and-device-identity.md).

This is the contract between the replication engine in this repository and the
two hosts that run it: the Desktop app (Node PS sidecar) and the phone app (PS
Lite in a WebView). It covers the internal-tester phase only. It defines how a
device proves it may write, how a host runs the engine, how a user turns
replication on and off, and what the two-device suite must prove.

Replication code is on PR #483, not on `main`. Citations without a repository
name refer to #483 at `ea4c18cf1463e425adaac6d9d30c5eec72c4810f`. Other
repositories are cited as `repo@sha path:line`: `unity-surfaces@9af449a2`,
`vana-storage@b1d3d83` and `data-gateway@37bc1fe`.

## 1. What exists today

- `replication.enabled` defaults to `false`
  (`packages/core/src/schemas/server-config.ts:54-59`). Bootstrap uses it only
  to open the record store (`packages/server/src/bootstrap.ts:953-976`), and
  "This boot has no replica receiver"
  (`packages/server/src/pdpp/records-bootstrap.ts:78`). Lite has a canonical
  store (`packages/lite/src/canonical-store.ts:204`) but no transport, runtime
  or routes for replication. Neither app enables it
  (`unity-surfaces@9af449a2 apps/desktop/src/hooks/usePersonalServer.ts:871-885`);
  the phone has no replication code.
- The carrier is DPv2. Each fragment is one vana-storage object at
  `<scope>/1`, one gateway AddData registration at `expectedVersion "1"`, and
  one finalized DataRegistryV2 commitment
  (`packages/core/src/replication/dpv2.ts:80-129`). Scopes are
  `pdpp_replica_v1.<writer>_<batch>.<index>`
  (`packages/core/src/replication/transport.ts:44-53`).
- Both writer ids are random: the transport writer token
  (`packages/server/src/storage/pdpp-replication-transport.ts:287-299`) and the
  installation writer used in operation revisions
  (`packages/server/src/storage/pdpp-replica-canonical-port.ts:113-118`).
  Neither is bound to a key. The receiver takes `authenticate(credential)` as
  an injected function and says the host "must verify a replica-specific
  credential" (`packages/server/src/storage/pdpp-replication-receiver.ts:122-132`).
- vana-storage does not protect replica objects by itself:
  - Blob GET and HEAD are public. The auth middleware skips them
    (`vana-storage@b1d3d83 src/middleware/auth.ts:153-170`), and PS relies on
    this (`main@b4e42412 packages/core/src/storage/adapters/vana.ts:93-94`).
    Anyone who knows a key can fetch the ciphertext.
  - PUT overwrites unconditionally
    (`vana-storage@b1d3d83 src/blobs/r2.ts:13`, called at
    `src/blobs/routes.ts:156`). DELETE checks only that the caller acts for the
    path's owner (`src/blobs/routes.ts:291-293`). Any registered server of the
    owner can overwrite or delete any of the owner's objects.
  - Integrity comes from the registered data hash (DPv2) and, after this
    design, the signed batch statement. Confidentiality comes only from
    encryption.

## 2. Transport

Testers use the DPv2 carrier as built. This PR makes no production transport
decision.

Later: DPv2 costs about two minutes of chain finality per hop (dev median
122 s, p90 134 s, 2026-10-21) and one registration per fragment (4,310 for one
101 MiB blob on Lite). That cost may justify a different carrier before
production. A new carrier is its own design and may need engine changes. Plan
item A12 replaces per-fragment registration with one registration per device
sync: a manifest that lists content-addressed fragments.

## 3. Who may write

### 3.1 Signer and membership

Each device signs its batches with its existing registered PS server key: the
Node `key.json` account (`packages/server/src/keys/server-account.ts:37-56`)
or the Lite server identity (`packages/lite/src/state.ts:66-79`). Lite must use
that server key for replication. It must not use the owner sync signer that Lite
sync uses for storage and AddData (`packages/lite/src/sync.ts:250-263`).

Membership is the owner's `ServerRegistration` roster at the gateway. Removal
is deregistration through the existing Account intent
(`unity-surfaces@9af449a2 apps/account/src/app/api/v1/intents/personal-server-deregistration/sign`).
The wallet never signs batches. The master-key signature only derives
encryption keys.

### 3.2 Writer ids come from the signer

A writer id is not chosen and not bound on first contact. It is derived from
the identity that signs, so a receiver checks it from the signature alone:

```
writerId(role) = first 16 bytes of SHA-256(
  "vana-pdpp-replica-writer-v1",
  owner,          // 20 bytes, the owner wallet
  server,         // 20 bytes, the signing server address
  serverId,       // 32 bytes, the gateway registration id (incarnation)
  role,           // "transport" or "operation"
  writerNonce,    // 16 bytes, disclosed in every statement
)
```

Fields are length-prefixed. The result is 32 lowercase hex characters, the
existing writer token format (`transport.ts:14`, `envelope.ts:23`). The
transport writer and the operation writer use the same nonce, so they always
come as a pair from one server.

The nonce is still needed. Without it, every database under one registration
would derive the same writer ids. A reset, a new database or a restored copy on
the same server would then restart sequences and revision counters under ids
that peers have already imported. PS picks a random nonce when it creates
writer identity: on first enable, on reset, and on the clone and restore
rotation (`packages/server/src/storage/pdpp-replication.md`, "Capture and
retention"). The nonce gives no authority. Any id it produces includes the
signer's address and incarnation.

PS derives its ids at first enable, from its own gateway record. If the server
is not registered yet, enable waits. Today's random ids
(`pdpp-replication-transport.ts:287-299`, `pdpp-replica-canonical-port.ts:113-118`)
are replaced. Dev databases that used them start fresh.

The derivation uses only the signer's identity and the nonce, not scope names,
so it carries over unchanged to a per-sync manifest (A12).

### 3.3 The batch statement

The server key signs an EIP-712 statement for each batch (domain
`"Vana PDPP Replica"`, version `"1"`, `chainId`):

```
PdppReplicaBatch {
  address owner;
  address server;          // signer
  bytes32 serverId;        // gateway registration id of the signer
  string  environment;     // "dev" | "prod"
  bytes16 writerNonce;
  string  batch;
  uint64  sequence;
  bytes32 previous;        // digest of the previous batch, or zero
  bytes32 digest;          // sha256 of the assembled batch
  uint64  totalBytes;
  uint32  count;
}
```

Fragment format version 2 carries the statement and signature inside the
encrypted body (version 1 is at `transport.ts:17-34`).

### 3.4 Receiver checks

In this order. Each failure is a typed quarantine of that item only. A batch
that fails any check never touches writer state, so it cannot occupy a
sequence or a predecessor slot of a real writer.

1. Decrypt and decode the fragment.
2. Recover the signer. It must equal `server`.
3. Partition: `statement.owner`, `chainId` and `environment` must equal the
   receiver's. Addresses are compared after normalizing to lowercase.
4. Roster: the gateway record for `server` must exist, have no `revokedAt`,
   have `id` equal to `serverId`, and have `ownerAddress` equal to
   `statement.owner` (`data-gateway@37bc1fe api/v1/servers/[address].ts:122-130`).
   So roster owner, statement owner and receiver owner are one address. The
   receiver caches a roster answer for at most 5 minutes. If it cannot read the
   roster and has no fresh answer, it waits. It never accepts on an unknown
   roster.
5. Writer ids: derive both ids from `owner`, `server`, `serverId` and
   `writerNonce`. With DPv2, the writer in the fragment's scope must equal the
   derived transport writer.
6. Finalized DPv2 evidence, as today.
7. Assemble and check `digest`. Every operation's `revision.writerId` must
   equal the derived operation writer. Then import.

This implements the receiver's `authenticate` hook. New codes in
`packages/core/src/replication/outcome.ts`: dependency kind `roster`;
quarantine reasons `signature_invalid`, `partition_mismatch`,
`server_not_registered`, `roster_owner_mismatch` and `writer_mismatch`.

### 3.5 Removal and re-registration

The rule for testers: import only from servers that are registered now. After
a server is deregistered, peers refuse its batches that they have not yet
imported, including batches it published before removal. Data already imported
stays. Peers lose any of the removed device's changes that they had not yet
imported. Removal lag is the receiver's roster cache plus the gateway CDN TTL.

The gateway lets a revoked address register again. It refuses the same
`serverId` (`data-gateway@37bc1fe lib/servers.ts:525-531`), then clears
`revokedAt` and writes the new `id` (`:533-551`). The new `serverId` makes it a
new incarnation. Writer ids include `serverId`, so the device derives new ids
and starts new sequences. Batches under the old ids name the old `serverId`,
fail step 4 and stay refused. The new incarnation inherits nothing, because
the gap between removal and return is when a lost or copied key is most likely
in use.

### 3.6 Known tester limits

- **Copied key.** Anyone who has a copy of a device's `key.json` (or the Lite
  identity and master key) can sign as that device and its writers until the
  owner deregisters it. Testers accept this.
- **Another device can delay a peer.** Storage PUT overwrites (section 1), so
  any registered server of the owner can replace another device's stored
  ciphertext. The peer then fails the registered hash and cannot import that
  fragment. It never accepts forged data.
- **Removed devices can still read.** Every device holds the owner master key,
  and storage reads are public (section 1). A removed device that kept the
  master key can read and decrypt new batches. This must be fixed before
  production.
- **Account can derive keys.** Account infrastructure can regenerate the
  master-key signature
  (`unity-surfaces@9af449a2 apps/mobile-shell/lib/auth/owner_device_signer.dart:7-18`),
  as for every other owner scope.

Later, before production: a dedicated per-device replication key, held in
Android Keystore, the iOS Secure Enclave or the OS keychain and certified by
the server key. It would stop a copied `key.json` from signing batches and let
batch keys be wrapped to each current device, which closes the read gap.

## 4. Host ports

### 4.1 Boot configuration

```ts
/** Passed by the host at PS start. Absent means off. */
export interface ReplicationBootConfig {
  enabled: boolean; // the host's opt-in record says "on" (section 5)
  owner: `0x${string}`;
  environment: "dev" | "prod";
  chainId: number;
  limits: ReplicationLimits;
}

export interface ReplicationLimits {
  /** Fragment size target. Node 4 MiB, Lite 1 MiB. */
  fragmentBytes: number;
  /** Work and memory per step (section 6). */
  step: { units: number; bytes: number; deadlineMs: number };
}
```

PS refuses an invalid value, as the worker does today for its storage cap
(`pdpp-replication-transport.ts:229-231`).

### 4.2 Transport I/O

`ReplicaTransportPort` (`dpv2.ts:64-77`) stays DPv2-specific, including
`register` and `evidence`. Each I/O method gains one argument:

```ts
export interface ReplicaCall {
  signal: AbortSignal;
  /** Stop reading and reject when a response passes this size. */
  maxBytes?: number;
}
// put(fragment, call), register(fragment, call), evidence(scope, call),
// get(scope, call & { maxBytes: number }), list(cursor, call)
```

The adapter must stop its I/O on abort. `abortable` (`coordinator.ts:100-123`)
only drops a late result. Adapters do not retry; a failure is a verdict the
coordinator settles. On the phone the adapter is the WebView's `fetch`, because
decryption runs in JS anyway; 1 MiB fragments fit the 1 MiB native record limit
(`unity-surfaces@9af449a2 apps/mobile-shell/lib/ps/native_ps_store.dart:11`).

The roster is one more port:

```ts
export interface ReplicaRosterPort {
  server(
    address: `0x${string}`,
    call: ReplicaCall,
  ): Promise<{ owner: string; id: string; revokedAt: string | null } | null>;
}
```

### 4.3 Lite persistence

`LiteCanonicalPersistence` (`packages/lite/src/canonical-persistence.ts:16-42`)
allows values of at most 256 KiB, and its blob methods take record blob claims
(`:3-6`), so they do not fit fragments. Lite adds byte storage:

```ts
export interface LiteReplicaBytes {
  /** <=128 KiB frames. The native side computes length and SHA-256. */
  stageBytes(chunks: AsyncIterable<Uint8Array>): Promise<string>;
  readBytes(id: string): AsyncIterable<Uint8Array>;
}
export interface LiteReplicaTransaction extends LiteCanonicalTransaction {
  attachBytes(
    stagingId: string,
    expected: { length: number; sha256: string },
  ): Promise<void>;
  releaseBytes(id: string): Promise<void>;
}
```

### 4.4 Runtime, scheduler and status

```ts
export interface ReplicationRuntime {
  /** Single-flight. A call while a step runs returns that step's report. */
  step(input: {
    budget: ReplicaBudget;
    signal: AbortSignal;
  }): Promise<ProgressReport>;
  wake(dependency: ReplicaDependency): void; // wraps onDependencyChanged
  status(): ReplicationStatus;
  start(config: ReplicationBootConfig): Promise<void>;
  /** Abort the running step and wait at most graceMs. */
  stop(graceMs: number): Promise<void>;
}

export interface ReplicationStatus {
  state: "off" | "on" | "paused" | "refused";
  refusal?: "reenable_refused" | "invalid_limits";
  server?: { address: `0x${string}`; id: string };
  peers: { transportWriter: string; server: string; lastSequence: number }[];
  pending: { batches: number; bytes: number };
  problems: ProgressReport["problems"];
  lastStepAt?: number;
  nextWakeAt?: number;
}
```

`ReplicaBudget` and `ProgressReport` are the coordinator's types
(`coordinator.ts:125-152`).

The host calls `step`, then arms one timer at `nextWake`, clamped to 1 s to
15 min (15 min when `nextWake` is undefined). It also calls `step` when the app
comes to the foreground, a local write commits, the network returns, or the
user taps "Sync now". The phone runs only in the foreground: on `inactive`,
`paused` or `hidden` the host aborts the step and stops scheduling.

| Concern              | Owner        | Where                                                |
| -------------------- | ------------ | ---------------------------------------------------- |
| Retries and backoff  | Coordinator  | `settleReplicaWork` (`schedule.ts:222-291`)          |
| Deadline per attempt | Coordinator  | `deadlineMs` (`coordinator.ts:162-181`)              |
| When to step         | Host         | Timer and triggers above                             |
| Cancellation         | Host         | Aborts the step signal on stop, background, sign-out |
| Stopping I/O         | Adapter      | Honours the signal                                   |
| Durable effects      | Phase commit | One transaction per verdict (`coordinator.ts:52-88`) |

## 5. Opt-in and the one-way door

### 5.1 Entitlement and per-device state

Account adds `GET /api/v1/replication/entitlement`, authenticated by the
Account session. It returns
`{ entitlement: "replication_internal", state: "allowed" | "paused" | "none" }`.
It reuses `isAdminEmail(email, source)`
(`unity-surfaces@9af449a2 apps/account/src/lib/auth/admin-domains.ts:16-55`)
with a source of only `opendatalabs.xyz`. Like enclave eligibility
(`apps/account/src/app/api/v1/personal-server/enclave-eligibility/route.ts:1-7`)
it is UI state, not a security boundary; section 3 is the boundary. `paused`
makes the host stop calling `step` without closing the door.

The host stores one record per owner partition, `replication-optin.v1`:
`{ state: "on" | "off_after_on"; enabledAt; disabledAt? }`. Desktop passes it
through derived config (`apps/desktop/personal-server/derived-config.mjs:85`);
the phone passes it in the Lite boot options.

### 5.2 The door

Turning replication off is permanent on that device. Re-enable is refused with
`reenable_refused`. No data is deleted.

Today #483 has no door. Its test proves only the first enable over rows written
while off (`packages/server/src/storage/pdpp-replication-flag.test.ts:313`).
On, off, write, on is still `it.todo` (`:363-365`). `beginBaseline` returns the
existing watermark on a repeat call
(`packages/server/src/storage/pdpp-replication-sqlite.ts:396`), so a re-enable
would not see writes made while off. The only refusal today is for a
connection method transition made while off (`flag.test.ts:593`).

The record-store write clock cannot detect off-time writes. A `changesSince`
read without a cursor advances it
(`packages/server/src/storage/pdpp-records-sqlite-store.ts:2350-2358`), and
`registerConnection` (`:1786`) does not.

The door uses a SQLite mutation fence that works whatever build opens the
database:

1. On first enable, PS creates a guard row `pdpp_replica_guard(capturing)`
   with value 0, a flag row `pdpp_replica_uncaptured`, and AFTER INSERT,
   UPDATE and DELETE triggers on every table a replicated mutation writes. Each
   trigger sets the flag when `capturing = 0`.
2. Every replicated-mutation transaction, local capture or remote import, sets
   `capturing = 1` first and back to 0 before commit. SQLite allows one writer
   at a time, and a rollback restores 0.
3. An A1 build that opens the database with the flag off also sets the flag at
   open.
4. An enabled open that finds the flag set refuses.

A write by any build that does not run the capture path, including an older
build or plain `main`, fires a trigger and sets the flag. The triggers add
objects next to main's tables; the rollback test (`flag.test.ts:367`) must be
extended to prove that main still opens and writes such a database.

Before the door closes, the host opens the store once with the flag on. That
open restores the plain blob row for blobs written by the earlier chunk-only
build (`flag.test.ts:198-238`).

Confirmation copy:

> **Turn off sync on this device?**
> This is permanent for this device. Your records stay here. This device stops
> sending changes to your other devices and stops receiving theirs.

## 6. Limits

The limits bound work and memory per step, not the size of what a user stores.
There is no blob-size cap.

- **Work per step:** the step budget (`units`, `bytes`) and `deadlineMs`.
  Initial values: phone 20 units, 8 MiB, 30 s; Desktop 50 units, 64 MiB, 30 s.
- **Memory:** at most one fragment per direction in memory. Fragments are
  1 MiB on Lite and 4 MiB on Node.
- **No permanent stall:** a batch becomes Unsupported only at the protocol
  limit of 100,000 fragments per batch (`transport.ts:11`), about 97 GiB at
  1 MiB fragments. A peer holds a writer's later batches behind an Unsupported
  one (`pdpp-replication-transport.ts:628-666`), so no tester limit may produce
  one.
- **Reclaim instead of a lifetime cap:** the outbox keeps plaintext and
  ciphertext and the batch table keeps the payload
  (`pdpp-replication-transport.ts:79-110`). After a batch's registration is
  finalized, PS drops those bytes and keeps hashes and metadata. A test must
  prove that no outbound phase reads them after that point. After import, PS
  drops inbox bytes.

### 6.1 Engine work the step bound needs

The engine cannot meet these bounds today. Preparation advertises the bytes of
the whole batch (`pdpp-replication-transport.ts:579`), and the coordinator
skips any item larger than the remaining byte budget (`coordinator.ts:458`).
So on the phone, a batch over 8 MiB is deferred on every step and never makes
progress. Preparation also frames a whole batch in one run and discards partial
work on error (`pdpp-replication-transport.ts:590-627`).

Plan item A7 (the bounded coordinator) owns these changes, and builds on the
atomic checkpoints of A5:

1. **Bounded admission:** an item advertises the bytes of its next resumable
   unit, at most one fragment, not the whole batch.
2. **Resumable retention and hashing:** capturing a batch's payload and
   computing its digest continue across steps from a durable checkpoint.
3. **Resumable preparation:** each framed and encrypted fragment is committed
   with a cursor, so a restart continues from the last fragment.
4. **Resumable import staging:** inbound fragments are staged as they arrive,
   and assembly reads them across steps.
5. **Kept as today:** the whole-batch digest check before import, and atomic
   promotion of the batch in one commit.

Each of retention, hashing, preparation and import staging needs a test that
aborts a multi-step batch part-way, restarts, and proves the batch completes
with earlier progress kept and the same final result.

## 7. Two-device acceptance suite (D2)

D2 runs one Desktop and one phone (or two Lite hosts in CI) against dev. Each
item needs a test that fails when the property fails.

1. A write on A appears on B, and the reverse.
2. A restart during a step loses and duplicates nothing.
3. Edits made while B is offline arrive in order when B returns.
4. A lost PUT or registration acknowledgement is retried safely.
5. Late finality: B waits, then imports; it never imports unproven data.
6. Blobs of 1 MiB − 1, 1 MiB, 1 MiB + 1 and 200 MiB replicate. The large one
   spans many steps and survives a restart part-way.
7. Deletion, reset and quarantine reach the peer with the right outcome.
8. Both devices report the same records and cursors after quiet.
9. Flag off: no step runs, nothing is sent or read.
10. Door: off then on is refused. So is on, then a write by a build without
    replication, then on.
11. Removal: after deregistration, B refuses A's unimported batches and keeps
    imported data. A re-registered A derives new writers that B accepts.
12. First-contact impersonation: registered server C publishes under A's
    transport writer and reaches a fresh receiver first. C's batch is
    `writer_mismatch`, and A's real batches then import.
13. Operation-writer reuse: C publishes under its own transport writer with
    operations carrying A's operation writer. The batch is `writer_mismatch`.
14. Foreign owner: a server registered under another wallet signs a batch into
    the victim's partition. It is `roster_owner_mismatch`.
15. A tampered statement is `signature_invalid`. A batch for another chain or
    environment is `partition_mismatch`.
16. Switching account or network on one device does not mix partitions.
17. Phone background aborts the step within the grace time; the next
    foreground step completes the work.

## 8. Open question

When a device is removed, its changes that other devices have not yet imported
are lost to them (section 3.5). Is that acceptable for testers?
