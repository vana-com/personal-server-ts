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
  (`packages/core/src/schemas/server-config.ts:54-59`). With it on, bootstrap
  builds the receiver, transport worker and driver through
  `createNodeReplication` (`packages/server/src/storage/pdpp-replication-host.ts`)
  and steps them from `startBackgroundServices` until `cleanup`. Lite has a canonical
  store (`packages/lite/src/canonical-store.ts:224`), the host ports
  (`packages/lite/src/replication-ports.ts`), a runtime and owner-only
  status/sync routes (`packages/lite/src/replication-runtime.ts`) and the
  phase engine (`createLiteReplicaEngine`,
  `packages/lite/src/replication-engine.ts`). Node and Lite run the same
  phase logic (`packages/core/src/replication/engine.ts`). The runtime
  reports `blocked: "no_engine"` until its host passes an engine; no host
  does yet. Neither app enables it
  (`unity-surfaces@9af449a2 apps/desktop/src/hooks/usePersonalServer.ts:871-885`);
  the phone has no replication code.
- The carrier is DPv2. In #483 each fragment is one vana-storage object at
  `<scope>/1`, one gateway AddData registration at `expectedVersion "1"`, and
  one finalized DataRegistryV2 commitment
  (`packages/core/src/replication/dpv2.ts:80-129`). Scopes are
  `pdpp_replica_v1.<writer>_<batch>.<index>`
  (`packages/core/src/replication/transport.ts:44-53`). Plan item A12
  replaces this with one registered manifest per sync (section 2).
- Both writer ids are random: the transport writer token
  (`packages/server/src/storage/pdpp-replication-transport.ts:287-299`) and the
  installation writer used in operation revisions
  (`packages/server/src/storage/pdpp-replica-canonical-port.ts:113-118`).
  Neither is bound to a key. The receiver takes `authenticate(credential)` as
  an injected function and says the host "must verify a replica-specific
  credential" (`packages/server/src/storage/pdpp-replication-receiver.ts:135-145`).
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

Plan item A12 changes the registration count, not the carrier. Each writer
has one stable scope, `pdpp_replica_v1.<writer>`. A sync is one batch, within
the batch bounds (default 10,000 operations and 32 MiB). Its fragments are
stored unregistered at `<scope>/fragments/<sha256>`. One manifest lists them
by digest and size, carries the batch statement, and is the only registered
object, at the next version of the scope. A receiver fetches the manifest only
when its registration is finalized, and checks each fragment against the
manifest digest before it decrypts it. Details:
`packages/server/src/storage/pdpp-replication-transport.md`.

Later: DPv2 still costs about two minutes of chain finality per hop (dev
median 122 s, p90 134 s, 2026-10-21). Before A12 it also cost one registration
per fragment (4,310 for one 101 MiB blob on Lite); with A12 that blob costs one.
Finality alone may justify a different carrier before production. A new
carrier is its own design and may need engine changes.

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

A new identity (re-registration, reset, restore or clone) publishes a full
current-state baseline before its tail: every live record, every tombstone,
every blob claim and every completion, signed under the new writer ids. So a
peer that missed old batches, whether refused, never published, or written
between a gateway change and the next worker step, still converges. Each
re-issued record and completion orders exactly as the retained operation whose
effect it copies, own or a peer's: it keeps that operation's counter and names
its writer and operation id in the signed `revision.origin`, which
`compareRevisions` reads before the re-issue's own ids. So a re-issue never
overrides a newer write and never loses a tie the original won. A state no
retained operation explains takes a new counter, like a local write. The
baseline is published in the usual bounded, fragmented batches and resumes
from its durable cursor after a crash. A worker step first checks the
replication door (`replicationAdmitted`): once it is closed, the step does no
identity, rebaseline or publish work.

**Host requirement: rotate on every copy.** PS cannot detect that its database
is a copy. Every host path that restores, clones or reinstalls a database
(Desktop backup restore, phone restore or device transfer, reinstall onto
existing data) must call `rotateReplicaWriterIdentity` before the first new
write. If a host does not, the copy continues the old writer's sequences.
Peers that already imported the original's batch at a sequence quarantine the
copy's batch at that sequence as `batch_equivocation` and keep the first one.
Every later batch of the copy needs that quarantined predecessor, so all of
the copy's later changes stay blocked at those peers. On a database whose
replication door is closed, rotation throws `ReplicationRefusedError` and
writes nothing; that database never replicates again, so the host may ignore
the refusal.

**How a host asks.** A host does not open the database itself. It passes
`rotateReplicaWriterIdentity: true` to `createServer` or `startPersonalServer`
for a boot in which the database may be a copy. PS rotates after the
replication door and before any store of that boot captures a write, then
reports what it did as `handle.replication.writerRotation()`:

| Outcome           | Meaning                                                                     |
| ----------------- | --------------------------------------------------------------------------- |
| `rotated`         | New nonce under the same registration, before any write of this boot.       |
| `no_identity`     | No writer identity yet. The first identity draws a new nonce anyway.        |
| `replication_off` | Replication does not run in this boot (flag off or closed door). No writer. |
| `not_requested`   | The host did not ask.                                                       |

A runtime that does this exports `REPLICA_WRITER_ROTATION_CONTRACT`
(`"replica-writer-rotation-v1"`). A host must not treat a copy as handled until
the runtime reports one of the first three outcomes. Lite has no writer
identity yet; A10 must take the same request in the Lite boot options
(`replication.rotateWriterIdentity`), apply it before the first capture, and
report the same outcome in `psReady` as `replication.writerRotation`.

Copy detection belongs to the host. The hosts keep a random device binding in
the platform keystore (OS keychain, Android Keystore, iOS Keychain
this-device-only) and a copy of it next to the database, and ask for a rotation
whenever the two differ. The rule and the paths it covers are in
`unity-surfaces contracts/replica-writer-binding/`.

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
  uint64  version;         // scope version the manifest registers at
  string  batch;
  uint64  sequence;
  bytes32 previous;        // digest of the previous batch, or zero
  string  previousBatch;   // id of the previous batch, or ""
  string  collectedAt;
  bytes32 digest;          // sha256 of the assembled batch
  uint64  totalBytes;
  uint32  count;           // number of fragments
  bytes32 fragments;       // sha256 of the ordered fragment list
}
```

The fragment list digest is the SHA-256 of each fragment's 32-byte digest
followed by its length as 8 bytes, big-endian, in index order. The writer
nonce and server fields derive the writer, and so the scope
`pdpp_replica_v1.<writer>`. So the statement covers everything a receiver uses
from the manifest and its slot. The manifest carries the statement and
signature: it is the one registered object of the batch. Fragments (format
version 3) carry neither; the signed list names their exact bytes.

### 3.4 Receiver checks

In this order. Steps 1 to 6 apply to the manifest after its registration is
finalized, and before any fragment is fetched. Step 1 checks its bytes against
the registered hash. Each fragment is then checked for length and sha256
against the manifest before it is decrypted. Each failure is a typed quarantine of that
item only. A batch that fails any check never touches writer state, so it
cannot occupy a sequence or a predecessor slot of a real writer.

1. The manifest and fragment entry points share `receiveReplicaJson`
   (`core/src/replication/receive.ts`). Both read with a byte bound and a
   30-second deadline, propagate cancellation, check the packet profile,
   decrypt and scan JSON before parsing it. Read the manifest, stopping at
   the storage cap. Before any KDF runs, refuse any message outside the
   writers' profile: one v4 password packet with iterated, salted SHA-256 S2K
   at count byte 224 or less, then one v1 integrity-protected data packet.
   During decryption refuse compression before inflation. Then refuse
   plaintext nested deeper than 16 or with more structural tokens than a manifest at the fragment limit needs, before it
   is parsed. Each refusal is `manifest_invalid`, because no writer makes such
   bytes and the commitment hashes plaintext the receiver would have to make
   or parse. Check the plaintext's hash pair against the finalized
   commitment; a mismatch, or plaintext with no `collectedAt`, retries as
   `commitment_mismatch`. Only then decode. A wrapper that is not the
   canonical envelope, a zero fragment length, duplicate fragment hashes,
   negative, fractional, non-finite or unsafe numeric fields, facts that
   disagree with each other, entry bytes over the framed bound (§6), or
   anything else that throws while decoding is `manifest_invalid`. A manifest without a statement is
   `signature_invalid`. A fragment is checked against its ciphertext commitment
   before decryption, then crosses the same packet, decrypt and bounded-parse
   checks. A failed fragment check is `fragment_mismatch`; definitive storage
   absence is `fragment_missing`. Both quarantine the slot. Transient reads,
   cancellation and deadlines retry. No fragment is fetched before the manifest
   is authorized. At most 50 inbox manifests are processed per step, even if
   the host requests a larger download quantum.
2. Recover the signer. It must equal `server`, and the statement must sign
   this manifest at the version it is registered at.
3. Partition: `statement.owner`, `chainId` and `environment` must equal the
   receiver's. Addresses are compared after normalizing to lowercase.
4. Roster: the gateway record for `server` must exist, have no `revokedAt`,
   have `id` equal to `serverId`, and have `ownerAddress` equal to
   `statement.owner` (`data-gateway@37bc1fe api/v1/servers/[address].ts:122-130`).
   So roster owner, statement owner and receiver owner are one address. The
   receiver caches a roster answer for at most 5 minutes. If it cannot read the
   roster and has no fresh answer, it waits. It never accepts on an unknown
   roster. So a peer can still import a removed server's batch for up to 5
   minutes after removal, plus the gateway's CDN cache time. The check runs
   again on every import attempt, so a batch downloaded before removal is
   refused once the cached answer expires.
5. Writer ids: derive both ids from `owner`, `server`, `serverId` and
   `writerNonce`. The writer in the manifest's scope must equal the derived
   transport writer.
6. Finalized DPv2 evidence, as today.
7. Assemble and check `digest`. Every operation's `revision.writerId` must
   equal the derived operation writer. Then import.

This implements the receiver's `authenticate` hook. New codes in
`packages/core/src/replication/outcome.ts`: dependency kind `roster`;
quarantine reasons `signature_invalid`, `partition_mismatch`,
`server_not_registered`, `roster_owner_mismatch` and `writer_mismatch`. Every
refusal after the commitment check is terminal: authentic bytes do not change
on retry.

### 3.5 Removal and re-registration

The rule for testers: import only from servers that are registered now. After
a server is deregistered, peers refuse its batches that they have not yet
imported, including batches it published before removal. Data already imported
stays. Peers lose any of the removed device's changes that they had not yet
imported. Removal lag is up to 5 minutes (the receiver's roster cache) plus the
gateway CDN TTL.

The gateway lets a revoked address register again. It refuses the same
`serverId` (`data-gateway@37bc1fe lib/servers.ts:525-531`), then clears
`revokedAt` and writes the new `id` (`:533-551`). The new `serverId` makes it a
new incarnation. Writer ids include `serverId`, so the device derives new ids
and starts new sequences. Batches under the old ids name the old `serverId`,
fail step 4 and stay refused. The new incarnation inherits no writer state,
because the gap between removal and return is when a lost or copied key is most
likely in use. Its first publication is the current-state baseline (section
3.2), so peers still receive the returning device's data.

### 3.6 Known tester limits

- **Copied key.** Anyone who has a copy of a device's `key.json` (or the Lite
  identity and master key) can sign as that device and its writers until the
  owner deregisters it. Testers accept this.
- **Another device can block a peer.** Storage PUT overwrites (section 1), so
  any registered server of the owner can replace another device's stored
  ciphertext. The peer then fails the registered hash and cannot import that
  fragment. It never accepts forged data, but the overwrite destroys the
  fragment's availability and blocks that writer's later batches until the
  original content is restored. Downloading again cannot repair it.
- **Another device can take a writer's next version.** Each writer has one
  scope and registers its next version there. Any registered server of the
  owner can register its own manifest at that version first. Receivers refuse
  it (`writer_mismatch` or `signature_invalid`), so forged data is never
  imported. But the version is taken, so the writer's own manifest there fails
  with `immutable_registration_conflict` and its later manifests wait behind
  it. Nothing moves the writer past a taken version yet.
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
// putFragment(fragment, call), getFragment(scope, digest, call & { maxBytes }),
// hasFragment(scope, digest, call), put(manifest, call),
// register(manifest, call), evidence(scope, version, call),
// get(scope, version, call & { maxBytes: number }), list(cursor, call)
```

Today `get` and `getFragment` take `ReplicaRead` (`{ maxBytes, signal }`):
`get` is bounded by the storage cap and `getFragment` by the manifest entry's
length. The DPv2 adapter reads only through the storage adapter's
`downloadBounded`, which stops on `Content-Length` or cancels the stream; it
refuses at construction a storage adapter without one. Both Vana storage
adapters, signed and public-read, provide it. An oversize read throws
`ReplicaObjectRefused`. The fragment existence probe also uses a zero-byte
bounded read, never `StorageAdapter.exists`, which may buffer a whole object.
Object reads default to a 30-second deadline, including the probe; the server
worker also defaults each attempt to 30 seconds. A host can configure the
worker attempt deadline. Deadline and cancellation failures remain retries.

The adapter must stop its I/O on abort. `abortable` (`coordinator.ts:100-123`)
only drops a late result. Adapters do not retry; a failure is a verdict the
coordinator settles.

On the phone, storage object I/O is native, not the WebView's `fetch`. The host
implements `LiteReplicaObjectTransfers` (`packages/lite/src/replication-ports.ts`)
over its bridge operations `replica.download`, `replica.probe`,
`replica.upload` and `replica.cancel`
(unity-surfaces PR #1971, `apps/mobile-shell/lib/replication/native_replica_transport.dart`).
A download streams into a native byte stage that a canonical transaction
attaches (§4.3), and an upload streams attached bytes, so object bytes never
cross the bridge as one message. The native side has fixed capacity: a
transfer that does not fit fails `busy` instead of queueing, and the
coordinator defers it. Abort maps to `replica.cancel`, and each transfer
carries its own deadline. JS still encrypts and decrypts, one fragment at a
time; 1 MiB fragments fit the 1 MiB native record limit
(`unity-surfaces@9af449a2 apps/mobile-shell/lib/ps/native_ps_store.dart:11`).
The Lite engine builds core's `ReplicaTransportPort` from core's DPv2
transport over `createLiteReplicaStorage`
(`packages/lite/src/replication-storage.ts`), which moves fragment and
manifest bytes through these transfers. Gateway calls (register, evidence,
the owner feed) and the roster read stay in PS JS core, over Lite's HTTP
client, as on Node. Native code carries only bulk replica object bytes; it
has no gateway, signing or replication-state logic.

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
/** `sha256` is 64 lowercase hex characters, no `sha256:` prefix. */
export interface LiteReplicaBytesInfo {
  length: number;
  sha256: string;
}
export interface LiteReplicaBytes {
  /** <=128 KiB frames. The native side computes length and SHA-256. */
  stageBytes(chunks: AsyncIterable<Uint8Array>): Promise<string>;
  readBytes(id: string): AsyncIterable<Uint8Array>;
}
export interface LiteReplicaTransaction extends LiteCanonicalTransaction {
  attachBytes(stagingId: string, expected: LiteReplicaBytesInfo): Promise<void>;
  releaseBytes(id: string): Promise<void>;
  /** Publish attached bytes as the canonical blob `expected`, in THIS tx. */
  publishBlob(bytesId: string, expected: LiteBlobDescriptor): Promise<void>;
  /** The engine's relational state, in THIS tx. */
  readonly sql: LiteReplicaSql; // get, all, run, exec
}
```

The phase engine keeps its state in relational tables (`pdpp_transport_*`,
`pdpp_replica_*`), so the native transaction also answers SQL. The native
side must provide:

- **One database, one transaction.** The tables live in the same SQLite
  database as the canonical rows, blobs and replica bytes. One `transaction`
  commits or rolls back all of them together.
- **SQLite 3.25 or later, with JSON1.** The engine uses window functions,
  `INSERT ... ON CONFLICT DO UPDATE`, `json_extract`, triggers, and reads
  `sqlite_master` and `PRAGMA table_info`.
- **Fixed statements only.** PS sends only its own statements. Parameters are
  text, integers, `null` or bytes; a byte value is at most one fragment
  (1 MiB). An absent row is `undefined` (a bridge `null` is accepted).
- **Savepoints.** `SAVEPOINT`, `RELEASE` and `ROLLBACK TO` sent through `sql`
  must also cover the transaction's key-value, blob and byte writes. The
  import of a received batch runs in a savepoint, so a refused import rolls
  back alone.
- **`publishBlob`.** A received blob arrives as replica bytes, verified only
  after the whole payload is, so it cannot use `stageBlob`. `publishBlob`
  checks length and SHA-256 against the descriptor and publishes the blob in
  the same transaction, as `attachBlob` does. The bytes stay attached until
  `releaseBytes`.

A new writer identity (the first enable, or a rotation) re-exports the
canonical state into the outbox (`rebaseline` in `canonical-store.ts`), so a
phone that wrote before it enabled still publishes those rows. Each row and
completion copies the operation the merge chose for it and keeps its counter,
origin and declaration (core `rebaseline.ts`). Lite keeps no binding history,
so a row the merge does not explain, such as one whose stream the host no
longer declares, is skipped.

Bounded growth on the phone:

- **Outbox.** Once a batch's manifest registration is confirmed on the
  gateway, the engine calls `exporter.acknowledgePublished(next)` in the same
  transaction, and Lite drops its outbox entries below `next`. Node keeps its
  journal: rebaseline, completion dependencies and receiver merges read it.
- **Orphaned bytes.** `attachBytes` records the id in
  `pdpp_lite_replica_transient`, and `releaseBytes` removes it, in the same
  transaction. A crash between them leaves the id listed, and the next step
  releases every listed id before it stages anything.
- **Refused batches.** A received batch the canonical store refuses
  (`LiteCanonicalRefusal`: over the batch or partition bound, wrong owner,
  binding mismatch, reused commit id, blob metadata conflict) cannot import on
  a retry. The engine records it terminal with reason `canonical_<reason>`
  and quarantines that writer from that batch. Other writers keep importing.

The engine runs every storage effect in its own native transaction. One idle
step takes about 40 transactions; the step that publishes or imports takes
more (about 110 in the two-writer trace).

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

`createReplicationDriver` (`packages/core/src/replication/host-driver.ts`)
implements this timer, single-flight `trigger`, `wake` and `stop(graceMs)` for
both hosts. Node wires it in `pdpp-replication-host.ts`; Node fires no
local-write trigger yet, so a local write waits for the next coordinator wake
(at most 15 min).

PS-Lite wraps the same driver in `createLiteReplicationRuntime`
(`packages/lite/src/replication-runtime.ts`): `resume` on foreground,
`pause` on background, `trigger(reason)` for the other triggers, and a step
deadline from `limits.step.deadlineMs`. `createPsLiteRuntime` calls `resume`
and `pause` from `activate` and `deactivate` and serves owner-only
`GET /v1/replication/status` and `POST /v1/replication/sync` (202, the step
runs after the answer; 409 when replication is not running). Its status is
the driver's (`stepping`, `lastStepAt`, `nextWakeAt`, last-step counts), not
yet the peer, pending and server fields above.

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
- **Receive bound:** a manifest read stops at the storage cap and a fragment
  read at its entry's length. A received OpenPGP message runs at most one
  iterated SHA-256 KDF over 16 MiB, and received JSON is at most 16 deep
  (`REPLICA_MAX_JSON_DEPTH`). Fragment reads count against the step's byte
  budget. The sum of a manifest's entry bytes must fit
  `replicaFramedBytesBound(totalBytes, count)` (`transport.ts`): the base64
  of the signed `totalBytes` plus a fixed per-fragment overhead. This is a
  consistency bound on what one batch can make a peer fetch, not a size cap.
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
the whole batch (`pdpp-replication-transport.ts:579`). An item larger than an
explicit byte budget is deferred until a budget fits it (`coordinator.ts`), so
on the phone a batch over 8 MiB never publishes until item 1 below lands. Preparation also frames a whole batch in one run and discards partial
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
