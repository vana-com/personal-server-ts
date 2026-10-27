# Replication host contract and security design

Status: proposed (D0). Date: 2026-10-27.
Decision record: [ADR 0001](adr-0001-transport-and-device-identity.md).

This document is the contract between the replication engine in this repository
and the two hosts that run it: the Desktop app (Node PS sidecar) and the phone
app (PS Lite in a WebView). It covers five subjects:

1. The transport backend that carries replica batches between devices.
2. Device identity and security.
3. The TypeScript ports that each host must supply.
4. The opt-in flow and the one-way door.
5. The limits for internal testers and the acceptance suite.

It is written so that the Desktop host work, the phone host work, device keys
(A11) and opt-in (D1) can start from it without re-reading the replication code.

## How to read the citations

Every claim about current code has a citation. Replication code is not on
`main` yet. It is on PR #483, branch `tnunamak/replication-flag-landing-1026`,
head `ea4c18cf1463e425adaac6d9d30c5eec72c4810f`. Citations without a repository
name refer to that commit. Citations to `main` use `main@b4e42412`. Other
repositories are cited as `repo@sha path:line`:

- `unity-surfaces@9af449a2` (Desktop, phone and Account apps)
- `vana-storage@b1d3d83`
- `data-gateway@37bc1fe`

## 1. What exists today

### 1.1 The engine is complete but not wired

- `replication.enabled` defaults to `false`
  (`packages/core/src/schemas/server-config.ts:54-59`, schema at `:218-222`).
- Bootstrap reads the flag only to open the record store
  (`packages/server/src/bootstrap.ts:953`, `:971`, `:976`). The record-store
  bootstrap states "This boot has no replica receiver"
  (`packages/server/src/pdpp/records-bootstrap.ts:78`). No code outside
  `packages/server/src/storage/` calls `createReplicaTransportWorker` or
  `createReplicaReceiver`.
- Lite has a canonical store with replica authentication as an injected
  dependency (`packages/lite/src/canonical-store.ts:204`). It throws when
  replication is disabled (`:216`). Lite has no transport, runtime or route
  wiring for replication.
- The Desktop app does not pass a replication flag when it starts the sidecar
  (`unity-surfaces@9af449a2 apps/desktop/src/hooks/usePersonalServer.ts:871-885`).
  Its derived config already has a sibling `sync: { enabled: true }` block
  (`apps/desktop/personal-server/derived-config.mjs:85`), so the config path
  exists.
- The phone has no replication code. Its PS bundle pins Lite
  `0.0.1-canary.b4e4241`.

### 1.2 The transport port

`ReplicaTransportPort` (`packages/core/src/replication/dpv2.ts:64-77`) has
`encrypt`, `decrypt`, `evidence`, `put`, `register`, `get` and `list`. No method
takes an `AbortSignal`. The only implementation is
`createDpv2ReplicaTransport` (`dpv2.ts:80-129`):

| Method     | What it does                                                                       | Citation          |
| ---------- | ---------------------------------------------------------------------------------- | ----------------- |
| `encrypt`  | OpenPGP with a password from `deriveScopeKey(masterKey, scope)`                    | `dpv2.ts:92-98`   |
| `put`      | `storage.upload("<scope>/1")` to vana-storage                                      | `dpv2.ts:100-102` |
| `register` | `gateway.registerDataPoint` at `expectedVersion "1"`, signed by the AddData signer | `dpv2.ts:103-116` |
| `evidence` | Finalized DataRegistryV2 commitment for the scope                                  | `dpv2.ts:131-192` |
| `list`     | The owner's data-point feed, `includeDeleted`, from a cursor                       | `dpv2.ts:118-127` |

So each fragment is one vana-storage object, one gateway registration and one
on-chain commitment. The scope grammar is
`pdpp_replica_v1.<writer>_<batch>.<index>`
(`packages/core/src/replication/transport.ts:44-53`).

Fragment limits (`transport.ts`): at most 100,000 fragments per batch, and at
most 100 MiB per stored object, which is the vana-storage limit (`:11-13`). The
default chunk is 4 MiB (`:210`), halved adaptively when a fragment is too large
(`:190-246`). There is no limit on the size of a record blob. The fragment schema is
`format: "vana-pdpp-replica-fragment"`, `version: 1` (`:17-34`).

### 1.3 Identity today

- **Server key.** Each Node install has a random secp256k1 key in `key.json`,
  written with mode `0600` (`packages/server/src/keys/server-account.ts:37`,
  `:56`). The owner registers it at the gateway with a signed
  `ServerRegistration`. The AddData signer must be such a registered server
  (`packages/core/src/signing/signer.ts:26-36`).
- **Lite server key.** Lite keeps an encrypted server identity
  (`packages/lite/src/state.ts:66-79`). Its AES key is
  `deriveScopeKey(masterKey, "ps-lite.server-identity")` (`state.ts:129-141`).
  The phone harness creates the keypair and the owner signs its
  `ServerRegistration`
  (`unity-surfaces@9af449a2 apps/mobile-shell/ps_bundle/src/harness.js:585-598`,
  `:1559-1565`). Lite sync replaces this signer with an owner signer for storage
  and AddData (`packages/lite/src/sync.ts:250-263`).
- **Writer ids.** The transport worker inserts a random writer token on first
  use (`packages/server/src/storage/pdpp-replication-transport.ts:287-299`,
  `randomUUID` at `:291`). The canonical port inserts a separate random
  installation writer id (`packages/server/src/storage/pdpp-replica-canonical-port.ts:113-118`).
  Both are random. Neither is bound to a key.
- **Receiver authentication.** `createReplicaReceiver` takes
  `authenticate(credential)` as an injected function. Its comment says the host
  "must verify a replica-specific credential"
  (`packages/server/src/storage/pdpp-replication-receiver.ts:122-132`). No such
  credential exists yet.
- **Revocation.** The gateway returns each server record with `revokedAt` and an
  attestation that includes the owner's registration signature
  (`data-gateway@37bc1fe api/v1/servers/[address].ts:129`, `:132-145`). Deregistration
  is an owner-signed soft delete (`:34-36`). vana-storage accepts writes from
  the owner or a registered, non-revoked server
  (`vana-storage@b1d3d83 src/auth/gateway-client.ts:26`) and caches that check
  for 60 s (`src/config.ts`, `AUTH_CACHE_TTL_SECONDS`). Account already has a
  deregistration intent route
  (`unity-surfaces@9af449a2 apps/account/src/app/api/v1/intents/personal-server-deregistration/sign`).

### 1.4 Scheduling today

The coordinator runs one bounded `step(now, signal, budget)` and returns a
`ProgressReport` with `nextWake`
(`packages/core/src/replication/coordinator.ts:378-498`, `nextWake` at
`:492-496`). Its comment states the rule this contract keeps: "The host
schedules step(); it never runs another semantic retry loop" (`:158-161`).
Each phase handler must honour the abort signal and commits each verdict in one
transaction (`:52-88`). Backoff runs from 1 s to 1 h
(`packages/core/src/replication/schedule.ts:186-187`); a wait without a known
deadline is retried after 60 s (`:212`). The worker's `step({budget, signal})`
returns at once when replication is disabled or a step is already running
(`pdpp-replication-transport.ts:1941-1944`).

### 1.5 Measured cost of the DPv2 carrier

From the live dev runs on 2026-10-21:

- Chain finality between two devices: median 122 s, p90 134 s. The finalized
  head lags 96 to 138 s.
- On Lite, one 101 MiB blob became 4,310 fragments. Each fragment was one PUT
  and one AddData registration.
- Lite's worst step grew memory by 77.6 MiB for one 8 MiB inbound fragment.

### 1.6 Retention today

Nothing in #483 caps retained replica bytes. The outbox stores both the
plaintext and the encrypted fragment, and the batch table stores the payload
(`pdpp-replication-transport.ts:79-110`). `pdpp-replication.md` says the
baseline and fence are retained indefinitely with no compaction. A device that
returns after weeks offline rescans the owner feed from its last cursor, so its
catch-up cost grows with all history since then.

## 2. Transport backend

### 2.1 Decision

- **Internal testers:** keep the DPv2 carrier exactly as built. It passed live
  dev runs and changing it now would reset that evidence.
- **Production:** a store-and-forward mailbox in vana-storage. Each fragment is
  one write-once object. A device-signed batch statement replaces the per-fragment
  gateway registration and chain commitment. The gateway is used only for the
  device roster (server registrations). This is a second implementation of the
  same carrier port (section 4.2), so the engine does not change.

### 2.2 Why the mailbox

| Need                     | DPv2 carrier (today)                            | Storage mailbox (production)                          |
| ------------------------ | ----------------------------------------------- | ----------------------------------------------------- |
| Latency between devices  | About 2 min, set by chain finality              | One PUT and one list call                             |
| Cost per fragment        | PUT plus AddData plus a chain commitment        | One PUT                                               |
| Public metadata          | Scope names, sizes and timing on chain          | Sizes and timing visible to the storage operator only |
| Registry growth          | One data point per fragment, forever            | None                                                  |
| Device offline for weeks | Works, but rescans all history since its cursor | Works; retention keeps unacknowledged batches         |
| Authenticity             | Registered server signs AddData                 | Device key signs each batch (section 3)               |

Rejected options:

- **PS-to-PS relay.** Both devices must be online at the same time. The phone
  replicates only in the foreground and the Desktop sleeps, so two devices
  would rarely meet. A relay also adds a new always-on service.
- **Gateway mailbox.** The gateway is a registry. Putting replica bytes there
  adds load and a new data class to a service that this repository does not own.

### 2.3 Mailbox contract

**Addressing.** Keys are `<owner>/pdpp_replica_v2/<writer>/<sequence>/<index>`,
with the sequence zero-padded so that a prefix list returns batches in order.
The object body is the encrypted fragment (format version 2, section 3.5).

**Auth.** Unchanged from today. vana-storage accepts a write signed by the owner
or by a registered, non-revoked server of that owner
(`vana-storage@b1d3d83 src/auth/gateway-client.ts:26`). Reads use the same
delegation. The storage check is a first barrier only. The receiver's signature
check (section 3.6) is the authority.

**Size.** vana-storage accepts up to 100 MiB per object today
(`vana-storage@b1d3d83 src/config.ts`, `DEFAULT_MAX_BLOB_SIZE`). The carrier
keeps fragments much smaller: 4 MiB on Node and 1 MiB on Lite (section 6).

**Write-once.** Storage already rejects a different body at an existing key
(`packages/core/src/storage/adapters/interface.ts:73-83`,
`StoredBlobConflictError`). The carrier treats a repeat PUT of identical bytes
as success, so a retry after a lost acknowledgement is safe.

**Retention.** Each device writes its acknowledgement horizon (the highest
contiguous imported sequence per writer) as a small signed object under
`<owner>/pdpp_replica_v2/_ack/<device>`. A device that has been offline holds
the horizon back. The rule is: a writer may delete its own batches below the
minimum horizon of all non-revoked devices. But a device that joins later has
no horizon and needs the full history, and no snapshot bootstrap exists. So
until one exists, writers delete nothing, retention is indefinite, and the
retained-bytes cap in section 6 is the only bound.

**Offline for weeks.** The device lists from its saved cursor and imports in
sequence order. Nothing is lost because nothing below its horizon was deleted.
If a device is revoked while offline, its horizon stops counting and its
own new batches are refused (section 3.7).

**vana-storage work required** (not in this PR):

1. A list-by-prefix endpoint with a cursor that returns each object's write
   time (needed for revocation, section 3.7). Today storage has PUT, GET and
   DELETE on blobs but no list (`vana-storage@b1d3d83 src/blobs/routes.ts:74`,
   `:184`, `:272`).
2. Deletion by the writer of its own objects under the mailbox prefix.
3. Optional presigned GET URLs for large objects, so the phone can stream a
   fragment without proxying through the Worker.

## 3. Device identity and security (A11)

### 3.1 Rules

- A device has its own replication key. It is not the Android attestation
  subject and not the wallet.
- The wallet never signs batches. The master-key signature only derives
  encryption keys. It is not a replica key.
- The owner proves membership once, through the existing `ServerRegistration`.
  No new owner signature is needed per device.

### 3.2 The device key

A P-256 ECDSA key per device and per owner partition (owner, environment,
network). P-256 because both platform secure keystores support it and secp256k1
is not supported in hardware on either phone platform.

| Host    | Storage                                                                                                                                                  | Exportable      |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
| Android | Keystore, StrongBox when available, else TEE. Alias namespace `vana.mobile.replica-device-key.v1`.                                                       | No              |
| iOS     | Secure Enclave key. Accessibility `AfterFirstUnlockThisDeviceOnly`.                                                                                      | No              |
| Desktop | PKCS#8 key in the OS keychain through the existing keyring wrapper (`unity-surfaces@9af449a2 apps/desktop/src-tauri/src/commands/keyring.rs:20`, `:60`). | Yes (see below) |

Phone keys require no user presence and no biometry, and Android does not set
`unlockedDeviceRequired`, because replication runs only in the foreground
(section 3.10) and a prompt per batch is not acceptable.

The alias namespace is separate from the attestation subject store
(`apps/mobile-shell/lib/attestation/secure_android_installation_subject_store.dart:23-39`),
which serves Account attestation only.

On Desktop, the app reads the key from the keychain and passes it to the
sidecar at launch, the same way it passes `VANA_MASTER_KEY_SIGNATURE` today
(`apps/desktop/src-tauri/src/commands/server.rs:1150-1169`). The sidecar keeps
it in memory only. Processes of the same OS user can read the environment of
the sidecar. This is the same exposure the master-key signature has today.

The phone's JS cannot read the key. The host exposes `sign(bytes)` over the
bridge and returns a 64-byte IEEE P1363 signature (`r || s`).

### 3.3 The device certificate

The registered server key signs one certificate per device. EIP-712 typed data:

```
domain: { name: "Vana PDPP Replica", version: "1", chainId }
PdppReplicaDevice {
  address owner;           // owner wallet
  address server;          // registered server address that signs this
  string  transportWriter; // pdpp_transport_state.writer
  string  operationWriter; // pdpp_installation_writer id
  bytes   deviceKey;       // SPKI DER of the P-256 public key
  uint64  issuedAt;        // ms since epoch
  uint32  certVersion;     // starts at 1
}
```

This binds the two random writer ids (section 1.3) to one key and to one
registered server. Signing on Node uses the server account from
`server-account.ts:37`; on Lite it uses the Lite server identity.

### 3.4 Trust chain

```
owner wallet
  └─ ServerRegistration (gateway record, revokedAt, gateway attestation)
       └─ PdppReplicaDevice certificate, signed by the server key
            └─ batch statement, signed by the device key
```

### 3.5 The batch statement and fragment format v2

The statement is canonical JSON:

```
{
  "format": "vana-pdpp-replica-batch-statement",
  "owner", "writer", "batch", "sequence", "previous",
  "collectedAt", "digest", "totalBytes", "count",
  "certificate": "<sha256 of the certificate>"
}
```

Fragment format version 2 adds three fields to the version 1 schema
(`transport.ts:17-34`): the statement, the device signature over it, and the
certificate. Fragment 0 carries the full certificate; the other fragments carry
its digest. The fields are inside the encrypted body, so storage sees none of
them.

### 3.6 Receiver checks

In this order, and each failure is a typed outcome, never a thrown string:

1. Decrypt, then decode the fragment.
2. Verify the device signature over the statement with the certificate's key.
3. Verify the certificate signature against `server`, and check the roster:
   the gateway record for `owner` and `server` exists and is not revoked. The
   roster answer is cached for at most 1 hour. If the roster cannot be read and
   no cached answer exists, the receiver waits; it never accepts.
4. Check that the statement's `writer` equals `certificate.transportWriter`.
5. DPv2 carrier only: check finalized registration evidence, as today.
6. Assemble the batch and check its digest against the statement.
7. Check that every operation's `revision.writerId` equals
   `certificate.operationWriter`. Then import.

New outcome codes in `packages/core/src/replication/outcome.ts`:

- dependency kind `device` (roster not yet readable) alongside the existing
  kinds at `:19-32`;
- quarantine reasons `device_revoked`, `signature_invalid` and
  `device_binding_conflict` alongside `:120-129`;
- problem `roster_unavailable` alongside `:38-53`.

The receiver's `authenticate(credential)` dependency
(`pdpp-replication-receiver.ts:122-132`) is implemented by steps 2 to 4.

### 3.7 Revocation

The owner revokes a device by deregistering its server through the existing
Account intent. The receiver then compares the batch time with `revokedAt`:

- DPv2 carrier: the finalized block timestamp of the batch's registration.
- Mailbox: the storage write time of fragment 0, as reported by the storage
  list call. A stolen key cannot backdate this. It relies on the storage
  operator being honest, which is Vana's own service.

A batch written before `revokedAt` is accepted. A later batch is quarantined as
`device_revoked`. Data already imported stays. Revocation lag is the gateway CDN
TTL plus the 60 s storage cache plus the receiver's roster cache (at most 1 h).

### 3.8 Rotation and loss

- **Internal testers:** no rotation. A reinstalled or reset device is a new
  device with new writer ids.
- **Later:** a new certificate with a higher `certVersion` and the sequence it
  takes effect from. Receivers keep the old key valid for sequences below that.
- **Lost key** (keystore wiped, app data cleared, OS restore without keys): the
  host reports the typed refusal `device_identity_lost`. The device cannot sign
  as the old writer again. It can only start again as a new device. This is
  one-way.

### 3.9 Encryption at rest in transit storage

Fragments stay encrypted with OpenPGP under a per-scope key derived from the
owner master key (`dpv2.ts:92-98`). The storage operator sees ciphertext,
sizes, timing and opaque writer tokens.

Known limits, stated plainly:

- Account infrastructure can regenerate the master-key signature
  (`unity-surfaces@9af449a2 apps/mobile-shell/lib/auth/owner_device_signer.dart:7-18`),
  so Account can derive the keys. This is the same as every other owner scope
  today.
- A revoked device keeps the master key and can still decrypt new batches if it
  can read them. Revocation stops its writes, not its reads.

A production option closes the second gap: encrypt each batch with a random
content key and wrap that key to each non-revoked device's public key. This is
open question (b).

### 3.10 Phone locked or in background

Replication on the phone runs only in the foreground. When the app lifecycle
becomes `inactive`, `paused` or `hidden`, the host aborts the current step's
signal and stops scheduling. It resumes on foreground. The iOS owner binding is
`unlocked_this_device` (`apps/mobile-shell/lib/auth/secure_owner_binding_store.dart:67-88`),
so the vault is closed while the phone is locked in any case.

## 4. Host ports

These are the interfaces the engine needs from a host. Node and Lite implement
the same ports. They do not change the visibility engine, so they do not depend
on phase-2 PR1 (visibility evaluate and commit), which has not landed. They use
the outcome types of PR5 (`outcome.ts`) and the coordinator of PR6
(`coordinator.ts`), both already on #483.

### 4.1 Boot configuration

```ts
/** Passed by the host at PS start. Absent means off. */
export interface ReplicationBootConfig {
  /** The host's per-device opt-in record says "on" (section 5). */
  enabled: boolean;
  owner: `0x${string}`;
  environment: "dev" | "prod";
  network: string;
  carrier: "dpv2" | "mailbox";
  limits: ReplicationLimits;
}

export interface ReplicationLimits {
  /** Largest record blob a batch may carry. A larger one makes its batch Unsupported. */
  maxReplicatedBlobBytes: number;
  /** Fragment size target before adaptive halving. */
  targetFragmentBytes: number;
  /** Outbox plus inbox plus batch payload bytes for this owner partition. */
  maxRetainedBytes: number;
  step: { units: number; bytes: number; deadlineMs: number };
}
```

PS validates the limits and refuses to start replication on an invalid value,
as the worker does today for its storage-object cap
(`pdpp-replication-transport.ts:229-231`). `targetFragmentBytes` must stay
below the vana-storage object limit (`REPLICA_MAX_BLOB_BYTES`,
`transport.ts:11-13`). `maxReplicatedBlobBytes` is new: the engine has no
record-blob limit today.

### 4.2 Carrier

The carrier replaces the I/O half of `ReplicaTransportPort`. Encryption moves
to its own port because it does no I/O and needs no signal.

```ts
export interface ReplicaCall {
  signal: AbortSignal;
  /** The carrier stops reading and rejects when a response passes this size. */
  maxBytes?: number;
}

export interface ReplicaCarrier {
  readonly owner: `0x${string}`;
  readonly finality?: ReplicaFinalityHints;
  /** Write-once. Identical bytes at an existing key resolve. Different bytes reject. */
  put(fragment: PreparedFragment, call: ReplicaCall): Promise<void>;
  /** DPv2: AddData at expectedVersion 1. Mailbox: resolves at once. */
  register(fragment: PreparedFragment, call: ReplicaCall): Promise<void>;
  /** DPv2: finalized commitment. Mailbox: storage write time of fragment 0. */
  evidence(
    scope: string,
    call: ReplicaCall,
  ): Promise<ReplicaRegistrationEvidence>;
  get(
    scope: string,
    call: ReplicaCall & { maxBytes: number },
  ): Promise<Uint8Array>;
  list(
    cursor: string | null,
    call: ReplicaCall,
  ): Promise<{ scopes: string[]; cursor: string | null }>;
}

export interface ReplicaCipher {
  encrypt(scope: string, plaintext: Uint8Array): Promise<Uint8Array>;
  decrypt(scope: string, encrypted: Uint8Array): Promise<Uint8Array>;
}
```

The carrier must really stop its I/O on abort. `abortable`
(`coordinator.ts:100-123`) only drops a late result; it cannot stop a request.

On the phone, the carrier is the WebView's `fetch` with the signal and a byte
cap on the response body. Bytes must enter JS anyway because decryption runs in
JS. Fragments of at most 1 MiB keep this inside the bridge limits
(`apps/mobile-shell/lib/ps/native_ps_store.dart:11`, 1 MiB records). The native
download path (`apps/mobile-shell/lib/connect/host_download.dart:24-31`) is not
needed for replication.

### 4.3 Device key and roster

```ts
export interface ReplicaDeviceKeyPort {
  /** SPKI DER, or undefined when this partition has no key yet. */
  publicKey(): Promise<Uint8Array | undefined>;
  /** Creates the key if absent. Never replaces an existing key. */
  create(): Promise<Uint8Array>;
  /** ECDSA P-256 over SHA-256(message). Returns 64 bytes, r || s. */
  sign(message: Uint8Array, signal: AbortSignal): Promise<Uint8Array>;
}

export interface ReplicaRosterPort {
  server(
    owner: `0x${string}`,
    server: `0x${string}`,
    call: ReplicaCall,
  ): Promise<{ registered: boolean; revokedAt?: number }>;
}
```

The roster reads the gateway server record, which includes `revokedAt`
(`data-gateway@37bc1fe api/v1/servers/[address].ts:129`). The owner listing
`GET /v1/servers?owner=` (`api/v1/servers.ts:57`) gives the set of devices for
the retention horizon (section 2.3).

If `publicKey()` returns `undefined` after the device has already written a
batch, PS reports `device_identity_lost` (section 3.8) and does not create a new
key under the old writer.

### 4.4 Persistence

**Node.** The SQLite database the worker already owns. No change.

**Lite.** `LiteCanonicalPersistence`
(`packages/lite/src/canonical-persistence.ts:16-42`) holds state rows in a
transaction, with values of at most 256 KiB and frames of at most 128 KiB. Its
blob methods take a record `blob-claim` descriptor (`:3-6`), so they do not fit
replica fragments. Lite adds generic byte storage:

```ts
export interface LiteReplicaBytes {
  /** Backpressured <=128 KiB frames. Native side computes length and SHA-256. */
  stageBytes(chunks: AsyncIterable<Uint8Array>): Promise<string>;
  readBytes(id: string): AsyncIterable<Uint8Array>;
}

export interface LiteReplicaTransaction extends LiteCanonicalTransaction {
  /** Publish staged bytes in THIS transaction after checking length and hash. */
  attachBytes(
    stagingId: string,
    expected: { length: number; sha256: string },
  ): Promise<void>;
  /** Free bytes in THIS transaction, e.g. when retention drops an outbox row. */
  releaseBytes(id: string): Promise<void>;
}
```

The native store already runs transactions
(`apps/mobile-shell/lib/ps/native_ps_store.dart:315`). These four methods are
the only new native surface for replication persistence.

### 4.5 Scheduler

The host owns the timer. PS owns everything else.

```ts
export interface ReplicationRuntime {
  /** Single-flight. A call while a step runs returns that step's report. */
  step(input: {
    budget: ReplicaBudget;
    signal: AbortSignal;
  }): Promise<ProgressReport>;
  /** Make waits on this dependency due now (wraps onDependencyChanged). */
  wake(dependency: ReplicaDependency): void;
  status(): ReplicationStatus;
  start(config: ReplicationBootConfig): Promise<void>;
  /** Aborts the running step and waits at most `graceMs` for it to settle. */
  stop(graceMs: number): Promise<void>;
}
```

The host loop:

1. Call `step` with the limits' budget and a signal.
2. Arm one timer at `nextWake`, clamped to between 1 s and 15 min. If
   `nextWake` is undefined, arm the 15 min timer.
3. Call `step` early on these triggers: app comes to the foreground, a local
   write commits, the network comes back, the user taps "Sync now".
4. On the phone, stop on background (section 3.10).

`ReplicaBudget` and `ProgressReport` are the coordinator's types
(`coordinator.ts:125-152`; `step` at `:378`).

### 4.6 Status

```ts
export interface ReplicationStatus {
  state: "off" | "on" | "paused" | "refused";
  refusal?:
    | "reenable_refused"
    | "device_identity_lost"
    | "entitlement_none"
    | "invalid_limits";
  device?: {
    server: `0x${string}`;
    transportWriter: string;
    operationWriter: string;
  };
  peers: {
    transportWriter: string;
    lastImportedSequence: number;
    revoked: boolean;
  }[];
  outbox: {
    batches: number;
    bytes: number;
    retainedBytes: number;
    capBytes: number;
  };
  problems: ProgressReport["problems"];
  lastStepAt?: number;
  nextWakeAt?: number;
}
```

This is a read model for the host UI and for tests. It is not a control surface.

### 4.7 Who owns retries, deadlines and cancellation

| Concern                      | Owner        | How                                                                    |
| ---------------------------- | ------------ | ---------------------------------------------------------------------- |
| Semantic retries and backoff | Coordinator  | `settleReplicaWork` (`schedule.ts:222-291`), 1 s to 1 h                |
| Deadline per attempt         | Coordinator  | `deadlineMs` (`coordinator.ts:162-181`, race at `:222-259`)            |
| When to call `step`          | Host         | Timer at `nextWake` plus triggers (section 4.5)                        |
| Cancellation                 | Host         | Aborts the step signal on stop, background or sign-out                 |
| Stopping I/O                 | Carrier      | Honours the signal for real (section 4.2)                              |
| Durable effects              | Phase commit | One transaction per verdict (`coordinator.ts:52-88`)                   |
| HTTP-level retry             | Nobody       | Carriers do not retry. A failure is a verdict the coordinator settles. |

## 5. Opt-in and the one-way door (D1)

### 5.1 Flow

```
Account entitlement  →  client UI  →  host opt-in record  →  PS replication.enabled
```

1. **Account.** `GET /api/v1/replication/entitlement`, authenticated by the
   Account session, returns
   `{ entitlement: "replication_internal", state: "allowed" | "paused" | "none", ttlSeconds }`.
   It reuses the existing `isAdminEmail(email, source)` domain check
   (`unity-surfaces@9af449a2 apps/account/src/lib/auth/admin-domains.ts:16-55`)
   with a new source variable `ACCOUNT_REPLICATION_EMAIL_DOMAINS`. CORS follows
   the enclave-eligibility route.
2. **Not a security boundary.** Like enclave eligibility, which is documented as
   "UI state, not a bearer token"
   (`apps/account/src/app/api/v1/personal-server/enclave-eligibility/route.ts:1-7`),
   this answer controls the UI and the host. Anyone can run their own PS with
   the flag on. The security boundary is the device certificate and the roster
   (section 3).
3. **Client.** Shows the "Turn on sync between devices" control only when the
   state is `allowed`.
4. **Host.** On confirmation, writes the per-device opt-in record and restarts
   PS with `enabled: true`.
5. **`paused`.** A remote stop. The host stops calling `step`. Local capture
   continues. This does not trigger the one-way door.

### 5.2 Where each device's "on" state lives

The host owns a record per owner partition, `replication-optin.v1`:

```ts
{ state: "on" | "off_after_on"; enabledAt: number; disabledAt?: number }
```

Desktop keeps it with its other app settings and passes it through derived
config, next to `sync` (`apps/desktop/personal-server/derived-config.mjs:85`).
The phone keeps it with the owner binding and passes it in the Lite boot
options. No record means never enabled.

### 5.3 The one-way door

Turning replication off is permanent on that device. Re-enable is refused.
No data is deleted.

Today #483 allows off, then on: enabling again takes a new baseline that
includes rows written while off
(`packages/server/src/storage/pdpp-replication-flag.test.ts:313`). It refuses
re-enable only after a connection method transition made while off (`:593`).
The door (plan item A1) is new work.

PS is the authority, not the host record, because the host record can be lost
or edited:

- On the first open of a once-enabled database with the flag off, PS writes a
  durable marker in that database. A later enabled open with the marker returns
  the status `refused` with `reenable_refused`.
- A build without A1 writes no marker. To catch a downgrade to such a build,
  each capture transaction also records the record-store write clock, which is
  monotonic (`main@b4e42412 packages/server/src/storage/pdpp-records-sqlite-store.ts:202`,
  `pdpp_write_clock`). Tail capture runs in the same transaction as the write
  (`packages/server/src/storage/pdpp-replication.md`, "Capture and retention").
  So on an enabled open, a write clock above the last captured value means
  writes happened without capture, that is, while off. PS refuses in the same
  way.

Clone and restore of a database are a separate problem: the copy must take a
new writer identity before it writes (`pdpp-replication.md`, "Capture and
retention"). This design does not change that.

Before the door closes, the host opens the store once more with the flag on.
That open restores the plain blob row for any blob written by the earlier
chunk-only build (`pdpp-replication-flag.test.ts:198-238`), so every blob stays
readable with the flag off.

Confirmation copy:

> **Turn off sync on this device?**
> This is permanent for this device. Your records stay here. This device stops
> sending changes to your other devices and stops receiving theirs.

## 6. Internal-tester limits

Initial values. D2 measures them and may change them.

| Limit                   | Desktop          | Phone                |
| ----------------------- | ---------------- | -------------------- |
| Largest replicated blob | 32 MiB           | 32 MiB               |
| Fragment target         | 4 MiB            | 1 MiB                |
| Retained replica bytes  | 4 GiB            | 1 GiB                |
| Warning at              | 80 %             | 80 %                 |
| Step budget             | 50 units, 64 MiB | 20 units, 8 MiB      |
| Step deadline           | 30 s             | 30 s                 |
| Background replication  | Yes              | No (foreground only) |

At the retained-bytes cap, the coordinator stops preparing new batches and
reports this in status. Local capture never fails because of replication.

A record blob over 32 MiB uses the existing Unsupported admission
(`pdpp-replication-transport.ts:628-666`) with a new capability string
`blob:<limit>`. This has a real cost. Unsupported is terminal for that batch
only, and the writer keeps publishing later batches. But a peer holds every
later batch from that writer as Wait(predecessor) until the cap rises and
`readmitUnsupported()` runs (`:2004-2017`). So one oversized blob stops that
device's changes from reaching its peers. Status must show this, with the
blob's size and the limit. This is open question (d).

The measured worst case was 4,310 fragments for one 101 MiB blob on Lite
(section 1.5), about 24 KiB per fragment. At that rate a 32 MiB blob is still
about 1,400 fragments. D2 must measure the real fragment count and peak memory
for a 32 MiB blob on the phone before the limit is final.

## 7. Two-device acceptance suite (D2)

D2 runs one Desktop and one phone (or two Lite hosts in CI) against dev. It
must prove each of these, with a test that fails if the property fails:

1. A write on A appears on B, and the reverse.
2. A restart of either device during a step loses nothing and duplicates
   nothing.
3. Edits made while B is offline arrive when B returns, in order.
4. A lost PUT or registration acknowledgement is retried without a duplicate or
   a conflict.
5. Late finality: B waits and then imports; it never imports unproven data.
6. Blobs at 1 MiB − 1, 1 MiB, 1 MiB + 1 and 32 MiB replicate. A 32 MiB + 1
   blob makes its batch Unsupported, status shows it on both devices, and
   raising the cap and re-admitting completes replication.
7. Deletion, reset and quarantine reach the peer with the right outcome.
8. Completion: both devices report the same record set and cursors after quiet.
9. Flag off: no step runs and nothing is sent or read.
10. One-way door: turning off and then on is refused, including after a
    downgrade to a build that writes no marker.
11. Revocation: batches after `revokedAt` are quarantined; earlier ones stay.
12. A tampered statement, certificate or fragment is quarantined as
    `signature_invalid` or `device_binding_conflict`.
13. Key loss gives `device_identity_lost`, and the device cannot write as the
    old writer.
14. Switching account or network on one device does not mix partitions.
15. Phone background aborts the running step within the grace time, and the
    next foreground step completes the work.

## 8. Open questions

These need a product or security decision.

- **(a)** Should production stop registering replication data on chain and use
  the storage mailbox? Replica data would then have no public DataRegistry
  evidence.
- **(b)** Is master-key encryption enough, or must each batch key be wrapped to
  each device? This decides whether a revoked device can still read new
  batches.
- **(c)** Which email domains are eligible for the tester entitlement?
- **(d)** Are the tester caps in section 6 (32 MiB blob, 4 GiB and 1 GiB
  retained) acceptable, given that one blob over the cap stops that device's
  later changes from reaching its peers until the cap rises?
