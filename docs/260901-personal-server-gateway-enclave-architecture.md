# Personal Server: Gateway + Full + Enclave

Status: working architecture note  
Date: 2026-09-01

## Purpose

Define the proposed Personal Server architecture before producing another diagram. This document separates decisions already made from transport, lifecycle, and isolation questions that still need design work.

### V1 decision rule

Prefer the least complex design and the fewest changes to the existing stack. Security must be good enough for production, but v1 accepts bounded, explicit trust in the shared TEE Node Agent and pragmatic key reuse rather than adding new protocols for watertight isolation. Defer hardening that does not close an immediate plaintext-exposure or cross-user boundary.

## Decisions so far

### No separate PS Edge

The always-on coordination layer belongs in DP RPC / `data-gateway`. It is not another Personal Server and does not need a separate PS Edge product or deployment.

The Data Gateway becomes the fixed Personal Server URL used by builders. It owns:

- request admission and authentication;
- grant and payment checks;
- a blind asynchronous job queue;
- PS Full presence and capability information;
- TEE capacity and health information;
- runtime selection, job status, retries, and receipts;
- ciphertext and operational metadata, but no user plaintext.

### No PS Lite server

The web, desktop, and mobile surfaces in `unity-surfaces` become owner-facing wallet and consent experiences only. They do not need to host an HTTP server or accept inbound builder traffic.

This retires shipped code, not a hypothetical. `personal-server-ts/packages/lite` is a browser/WebView Personal Server with its own random identity, sync, MCP, and derivatives. `unity-surfaces/apps/web` and `apps/mobile-shell` host it today and accept builder reads and delegated writes over the `personal-server-relay` WebSocket relay. `vana-sdk` also exports a replayable `ps-lite-owner` binding message. All of this needs an explicit retirement path.

The owner surface:

- authenticates the user;
- displays and signs consent;
- registers or revokes a Personal Server;
- may prewarm the user's PS Enclave after login;
- does not need a tunnel or a publicly reachable URL.

### PS Full remains optional

PS Full runs on a user-controlled desktop or other local device. When it is online, current, capable of the requested operation, and reachable through the Gateway, it is the preferred executor.

PS Full is an optimization for user control and cost. The system must remain available when it is offline.

### PS Enclave is the always-available fallback

The TEE creates a wallet for the user's PS Enclave. The owner explicitly consents to registering that wallet and its public key as one of their Personal Servers.

The PS Enclave wallet and data keys are allowed to exist in plaintext inside the attested TEE. They must not be exposed to the Data Gateway, TEE host operator, or another user's sandbox.

The wallet must be stable across sandbox teardown and movement between TEE nodes. A new random wallet on every wake would require repeated owner registration and would change the PS identity.

#### Near-term wallet derivation

Use dstack KMS deterministic key derivation instead of persisting a randomly generated wallet file.

1. Define a public user Personal Server identifier:

   ```text
   userPsId = keccak256("vana.ps-enclave.v1" || chainId || ownerAddress)
   ```

2. Run each horizontally interchangeable TEE node with the same approved dstack application identity. In the initial shared-CVM design, a trusted key agent inside that CVM requests `GetKey("users/{userPsId}/wallet/ethereum/secp256k1/v1")`.
3. dstack binds deterministic key derivation to the outer CVM's application identity and the path, so the same approved application identity and user path recover the same wallet on any authorized node.
4. Persist only the public address, public key, derivation version, application identity, and registration. Do not store the wallet private key in R2, the Gateway, or a node-local sealed file.
5. Revoking the registered PS prevents that identity from serving future requests. A future key epoch can use a new derivation path and owner-approved registration.

The dstack `app_id` is the stable cryptographic namespace of the outer PS Enclave application. Conceptually, KMS first scopes its root to `app_id`, then derives the requested path beneath that application root. The same KMS root, `app_id`, and path produce the same key; another application using the same path does not. This is what lets horizontally interchangeable nodes recover the same user identities without sharing a mnemonic or wallet files.

For the shared-CVM MVP, explicitly pin one production PS Enclave fleet `app_id` across every node and normal runtime upgrade. Do not let it default to a changing compose digest or every upgrade may change every wallet. Treat the stable `app_id` only as a key namespace—not proof of approved code—and separately require valid attestation, approved dstack OS/TCB state, approved `compose_hash` and pinned PS image digests before admitting a node or releasing keys. Rolling upgrades temporarily allow both old and new approved measurements while preserving the same `app_id`.

This has an explicit trust consequence: dstack `app_id` identifies the outer confidential VM, not an inner gVisor, container, or nested sandbox. In a shared CVM, the node key agent and coordinator are in every user's trusted computing base and can technically derive every user's path. Inner user sandboxes must never receive the dstack socket; they receive only their own derived key through a narrow, memory-only handoff. The coordinator must validate the Gateway's authenticated user/job binding before asking the key agent for that path.

If Vana requires KMS-enforced isolation even from the node coordinator, each user must run as a separately attested CVM with a user-specific application identity, or Vana must build a user-aware key service that can authenticate the inner sandbox boundary. Ordinary containers or gVisor inside one CVM do not provide a hardware-attested identity that dstack KMS can distinguish. The near-term shared-CVM model accepts the coordinator in the TCB to keep density and cold starts practical.

In both models, attestation policy must bind the stable application identity to approved runtime measurements. A custom `app_id` alone is not proof that approved code is running.

The address cannot be calculated publicly from a secret KMS root. During onboarding, the attested node key agent should derive the wallet without starting the full PS and return its address, public key, derivation metadata, and verifiable KMS/attestation evidence before the owner signs registration. This does not require syncing R2 data or keeping a user sandbox warm. Once registered, any approved TEE node with the same dstack application identity can recover the same wallet on demand.

Do not derive this enclave wallet from the user's existing Vana master-key signature. PS Full also holds that secret; deriving the enclave signing identity from it would allow a compromised PS Full to impersonate PS Enclave.

#### Wallet recovery is not data-key recovery

The deterministic PS wallet authenticates the enclave to the Gateway, storage, and protocol. It does not decrypt the user's R2 blobs. Current scope keys are derived from the exact raw `vana-master-key-v1` owner signature, not from the owner address or PS wallet.

During owner provisioning, the owner surface must deliver that exact signature through an attested encrypted channel. Inside the TEE, it should be encrypted under a separate deterministic sealing key such as `GetKey("users/{userPsId}/secrets/master-signature/v1")`; only the ciphertext is persisted. On another node, the approved TEE application recovers the same sealing key, unwraps the signature in memory, and derives the existing scope keys. The PS wallet key and master-signature sealing key must use different domain-separated paths.

For v1, inject the unwrapped signature into the user sandbox as the existing `VANA_MASTER_KEY_SIGNATURE` environment variable. Desktop PS Full already uses exactly this mechanism (`unity-surfaces/apps/desktop/personal-server/index.js:821-823`). The variable exists only in the user sandbox, is never placed in the outer Node Agent environment, and is never logged or persisted.

Current PS behaviour falls short of that target. Required changes (`packages/server/src/bootstrap.ts:196-226`):

- PS validates the signature and derives the master key at boot but never deletes it from `process.env`. It also keeps the raw signature in a closure and passes it into `createApp` as `ownerSignature`.
- With `devUi.enabled` (default `true`) the raw signature is served to the browser as `psLiteBootstrap` JSON on `/ui` (`packages/server/src/app.ts:385-396`). The enclave profile must disable this.
- The frpc subprocess is spawned without an `env` option and inherits the full environment (`packages/server/src/tunnel/manager.ts:262`). There are no agent/tool subprocesses yet; MCP tools run in-process. Any future subprocess must use an explicit allowlisted environment (precedent: `pdpp/reference-implementation/runtime/connector-child-environment.ts`), a separate unprivileged UID, and restricted `/proc`/ptrace access.
- `VANA_OWNER_PRIVATE_KEY` is a second secret env var read at boot and cross-checked against the owner. The enclave profile must never set it.

Core dumps and debug environment endpoints remain disabled. JavaScript cannot guarantee zeroization, so sandbox destruction is the final cleanup boundary; this is an accepted v1 tradeoff.

Do not ask the wallet to recreate the signature on every wake. A changed signature would derive different scope keys and strand previously encrypted blobs. Revocation and rotation of this durable data-root secret require a separate migration/re-encryption design from PS wallet rotation.

### Shared-CVM isolation for v1

V1 uses one multi-user outer dstack CVM with a trusted Node Agent and one gVisor-class sandbox per active user. The Node Agent is explicitly inside every user's trusted computing base. One outer CVM per user and nested microVM isolation are deferred.

The coordinator runs once per TEE node. It creates, monitors, and destroys user sandboxes, but should not mount several users' plaintext into its own filesystem or expose a privileged Docker socket to a sandbox.

### Prewarm is an optimization

Login may prewarm the user's sandbox and begin data synchronization. It cannot be the only activation trigger because a builder may submit an authorized request while the owner is logged out.

An authorized builder request must also be able to wake or create the sandbox on demand.

### Private inference remains swappable

For v1, all builder-triggered inference runs in PS Enclave. PS Full is not an inference target. This gives builders one stable encrypted inbox—the registered deterministic enclave key—and allows the Gateway to retry an inference job on any admitted TEE node without placement negotiation or builder re-encryption.

PS Enclave may call a selected inference provider. The provider can be private and attested, such as Tinfoil, or a standard provider such as Gemini when the user and grant permit that privacy class.

There must be no silent fallback from private inference to a non-private provider.

## Proposed request lifecycle

### 1. Owner registration

1. The Gateway computes the public `userPsId` and places an identity-only provisioning request on an eligible attested TEE node.
2. The node's trusted key agent asks dstack KMS for the deterministic user wallet path and returns only its address, public key, derivation metadata, and evidence.
3. The owner surface verifies or displays the attested PS identity and requested capabilities.
4. The owner consents and signs the server registration.
5. The Data Gateway records the PS address, public key, capabilities, derivation version, application identity, and revocation state.
6. The key agent wipes the derived private key from the provisioning operation. No private wallet state needs to be persisted.

The current Gateway already models Personal Servers with an owner address, server address, public key, and URL (`data-gateway/db/schema.ts:161-258`). The public key is not a separate encryption key: registration requires an uncompressed secp256k1 key whose address equals `serverAddress` (`api/v1/servers.ts:315-348`), so it is the signing key. The new design changes the URL into the stable Gateway address plus internal runtime routing rather than exposing each runtime directly.

Two constraints follow. `serverId = keccak256(domain, serverAddress, publicKey, serverUrl)` on both Gateway and chain (`lib/servers.ts:59-76`), so moving an existing PS to the Gateway URL creates a new `serverId`. The owner-signed typed data has four fields (owner, server, public key, URL) with no nonce or deadline (`vana-sdk/.../protocol/eip712.ts:139-146`), so capabilities, derivation version, and application identity are Gateway-asserted unless the SDK typed data grows, and a registration signature is replayable for the same tuple.

### 2. Warm-up

1. Login sends a prewarm request to the Gateway.
2. The Gateway checks whether an eligible sandbox is already active.
3. If not, it selects a TEE node with capacity.
4. The node key agent derives the deterministic wallet and hands only that user's key to the new sandbox in memory; the sandbox then lazy-loads the minimum data needed.
5. The sandbox remains warm for an activity-based TTL, for example one hour.

### 3. Builder request

1. For a raw read, the builder submits signed control metadata—grant, scope, deadline, and idempotency key. The request contains no user data and does not need application-layer encryption. Gateway resolves the builder's existing registered public key for the response.
2. For inference, the builder encrypts the question directly to the user's registered deterministic PS Enclave key and submits the ciphertext with signed job metadata.
3. Gateway verifies the builder, grant, scope, payment policy, size, and rate limits. It may route raw reads to present PS Full or PS Enclave; inference always routes to PS Enclave.
4. The selected runtime claims the job, reauthorizes it, decrypts only the granted data, and performs the operation.
5. The PS encrypts the raw result or answer to the builder before it leaves the runtime. Gateway stores or relays ciphertext only.

## Encryption model

Use three encryption layers with distinct jobs. PS wallets are authentication identities; they do not derive the keys that encrypt R2 data.

| Layer                   | Scheme                                                                   | Purpose                                                                                                                                          |
| ----------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Stored user data        | Existing master-signature → per-scope key → encrypted R2 blob            | Lets PS Full and PS Enclave read the same data when both receive the exact user data root. Keep unchanged.                                       |
| Builder messages        | Vana secp256k1 ECIES envelope using registered PS/builder public keys    | Encrypt inference questions to PS Enclave and encrypt raw results/answers to builders. Raw-read control metadata remains signed but unencrypted. |
| PS → inference provider | Existing Phala E2EE v2 using attested X25519 + HKDF-SHA256 + AES-256-GCM | Protects the expanded prompt and answer from the Data Gateway while the external model computes.                                                 |

V1 reuses the registered PS Enclave secp256k1 public key as its stable encrypted inbox and the registered builder public key for results. This signing/ECDH key reuse is already shipped: the SDK's `encryptWithWalletPublicKey` encrypts to EOA keys, and PS registers the same key it signs with. Separately derived inbox and per-job response keys are deferred unless a focused cryptographic review finds a concrete vulnerability in the existing ECIES construction (HashCloak audit, `vana-sdk/audits/2025-10-hashcloak-ecies-audit.pdf`).

The SDK ECIES is eccrypto-compatible: ECDH x-coordinate → SHA-512 → AES-256-CBC + HMAC-SHA256, wire `iv || ephemPub || ct || mac` (`vana-sdk/packages/vana-sdk/src/crypto/ecies/base.ts`). It has no AAD, does not bind the recipient key, has no version byte, and no sender authentication. Job, grant, deadline, and builder-key binding therefore go inside the plaintext under a separate signature; the envelope alone cannot provide them. Gateway stores builder and server keys as unvalidated strings, so the SDK must normalise 33/64/65-byte forms at the boundary.

### Existing PS → Phala inference E2EE

The remembered inference flow is present in the current checkouts. Note the default `inference.baseUrl` is `https://inference.phala.com/v1`, direct to Phala (`packages/core/src/schemas/server-config.ts:63`); the relay path below applies only when `INFERENCE_BASE_URL` points at the Gateway. The precise responsibility split is:

1. The PS generates a fresh 32-byte nonce and signs `GET /v1/inference/aci/attestation?nonce=...` with its registered server wallet.
2. The Data Gateway checks that the signer is the owner or a live registered PS, injects its Phala API key, and relays the attestation response byte for byte.
3. The PS validates the ACI report's nonce, canonical workload-keyset digest, freshness, advertised E2EE version, and X25519 key shape.
4. The PS creates an ephemeral X25519 keypair and encrypts each prompt content field with X25519 + HKDF-SHA256 + AES-256-GCM. The authenticated data binds the model, nonce, timestamp, and field path.
5. The PS signs the exact encrypted request bytes and sends `POST /v1/inference/chat/completions` to the Data Gateway.
6. The Gateway checks the signature and quota, injects the Phala API key, and forwards the exact body and E2EE headers. It does not encrypt or decrypt the content.
7. Phala encrypts response fields to the PS's ephemeral client key. The Gateway byte-relays the JSON or SSE response, and the PS decrypts it. PS does not currently request streaming.

For v1, only PS Enclave uses this path for builder-triggered inference. It does **not** by itself protect the Builder → PS question or the PS → Builder answer; those use the Vana ECIES envelope above.

There are three material security gaps in the current path:

1. Full TDX/DCAP quote verification is an optional `verifyEvidence` hook and is not wired by the server bootstrap. Without it, the client verifies the nonce-to-keyset binding and internal report structure, but ultimately trusts the report received from the configured TLS origin.
2. When the relay answers 404/405 for `/aci/attestation`, the client falls back unsigned to `https://inference.phala.com/v1` (`attestation.ts:383-408`), widening the trusted origin.
3. Gateway also exposes a legacy unchallenged `GET /v1/inference/attestation/report` behind the same auth bar.

Production should fail closed unless the hardware evidence, measurements, and approved runtime policy have been verified. The relay authorises the server address or the owner address of any live registration and enforces a per-signer daily quota (`INFERENCE_SIGNER_REQUESTS_PER_DAY`, default 20) plus a global budget on one shared operator key (`data-gateway/db/schema.ts:1687,1724`). Making PS Enclave the sole inference executor needs a quota model.

### Builder → PS message flow

Raw reads do not need an encrypted request. The signed request contains only control metadata already required by the Gateway for authorization and routing. Gateway may choose PS Full or PS Enclave after submission, and the selected runtime encrypts the raw result to the builder.

Inference questions are confidential and always target PS Enclave in v1. The builder encrypts once to the deterministic registered enclave public key and submits the ciphertext directly as a job. Every admitted TEE node derives the same enclave key, so Gateway can retry or reroute within the enclave fleet without builder involvement.

This removes the `prepare → select → encrypt` round trip, multi-recipient envelopes, shared Full/Enclave private keys, and inference fallback to PS Full.

### Result delivery

The result can safely pass through the Data Gateway if it is encrypted to the builder before leaving the PS runtime.

The builder already has a registered secp256k1 public key, though no SDK code path encrypts to it today. Therefore the simplest async result path is:

1. PS produces plaintext inside PS Full or PS Enclave.
2. PS encrypts the result to the registered builder public key.
3. Gateway stores or relays ciphertext and marks the job complete.
4. Builder polls by job ID or receives a metadata-only webhook notification.
5. Builder downloads and decrypts the result.

A webhook does not need to carry plaintext. It can contain only `jobId`, status, expiry, and an authenticated result handle. This avoids webhook body confidentiality, retry, and payload-size problems.

For very large raw reads, the PS can stream-encrypt to object storage and return a short-lived result handle rather than buffering the entire result in the Gateway database.

## Routing, leases, and duplicate execution

There is no inherent **PS Full fallback lease** in this model. That phrase mixed together three different mechanisms.

### 1. Presence TTL

The Gateway needs a short-lived presence record saying PS Full is online, reachable, and capable. This is not an execution lease. If the heartbeat expires, the Gateway stops selecting PS Full.

### 2. Job claim

Every queued job needs an atomic claim so only one executor drains it at a time. The claim may have an expiry so another worker can recover the job if the first worker dies.

This is ordinary queue infrastructure, not a per-user runtime lease.

Duplicate execution is still possible around uncertain failure boundaries:

- PS Full claims a job from the Gateway.
- PS Full completes it, but the connection drops before acknowledging completion.
- Gateway cannot tell whether execution happened and retries through PS Enclave.

The same ambiguity exists when a TEE worker dies after doing the work but before marking the queue row complete. The answer is a stable job ID and idempotent execution/commit, not necessarily a user-wide lease.

For a raw read, duplicate execution mostly wastes work and may duplicate payment or access receipts. For an agent action, transformation, or external side effect, it can be materially harmful.

### 3. Per-user runtime exclusivity

A lease saying “only one runtime may act for this user” is necessary only if PS Full and PS Enclave can concurrently mutate shared state in ways that cannot be reconciled.

It may be unnecessary if:

- R2 objects are immutable or versioned (not true today: `vana-storage` PUT overwrites in place with no object versioning or conditional PUT; versioning is only the PS-side `{scope}/{version}` key convention, and `vana-storage/docs/260202-vana-storage-design.md` §11.2 documents the resulting multi-writer corruption);
- every write has an idempotency key;
- the Gateway serializes or conditionally commits mutations;
- index and cache state can be rebuilt from the durable source of truth;
- agent side effects use their own idempotency controls.

If PS runtimes write directly to mutable per-user state without a centralized compare-and-swap or version rule, then stale PS Full presence plus an active enclave can produce conflicting writes. In that design, a per-user writer lease or single-writer epoch becomes useful.

The preferred direction is to keep runtime selection lightweight and make writes versioned and idempotent, rather than locking an entire user to one runtime for all reads. Because storage has no CAS today, a storage-side conditional PUT or a per-user writer epoch is required before Full and Enclave may both write.

## Minimal job model

The Gateway likely needs these durable concepts:

- `jobId`: stable idempotency and correlation key;
- `owner`, `builder`, `grant`, `scope`, and operation type;
- encrypted request envelope or pointer;
- required runtime kind, assigned runtime identity, and assignment expiry;
- state: `preparing`, `queued`, `claimed`, `running`, `completed`, `failed`, `expired`, or `cancelled`;
- claim owner and claim expiry;
- attempt number and retry reason;
- encrypted result pointer, result hash, size, and expiry;
- payment and access receipt state.

The queue can live in the Gateway database initially if claims are atomic and polling load is acceptable. The Gateway already runs this pattern: `settlement_outbox` plus `FOR UPDATE SKIP LOCKED` drains on one-minute Vercel crons (`api/v1/settle.ts`). Vercel functions cap at 300 s and Postgres is Neon over WebSocket, so node long-polling is a new load profile. A dedicated queue can replace it later without changing the public job protocol.

## Implementation ownership

| Repository                                | Primary changes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `data-gateway`                            | Add PS Full presence/capabilities, TEE node registry and attestation status, identity records, job preparations, blind jobs/attempts/claims, capacity reservations, encrypted result handles, idempotency and fencing. Use Postgres for control state and opaque private R2 objects for large ciphertext (no object storage exists today). Pick one server-liveness predicate: writes accept any non-revoked server (`lib/data-point-registration.ts:35-52`), while lineage reads and inference require `confirmed                                                                                                                                                                                                                                                                                                                                                                | finalized`and`paid` (`lib/inference.ts:236-256`). |
| `personal-server-ts`                      | Inject a `ServerAccount`/key provider instead of always creating `key.json` (the `ServerAccount` interface already exists; `packages/lite` and `core/src/mcp/grantee.ts` generate further random keys); consume `VANA_MASTER_KEY_SIGNATURE` in the enclave profile and scrub it (see above); build the profile on `CLOUD_MODE`, which already disables the local approval listener and interactive login but also fetches `PS_ACCESS_TOKEN` from GCE metadata; disable tunnel and dev UI by config; add targeted scope hydration (sync is owner-wide, `listDataPointsByOwner` has no scope filter), readiness/drain hooks (`runtimeAvailability` is unwired in the Node bootstrap), and separation of plaintext runtime state from encrypted caches; add operator scripts (`scripts/tee/*`) for TEE provisioning, admission, and drain. Keep dstack-specific code out of PS core. |
| `vana-sdk`                                | Keep the existing registration typed data; add identity evidence types and a single job submission flow: sign raw-read metadata or encrypt an inference question to PS Enclave, then submit → poll → decrypt. Preserve direct reads temporarily for migration: two readers exist (`direct/personal-server-read.ts` with the x402 loop, `protocol/personal-server-data.ts` with envelope schema), both call `res.json()` and cannot read binary. `session-relay` already implements init → poll → claim with `webhookUrl`, the nearest precedent for the job API. Write paths (`protocol/personal-server-write.ts`, write sessions in `derivative-questions.ts`) also target a reachable PS and need a Gateway route. Bind messages and results to job, grant, deadlines, and builder key.                                                                                         |
| `unity-surfaces`                          | Request and verify the attested enclave identity before a full PS exists; reuse the existing owner registration signing flow (desktop silent-signing already requires a trust token); submit registration directly to the Gateway; retire PS Lite hosting from `apps/web` and `apps/mobile-shell`; DCR lives in Account here, not in the Gateway, and must return the Gateway URL instead of `personalServerUrl`; grants are minted PS-side via `serverSigner.signGrantRegistration` under an owner bearer token, with a `grantVersion` collision workaround in web; model consent, registration, readiness, and runtime availability as separate states.                                                                                                                                                                                                                         |
| `vana-storage`                            | Keep encrypted R2 blob storage and PS delegated writes. Fix `verifyServerDelegation` (`src/auth/gateway-client.ts:25-52`), which checks only owner match on `GET /v1/servers/:address` and caches positives for 60 s, so revoked, pending, failed, or unpaid servers keep writing; adopt the inference relay predicate. Blob `GET`/`HEAD` is fully unauthenticated (`src/middleware/auth.ts:147-165`); decide whether ciphertext reads need auth. Conditional reads (`If-None-Match`, ETag) already exist; add range reads later only if cold-start profiling justifies them.                                                                                                                                                                                                                                                                                                     |
| `vana-frp` / `personal-server-relay`      | Load-bearing today: `tunnel.enabled` defaults to `true`, the registered `serverUrl` is the tunnel or relay URL, and DCR completion hard-fails without external routing. The browser relay is a single-instance VM on a raw IP. The new Gateway job path is outbound pull and needs neither. Retire them from the primary flow after SDK migration.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `vana-smart-contracts`                    | No initial contract change: `Server { owner, serverAddress, publicKey, url }` with owner-signed `addServerWithSignature` accepts the deterministic EOA, public key, and fixed Gateway URL; no on-chain fee. Constraints: `serverAddress` is a permanent global claim and `publicKey` is immutable (only `updateServer(url)`), so a key epoch needs a new address and the Gateway's revoke-then-re-register path cannot settle. There is no on-chain server deregistration, only per-user `untrustServer`; revocation is Gateway state. Grant content is an off-chain URI. Revisit only if key rotation, runtime policy, or derivation metadata must become consensus state.                                                                                                                                                                                                       |
| Builder apps such as `playlist-shelf-app` | Prefer absorbing transport changes through `vana-sdk`; update pending/retry/error UX for async jobs and remove reopen-browser-tab guidance when the legacy path is retired.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |

The new orchestrator boundary should be pull-based: attested nodes heartbeat and claim work from the Gateway, so neither Vercel functions nor TEE nodes need long-lived inbound control connections. A privileged lifecycle helper may be Rust while the Node Agent remains TypeScript. The sandbox must never receive the dstack socket, host filesystem, Docker socket, arbitrary key-domain input, or another user's mounts.

## Common workflow validation

Validated against the latest `main` checkouts on 2026-09-01: `personal-server-ts` `1ce460d`, `data-gateway` `3d0d754`, `vana-sdk` `42be961`, `unity-surfaces` `ed26254a`, `vana-storage` `1961dcf`, `playlist-shelf-app` `72ae070`, `vana-smart-contracts` `f37545c`, `personal-server-relay` `b00101d`, and `vana-frp` `a711769`. `pdpp` `9202f6b0a` was checked and is the Personal Data Portability Protocol spec; it has no TEE, dstack, or KMS material and supports nothing here beyond the child-environment allowlist precedent.

These are target flows. Identity provisioning, stable-Gateway jobs, node orchestration, targeted hydration, and result E2EE do not exist yet.

No dstack SDK, client, or spec exists in any checkout; every `dstack` string in the workspace is a mocked Phala `key_id`. The KMS `GetKey`, `app_id`, and `compose_hash` semantics in "Near-term wallet derivation" match upstream dstack documentation as understood on 2026-09-01 but are unverified here. Verify against upstream before they become load-bearing; a wrong assumption changes every wallet.

### 1. New web user with no PS Full

1. `unity-surfaces` authenticates the user and resolves the canonical owner wallet.
2. Web asks the Gateway to prepare the user's enclave identity. An admitted TEE Node Key Agent derives the deterministic wallet from the stable fleet `app_id` and canonical user key domain, returning public identity and fresh evidence only.
3. Web verifies the owner/network binding, public key/address, KMS root, `app_id`, approved runtime measurements, and fixed Gateway URL.
4. **Prompt once here:** “Enable your always-on Personal Server.” The consent covers registering a long-lived enclave delegate and provisioning the data-unlock secret. Declining leaves the Vana account usable but without always-on builder access.
5. Under that consent, Account produces two distinct artifacts: the owner-signed server registration and the exact reusable `vana-master-key-v1` signature. Web sends the latter through an attested encrypted channel; only its KMS-sealed ciphertext persists.
6. Web submits the existing owner-signed server registration directly to `POST /v1/servers` with the deterministic address and fixed Gateway URL. No full PS needs to boot.
7. Gateway records `pending` and settles on-chain. UI keeps `identity_ready`, `secret_sealed`, `registration_pending`, `registration_active`, `sandbox_cold`, `warming`, and `data_ready` distinct.

Current reusable paths are Account owner-binding and registration signing in `unity-surfaces/apps/account/src/lib/signing/personal-server-intent-service.ts`, the SDK registration typed data in `vana-sdk/.../personal-server-registration.ts`, and Gateway verification in `data-gateway/api/v1/servers.ts`. Current Web couples registration to a booted PS session: `registerIfNeeded` awaits `ready({ publicUrl: true })`, the PS builds the typed data from its own key, and the PS submits it (`apps/web/src/features/personal-server/web-personal-server-session.ts:843-883`). Registration therefore also blocks on relay connectivity, and `prepareRegistration` in PS core must accept an external URL.

**Ordering holes:** decide whether a pending Gateway row or only confirmed/finalized chain state activates the enclave (the Gateway relayer submits on-chain from a one-minute cron, so that latency is Gateway-paced); the server-registration fee flag is read from the on-chain FeeRegistry per request, and when enabled `POST /v1/servers` returns 503 because escrow supports only `grant` and `data_access`, so enclave registration can break without a deploy; the four-field registration signature has no nonce or deadline and is replayable; registration must never imply that a sandbox or its data is ready.

### 2. Builder reads raw data by grant and scope

1. Owner consent creates the grant directly with the owner wallet or through a lightweight enclave signing operation (today the PS signs it as owner delegate via `serverSigner.signGrantRegistration`); wait until the grant is live before advertising read readiness.
2. DCR (Account in `unity-surfaces`, not the Gateway) returns the fixed Gateway URL instead of today's per-user `personalServerUrl`, plus grant ID and approved scopes. Builder submits one signed raw-read job containing operation, scope, idempotency key, and deadline. It contains no user data and needs no encrypted request envelope; Gateway resolves the builder's registered result key.
3. Gateway validates builder and live grant, assigns present/capable PS Full or PS Enclave, and queues the job with a stable ID.
4. If an assigned runtime fails before execution, Gateway may safely reassign the same metadata-only raw-read job to the other runtime.
5. Selected runtime claims the job with a fenced attempt. An enclave derives the same wallet on any admitted node, unwraps the exact owner signature, starts/reuses the user sandbox, and hydrates only the pinned scope/version from R2.
6. PS reads the signed job metadata and rechecks builder, owner, grantee, scope, grant revocation/expiry/status, tombstones, and selected data version immediately before plaintext access.
7. Payment and delivery ordering remain deferred. PS redacts grantee-hidden fields, encrypts the raw result to the registered builder key, signs its provenance, and durably commits ciphertext.
8. Builder fetches, verifies, decrypts, and only then acknowledges product completion. A lost acknowledgement must not lose the encrypted result.

Current direct paths are `vana-sdk/.../personal-server-read.ts`, PS authorization in `personal-server-ts/packages/core/src/policy/data-read.ts`, payment/access records in `packages/core/src/api/index.ts`, and R2 download/decryption in `packages/core/src/sync/workers/download.ts`.

**Ordering holes:** no async job APIs or canonical envelope; no targeted scope hydration; scope/version semantics must be pinned; grant must be rechecked at execution and result fetch; current payment happens before successful delivery; PS and Gateway disagree on live grant checks (PS deliberately ignores `grant.status` and `paymentStatus`, `policy/data-read.ts:39-42`); raw binary reads skip one fulfillment-report path; the SDK readers cannot consume binary bodies.

### 3. Builder receives an inference answer, not the source dataset

1. Owner approves a question, source scopes, and derived output scope. Store a deterministic question intent as inactive first.
2. Mint and confirm the builder's grant to the derived scope only; never grant the source scopes. Activate the compute job only after grant commit so failed grant creation cannot cause orphan inference spend. This changes the consent model: today a builder question requires bare read on every source scope in the same grant (`DERIVATIVE_SOURCE_NOT_GRANTED`, `docs/derivative-data-api.md`), and web mints `dcr.scopes` verbatim. The enclave must instead verify the decrypted question matches an owner-approved intent.
3. Gateway places the encrypted compute job. Enclave wakes and hydrates only the source scopes inside the sandbox.
4. PS rechecks owner consent and delivery grant, pins source versions, builds a bounded prompt, and sends it through the existing Phala E2EE relay. Source data and prompt remain encrypted past the PS boundary.
5. PS decrypts the model response, produces an answer-only builder DTO, and separately records owner/audit lineage and provider receipt. Make the encrypted answer or derivative durable before marking compute complete.
6. PS encrypts only the answer envelope to the registered builder key. Gateway stores ciphertext; builder fetches and decrypts it without receiving source records.

Current compute and prompt paths are `packages/core/src/derivatives/compute.ts` and `prompt.ts`; current blind inference is `packages/core/src/derivatives/e2ee/phala.ts` through `data-gateway/api/v1/inference/chat/completions.ts`. Recent derivative status APIs help polling but remain local to one PS.

**Ordering holes:** question registrations live only in local SQLite and do not follow the user between runtimes; Full and Enclave schedulers could recompute the same question; current web owner flow (`use-data-connection-request-flow.ts:1121-1160`) registers questions and starts compute without awaiting, then mints the grant and completes the DCR; `ready_for_read` in the SDK/surfaces can therefore precede answer readiness; current derivative payload contains question/evidence/source metadata rather than a strict answer-only DTO; full TDX/DCAP verification is still not wired into inference bootstrap; compute billing versus derived-data access billing is unresolved.

### 4. Sandbox TTL expires and the user returns

1. At idle TTL, atomically transition the user assignment `warm → expiring`; reject or CAS-cancel teardown if a new job arrives.
2. Stop accepting work, drain bounded background tasks, destroy sandbox/process/tmpfs/mounts/plaintext SQLite, and retain only explicitly encrypted manifest/index caches. Release the slot.
3. Later, Gateway admits a new job, selects PS Enclave, and atomically creates or joins one per-user startup assignment on an admitted node.
4. Node Key Agent constructs the user key domains itself, derives the same registered wallet, unwraps the sealed historical master signature, validates its owner, and injects it into the sandbox as `VANA_MASTER_KEY_SIGNATURE`.
5. Node starts the enclave PS profile. PS verifies wallet registration, reconciles the encrypted manifest/tombstones, hydrates required scopes, and reports explicit job readiness.
6. Execute the job and refresh the activity TTL. Because every enclave node derives the same registered key, enclave-targeted inference ciphertext may be retried on another enclave node. Raw-read jobs contain no encrypted request and may be reassigned to Full or Enclave.

Current `createServer().cleanup()` and `syncManager.stop()` are reusable, but `key.json`, exact-secret recovery, manifest-first hydration, assignment CAS, and orchestration-grade readiness are missing. Current `/health` is only process health and may be green while full reconciliation is still running. PS today only polls the Gateway for its `serverId` to gate the tunnel; there is no execution-time check that it is still registered and unrevoked.

### 5. An operator adds another TEE

V1 scales manually. An operator watches queue age, unplaced jobs, and heartbeat freshness (Datadog gauges from the existing metrics cron) and provisions or drains nodes by hand. Automated scaling is deferred.

1. Operator runs `personal-server-ts` operator scripts (`scripts/tee/provision`, `admit`, `drain`, `list`), which ship beside the enclave profile. `provision` drives the dstack tooling to create a CVM with the exact stable fleet `app_id`, approved compose/runtime policy, pinned image digest, and existing replicated KMS root.
2. The script registers the node's expected identity with the Gateway through an operator-only endpoint. `data-gateway` has no admin UI today; the only operator surface is bearer-secret endpoints gated by `lib/operator-auth.ts` (`CRON_SECRET`). Add `GET/POST /v1/operator/tee-nodes` and `PATCH /v1/operator/tee-nodes/:id` (admit, drain) behind a separate operator secret or a Web3Signed operator allowlist, not the cron secret.
3. New Node Agent answers a Gateway nonce challenge. Verifier checks the vendor quote, OS/TCB state, stable `app_id`, approved `compose_hash`, transport key, KMS-root fingerprint, and production mode.
4. Node pre-pulls and verifies the PS image, tests KMS access and sandbox isolation, then heartbeats `warming → ready` with slots, memory, CPU, cache disk, and image readiness.
5. Operator admits the node. Gateway alone reserves capacity and assigns fenced claims.
6. Scale-down: operator marks the node draining. It stops new claims, finishes jobs, wipes warm sandboxes, and only then does the operator destroy the CVM. Abrupt failure expires claims and requeues only safe/idempotent work.

**Ordering holes:** no node/admission/capacity/provision state exists; wrong KMS root can look healthy but derive every wallet incorrectly, so admission needs a deterministic canary; KMS authorization and Gateway admission are separate gates; outer-CVM attestation does not automatically approve dynamically loaded PS images; heartbeat capacity still requires transactional reservations; inference or agent side effects cannot be made exactly once without provider/tool idempotency.

### Cross-workflow invariants

- Registration, chain activation, node presence, process health, scope readiness, grant readiness, and answer readiness are separate states.
- Gateway checks declared metadata; the selected PS always reauthorizes immediately before accessing plaintext.
- Every queue claim and completion is fenced and idempotent; mutating/side-effecting work has stronger serialization or reconciliation.
- Gateway sees signed control metadata but never user plaintext, inference questions, results, owner signatures, or derived keys.
- Shared-CVM Node Agent remains in every user's TCB; inner sandboxes never receive dstack or host-control sockets.
- Revocation must affect Gateway placement, PS execution/result fetch, storage delegation, and future KMS/secret release.

## Decisions recorded

1. Reuse registered secp256k1 PS and builder public keys for the Vana ECIES message envelope in v1. Separate inbox and per-job response keys are deferred.
2. Persist only KMS-sealed ciphertext for the exact historical `vana-master-key-v1` signature. Inject its plaintext into the user sandbox through the existing `VANA_MASTER_KEY_SIGNATURE` environment variable at bootstrap, then scrub the PS/tool environment.
3. Accept the shared Node Agent in every user's TCB. Use one multi-user dstack CVM with gVisor-class per-user sandboxes; one CVM per user is deferred.
4. Defer payment capture, delivery receipts, side-effect reconciliation, and detailed job-retention policy to a later decision.
5. Store portable encrypted question intents in Gateway job/control state, separate grant readiness from answer readiness, return an answer-only builder DTO, keep detailed lineage owner-side, and never silently downgrade private inference.
6. Scale the TEE pool manually in v1. Operator scripts in `personal-server-ts` (beside the enclave profile) provision CVMs with dstack tooling and admit or drain them through Gateway operator-only endpoints.

## Still open

1. Whether enclave activation requires only a valid Gateway registration row or confirmed/finalized on-chain registration.
2. Where the small sealed master-signature ciphertext lives. The lowest-change default is the existing Gateway Postgres row; private opaque R2 is only needed if policy forbids secret ciphertext in Postgres.
3. KMS-root backup and provider migration. Losing or changing the root changes every deterministic wallet and prevents unsealing user data roots.
4. Raw-read version semantics: pin the version at job admission or define “latest at execution.” Pinning is safer for retries; latest is simpler for callers.
5. The minimum sandbox/tool containment needed to keep agents from reading the bootstrap environment: separate unprivileged UID, restricted `/proc`/ptrace, explicit child-process environment, no core dumps, and TTL wipe.
6. Who authors an inference question. "Builder request" step 2 has the builder encrypt a question to the enclave; workflow 3 has the owner approve one. Decide whether the builder's ciphertext must match an owner-approved intent and how the enclave checks that.
7. How the owner surface verifies node attestation for the attested encrypted channel and identity evidence. Browsers cannot run DCAP verification; either the Gateway pre-verifies admission and the surface trusts a KMS-signed app certificate chain, or a separate verifier service is needed.
8. Two active registered servers per owner (PS Full and PS Enclave). Confirm grants, DCR, storage delegation, and `listServersByOwner` consumers handle more than one live server.
9. PS Full transport. Pull against Vercel functions means polling cost and wake latency; define the poll interval or a push channel.
10. Builder and PS write paths through the Gateway. The job model covers reads and inference only.
11. Whether `vana-storage` blob reads need authentication and revocation, given ciphertext is publicly readable by key today.

## Current code references

- `data-gateway/docs/INFERENCE_RELAY.md`: current blind inference relay contract, visibility, auth, quotas, and attestation passthrough.
- `data-gateway/api/v1/inference/chat/completions.ts`: authenticates the registered PS, injects the provider credential, and relays the exact encrypted request and response bytes.
- `data-gateway/api/v1/inference/aci/attestation.ts`: relays the nonce-bound ACI attestation report byte for byte.
- `personal-server-ts/packages/core/src/derivatives/e2ee/attestation.ts`: validates nonce, keyset binding, freshness, and key shape; full hardware-evidence verification remains an optional hook with a TODO.
- `personal-server-ts/packages/core/src/derivatives/e2ee/phala.ts`: performs field-level request encryption and response decryption using the attested X25519 key.
- `personal-server-ts/packages/core/src/derivatives/e2ee/suite.ts`: X25519, HKDF-SHA256, and AES-256-GCM cryptographic suite.
- `personal-server-ts/packages/core/src/derivatives/inference.ts`: signs and submits the encrypted OpenAI-compatible request and decrypts the response inside the PS.
- `personal-server-ts/packages/server/src/bootstrap.ts`: enables Phala E2EE by default and wires the registered server signer to the relay; it does not currently wire a hardware evidence verifier.
- `personal-server-ts/packages/server/src/keys/server-account.ts`: currently creates a random key and persists `key.json`; enclave reuse needs an injected `ServerAccount`/key-provider port.
- `vana-sdk/packages/vana-sdk/src/crypto/keys/derive.ts`: current data master and scope keys depend on the exact raw owner signature, which must be provisioned separately from the deterministic PS wallet.
- `data-gateway/db/schema.ts`: builder public keys and Personal Server public keys are already first-class fields.
- `data-gateway/api/v1/servers.ts`: owner-signed server registration already accepts server identity, public key, and URL.
- `vana-sdk/packages/vana-sdk/src/direct/personal-server-read.ts`: current builder read is signed HTTPS followed by direct JSON parsing.
- `personal-server-ts/packages/core/src/api/index.ts`: current PS returns decrypted JSON or decoded raw bytes after authorization.
- `vana-sdk/packages/vana-sdk/README.md`: ECIES primitives already exist in both Node and browser SDK entry points.
