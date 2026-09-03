# Personal Server: Gateway + Enclave

Status: working architecture note, **not ratified** (pending Anna's sign-off, see Open 1)  
Date: 2026-09-02

## Purpose

Define the always-available Personal Server: a fixed Gateway URL for builders, an ephemeral per-user enclave that answers, and owner surfaces that only sign. Decisions first, then mechanics, then what is still open.

## V1 rule

Fewest changes to the existing stack. Accept bounded, explicit trust in the shared TEE node agent and pragmatic key reuse. Defer hardening that does not close a plaintext or cross-user boundary.

Exceptions (known defects the rule must not protect):

1. **Gateway is refuse-only.** It may deny; it can never redirect a job, swap a key, or change registration state.
2. **Grants are owner-signed, always.** No server-delegate minting.
3. **Registration carries nonce and deadline.** Contract change, `DataPortabilityServers` V3.
4. **Revocation is user-signed and settled on-chain.**

The master signature stays the root of every data key in v1 by decision (see Compromise and rotation).

## Decisions

### Product

1. **One Personal Server per user.** Desktop and enclave identities are internal. One screen: your data, your apps, every grant with revoke.
2. **Two user-facing states**: _on_ and _ready for apps_. Internal readiness states stay in logs and a diagnostics view. If readiness takes minutes, say so once and let the user leave.
3. **Desktop leaves the builder read path.** Desktop collects, encrypts, uploads, and serves the owner locally. The enclave answers every builder request. Desktop-only users get no builder access (today's behaviour when the desktop is offline). The job worker stays runtime-agnostic so desktop can be re-admitted later.
4. **No PS Lite server.** Web and mobile become wallet and consent surfaces. Stop registering PS Lite first; delete `packages/lite` after the enclave serves real users. This retires shipped code: web and mobile-shell host `packages/lite` behind `personal-server-relay` today.
5. **External-wallet users in scope.** Owner is an EOA. Privy signs silently via Account intents; external wallets sign via prompts. Both need deterministic (RFC 6979) `personal_sign`; ERC-1271 smart wallets are out.
6. **Mobile in scope** as onboarding with a limited connector set. Ingestion needs no PS: the app encrypts client-side, uploads to `vana-storage`, registers data points at the Gateway; the enclave syncs.
7. **Builder private key is a server secret**, like a Stripe secret key. Results stay encrypted to it. Browser apps read through their own backend.
8. **One SDK read call.** Direct-read versus job-path migration is hidden in the SDK. Builder writes are v1.1.

### Trust

9. **Gateway is refuse-only.** Before touching plaintext the runtime verifies: the owner-signed grant (signer equals owner; scope, grantee, expiry from the payload); the builder-signed registration with `publicKeyToAddress(publicKey) == granteeAddress == grant.granteeId`; its own owner-signed registration; and revocation state on chain over RPC, falling back to Gateway state within a 5 min staleness window. Today `policy/data-read.ts` trusts Gateway rows and the Gateway supplies the result key. Both change.
10. **Grants owner-signed.** The `serverSigner.signGrantRegistration` delegate path is removed for the enclave and deprecated for desktop. A Vana-run enclave registered as the user's server must not be able to mint grants.
11. **Registration nonce and deadline.** The Gateway settles the four-field owner signature into `DataPortabilityServersV2.registerServerWithSignature`, so replay protection is a V3 struct change (`nonce`, `deadline` on registration and deregistration). Bridge: Gateway refuses already-settled signatures and retired epochs; node agent refuses to derive for a retired epoch.
12. **Revocation** is owner-signed (already true at the Gateway), settled on-chain, deletes the sealed master-signature ciphertext from every store and backup, and retires the KMS path. Re-enable uses path `v2` and a fresh registration.
13. **Multiple user sandboxes per CVM is the design**, not a v1 compromise. Conditions: node agent small, reviewed, measurement-pinned; public claims about Vana's access match what the node agent can do. No per-user CVM trigger is defined; revisit only if a regulator or Anna's review requires it. Spike 3 (2026-09-02, dstack 0.5.9) fixed the shape: one gVisor `runsc` (ptrace platform) sandbox per user, launched by a small trusted management container that holds the sockets; the sandbox runs as uid 1000 with zero capabilities, read-only root, a 256 MiB tmpfs, and no dstack or Docker socket. Sysbox works for nested Docker but gVisor does not nest inside it on 0.5.9. `runsc` and the PS image are baked and pinned in the compose.
14. **No data-key rotation in v1**, by decision. See Compromise and rotation.

### Money and limits

15. **Payments from day one.** Every job carries `price` (may be zero), `payer` (builder), `paymentState`. Access receipt issues when the encrypted result is durably committed.
16. **Inference bills two line items**, compute (per model call) and access (per derived-scope read). Builder pays both. Owner never pays for a builder's question.
17. **Attested inference only in v1.** Standard providers are out; a later version needs a per-grant privacy class the owner consents to. No silent fallback.
18. **Per-builder rate limits** at job admission before launch. The Gateway has none today; the relay quota is per signer, and the signer is the user's enclave wallet, so one app can burn a user's allowance and Vana's spend. Quota is attributed to the builder behind the job.

### Infrastructure

19. **Activate on the Gateway row.** Enclave serves once the row exists, marked `confirming`; rolled back if the chain rejects. A job served under a row the chain later rejects is bounded by the owner signature existing.
20. **Queue on Vercel accepted** with conditions: the wake experiment runs through it. Trigger for a dedicated queue: p95 submit-to-claim above 2 s, sustained 50 jobs/min, or Neon connection exhaustion.
21. **dstack verified.** Spikes 0 to 3 (2026-09-02, Phala Cloud, dstack 0.5.9; `docs/260902-enclave-spike-results.md`): same wallet and sealing key on a second CVM under one `app_id` and across a compose change; different `app_id` gives a different wallet; a master signature sealed on node A unsealed on node B in 4.9 ms and decrypted a real SDK blob, and the wrong user id failed AAD; gVisor sandbox cold start to `/health` 7.5 s p50, 7.7 s p95 (warm image, PS boot dominated); 119 MiB idle and 136 MiB active per sandbox, a RAM-only ceiling of 240 per `tdx.2xlarge`. Hydration measured against Moksha (`dp-rpc-dev`, `storage.vana.org`, 1 vCPU): start to sync complete 11.7 s p50 / 15.3 s p95 for 1 MB, 60.7 s p50 / 65.4 s p95 for 50 MB; `/health` answers at about 10 s in both cases, so readiness gates on sync complete, not `/health`. Queue measured on a Vercel preview with a Neon branch (2026-09-02): submit→claim p95 1.6 s at 50 jobs/min with three workers, 3 Neon connections, orphaned job recovered in 15 s; decision 20 stands. Still unverified: concurrent density and the chained wake experiment.
22. **Manual scaling.** Operator scripts in `personal-server-ts` provision CVMs with dstack tooling and admit or drain them through Gateway operator-only endpoints. No Fleet Director. `data-gateway` has no admin UI; `apps/metrics` is product analytics, not a Gateway console.
23. **All enclave code in `personal-server-ts`.** No new repo. Agent and PS image ship in one compose, one approved hash.
24. **Key reuse.** Registered secp256k1 keys serve as ECIES inbox (enclave) and result key (builder). Already shipped in the SDK. Separate keys deferred unless review finds a concrete flaw.
25. **Question intents live in Gateway control state**, encrypted. Grant readiness and answer readiness are separate. Builder receives an answer-only DTO; lineage stays owner-side.
26. **Phala KMS (off-chain) anchors the fleet `app_id`** in v1: `--custom-app-id` with a nonce; the Phala Cloud workspace account approves compose changes; no per-device revocation, so node compromise is handled by drain, compose-hash rotation, and re-provisioning. On-chain KMS is the upgrade path if contract-owned approval or `removeDevice` becomes a requirement. Keys derived under the two modes differ, so switching is a re-provisioning event.

### Requires sign-off: reversal of the June browser-PS decision

In June the PS stayed in the browser so Vana never holds user data on its own machines. This design reverses that: Vana-operated hardware holds plaintext transiently inside an attested sandbox and holds the sealed data-unlock secret durably; Vana cannot read either outside the enclave, but Vana operates the enclave and the KMS is Phala's. Consent copy must state the revocation guarantee: revoking deletes Vana's sealed copy of the secret and retires the identity. That guarantee is operational (deletion plus node-agent refusal), not cryptographic; dstack cannot revoke a deterministic key. Anna signs off before this note is final.

## Components

| Component               | Role                                                                                             | Sees                                                  |
| ----------------------- | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------- |
| Data Gateway (`dp-rpc`) | Fixed PS URL. Auth, grants, payment, rate limits, blind job queue, TEE registry, inference relay | Signed metadata, ciphertext                           |
| Vana Storage (R2)       | Encrypted blobs `{owner}/{scope}/{version}`                                                      | Ciphertext                                            |
| TEE node (dstack CVM)   | Node agent plus one gVisor sandbox per active user                                               | Plaintext inside sandboxes; agent in every user's TCB |
| PS Enclave              | Ephemeral per-user PS. Wallet and master signature in memory only                                | Own user's plaintext                                  |
| Private inference       | Attested provider (Phala) via Gateway blind relay                                                | Encrypted prompt                                      |
| Desktop (PS Full)       | Collector and owner-local server. Not a builder executor                                         | Own plaintext                                         |
| Web, mobile             | Wallet and consent. No server                                                                    | Nothing at rest beyond cached signature               |

## Identity and keys

**Enclave wallet.** `userPsId = keccak256("vana.ps-enclave.v1" || chainId || ownerAddress)`. The node key agent calls dstack v0 `getKey(path)` with `users/{userPsId}/wallet/ethereum/secp256k1/v1`. Verified upstream (Spike 0, `docs/260902-enclave-spike-results.md`): KMS derives the app root key from its root and `app_id` only; the guest derives `HKDF-SHA256(app_root, path)`. `purpose` and `algorithm` do not enter the KDF, so the path string is the only separation. Every CVM with the same `app_id` recovers the same wallet; `compose_hash` and `instance_id` are not inputs. Pin SDK `@phala/dstack-sdk` 0.5.8 and dstack OS 0.5.x: the 0.6 `/v1` API uses a different KDF, so an OS major bump is a re-provisioning event, not a rolling upgrade. Wallet bytes are the raw 32-byte key (not `toViemAccountSecure`), recorded once and never changed.

`app_id` is a namespace, not proof of code. Separately require attestation, approved OS image, approved `compose_hash`, pinned image digests. Two ways to pin `app_id`: Phala KMS (`--custom-app-id` with a nonce; Phala's control plane approves compose changes for the workspace) or on-chain KMS (`app_id` is a `DstackApp` contract address; the contract owner calls `addComposeHash`/`removeComposeHash`, and several hashes can be live for rolling upgrades). Decision 26 picks. Second and later nodes are `phala cvms replicate`, not fresh deploys. Persist only public data. Never derive this wallet from the master signature: desktop holds that secret and could impersonate the enclave.

**Identity before registration.** The key agent derives the wallet without starting a sandbox and returns address, public key, derivation metadata, and attestation evidence. The owner signs against that.

**Data root.** Scope keys derive from the raw 65-byte `vana-master-key-v1` signature (`vana-sdk/.../crypto/keys/derive.ts`), not from any wallet. A different signature strands every blob, so the enclave needs the exact bytes. Desktop already ships them as `VANA_MASTER_KEY_SIGNATURE`.

**Sealing.** The owner surface delivers the signature over an attested channel. Inside the TEE: random per-user content key encrypts the signature; `GetKey("users/{userPsId}/secrets/master-signature/v1")` wraps the content key. Ciphertext is bound to `userPsId` as AAD so a node cannot be tricked into unsealing user A's secret for user B's sandbox. Only ciphertext persists. Wallet path and sealing path are domain-separated. Envelope form makes vendor exit one re-wrap job. On wake the node unwraps in memory and injects `VANA_MASTER_KEY_SIGNATURE` into the sandbox only.

**PS changes required** (`packages/server/src/bootstrap.ts:196-226`): PS never deletes the variable from `process.env` and keeps the raw signature in a closure; the dev UI (default on) serves it to the browser as `psLiteBootstrap`; frpc inherits the full env; `VANA_OWNER_PRIVATE_KEY` is a second secret. The enclave profile disables dev UI and tunnel, scrubs env, never sets the owner key, and any future subprocess uses an allowlisted env, separate UID, restricted `/proc`. JavaScript cannot zeroize; sandbox destruction is the final boundary.

**Shared-CVM trust.** `app_id` identifies the outer CVM, not the inner sandbox. The node agent can derive every user's path. Sandboxes never receive the dstack socket, Docker socket, host filesystem, or another user's mounts. KMS-enforced per-user isolation needs one CVM per user; deferred (decision 13).

### Compromise and rotation

- **Node compromise.** Drain, quarantine, remove its measurement, rotate compose hash. On-chain KMS supports `removeDevice` and `removeComposeHash`; Phala KMS exposes no per-device control. Users active on it have an exposed data root; notify. No re-key in v1.
- **KMS root compromise.** Delete all sealed rows, move to sealing path `v2`, re-provision every user under fresh consent.
- **User rotation.** Revoke and re-enable gives a new identity and sealing. The data root cannot rotate.
- **Before GA**: data root key (DRK) with epochs. Random per-user key wrapped to the master signature; scope keys derive from `DRK || epoch`. Rotation is a new epoch plus background re-encryption. Cost: key-management design, one-time migration of every blob, epoch metadata. Per-scope escrow costs the same migration with more keys.
- **Vendor exit.** Re-wrap content keys inside the old enclave while the old KMS is alive. No Vana-held second wrap: Vana never holds a path to the data root outside the enclave. Proposed to Anna as the stance.

## Encryption layers

| Layer            | Scheme                                                              | Note                                                                                                                                                |
| ---------------- | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Stored data      | master signature → HKDF scope key → OpenPGP blob                    | Unchanged                                                                                                                                           |
| Builder messages | SDK ECIES (secp256k1, AES-256-CBC + HMAC) to registered keys        | No AAD, no recipient binding, no sender auth. Job, grant, deadline, builder key bind inside the plaintext under a signature. HashCloak audit exists |
| PS → inference   | Phala E2EE v2, X25519 + HKDF + AES-GCM per field, via Gateway relay | Default `inference.baseUrl` is direct Phala; relay only when configured                                                                             |

ECIES wire format is `iv(16) || ephemPub(65) || ct || mac(32)`. Gateway stores builder and server keys as unvalidated strings, so the SDK normalises 33/64/65-byte forms at the boundary. Moving to one deterministic enclave inbox removes the old `prepare → select → encrypt` round trip and any multi-recipient envelope.

**Phala relay flow (exists today, `packages/core/src/derivatives/e2ee/`):**

1. PS signs `GET /v1/inference/aci/attestation?nonce=<32 bytes>` with its server wallet; Gateway checks the signer is the owner or a live registered PS, injects the Phala key, relays bytes.
2. PS validates the ACI report: nonce, canonical workload-keyset digest, freshness, E2EE v2, X25519 key shape.
3. PS encrypts each prompt field with a fresh ephemeral X25519 key; AAD binds purpose, algo, model, field path, nonce, timestamp.
4. PS signs the exact encrypted bytes and posts `/v1/inference/chat/completions`; Gateway checks signature and quota, injects the key, byte-relays request and response. PS decrypts. No streaming today.

Gaps to close: DCAP `verifyEvidence` unwired; unsigned fallback to `inference.phala.com` on 404/405; legacy unchallenged `/v1/inference/attestation/report`. Fail closed in production.

## Job model

`jobId`; owner, builder, grant, scope, operation; encrypted request or pointer; pinned scope version; assigned node and assignment expiry; state `queued | claimed | running | completed | failed | expired | cancelled`; claim owner and expiry; `claimed_at`, `completed_at`, `deadline_at`; attempt and `failure_reason`; encrypted result pointer, hash, size, expiry; `price`, `payer`, `paymentState`, receipts.

Login may prewarm the sandbox; it cannot be the only trigger, because a builder may submit while the owner is logged out. An authorized job wakes or creates the sandbox on demand.

Runtimes pull: heartbeat and claim from the Gateway, no inbound connections. Queue in Postgres; the claim is one `UPDATE … WHERE id IN (SELECT … FOR UPDATE SKIP LOCKED) RETURNING` statement, no explicit transaction (Spike 4, `docs/260902-enclave-spike-results.md`). Lease plus fencing plus sweep-before-claim recovered a killed worker in 13.8 s without a cron. A 1 s claim poll sets the submit-to-claim floor (p50 ≈ half the interval per idle worker) and costs 60 invocations per worker per minute idle; decide before launch between a long-poll claim (`/v1/jobs/claim?wait=25`) and backoff on 204. Fast tier: `POST /v1/jobs?wait=25` holds up to 25 s and returns inline, else `202` and the SDK polls. Metadata-only webhooks v1.1. Large results stream-encrypt to a private R2 bucket and return a handle.

Duplicate execution around an ambiguous failure is answered by stable `jobId` and idempotent commit. With desktop out of the read path there is one executor per user, so no presence TTL, per-user lease, or storage conditional PUT in v1. Raw-read version is pinned at admission; retries return identical bytes.

## Workflows

Target flows. None exists yet.

### 1. Register the enclave

1. Web asks the Gateway to prepare the identity; a node derives it and returns public identity plus evidence. No sandbox starts.
2. Web verifies evidence: the Gateway has already admitted the node after DCAP, and the browser verifies the two-link `signature_chain` (app root key over the derived key; KMS root over `app_id || app_root_pubkey`) against the pinned KMS anchor `DstackKms.kmsInfo().k256Pubkey`, and that `app_id` is ours. This is a secp256k1 signature chain, not an X.509 chain. Web shows one prompt: "Enable your always-on Personal Server", including the revocation guarantee.
3. Two signatures under that consent: registration (EIP-712) and the master-key `personal_sign`. Silent for Privy, prompts for external wallets, one if the master signature is cached from login. No background signing afterwards.
4. Web submits registration to `POST /v1/servers` with the Gateway URL. Row is `confirming`; enclave is _on_. Gateway settles on-chain.
5. Web sends the master signature over the attested channel; the TEE seals it; ciphertext persists as a Gateway Postgres row; delete-on-revoke covers Neon backups within the PITR window.
6. Prewarm provisions the sandbox; _ready for apps_ when scopes hydrate.

Today web couples registration to a booted PS Lite with a relay URL (`web-personal-server-session.ts:843-883`). Registration fee, when enabled on chain, returns 503 because escrow supports only `grant` and `data_access`.

**Desktop migration.** Existing desktop registrations use tunnel URLs; the Gateway URL is a new `serverId`. Desktop shows one prompt; the owner signs new registration plus old deregistration. Old row is `retiring` until settled, `stale` after 30 days without presence. If the user never opens desktop, enabling the enclave from web or mobile includes deregistering stale desktop rows.

### 2. Builder raw read

1. Builder submits signed metadata: grant, scope, deadline, idempotency key. No user data, no encryption.
2. Gateway verifies builder, grant, payment policy, rate limits; queues with `price`, `payer`.
3. A node claims, derives the wallet, unseals the signature, starts or reuses the sandbox, hydrates only the pinned scope and version.
4. PS verifies grant, registration, and builder key from signed artifacts; checks revocation on chain; redacts grantee-hidden fields; encrypts to the builder key; commits ciphertext. Receipt issues.
5. Builder fetches, verifies, decrypts. Lost acknowledgement never loses the result.

Today: DCR returns a per-user `personalServerUrl` (Account, not Gateway); SDK readers call `res.json()` and cannot read binary; PS ignores `grant.status` and `paymentStatus` while the Gateway requires `confirmed|finalized` and `paid`; payment happens before delivery.

### 3. Inference answer

1. Owner approves question, source scopes, derived scope. Intent stored inactive in the Gateway, encrypted to the enclave key.
2. Owner-signed grant to the derived scope only. Today a builder question needs bare read on every source scope (`DERIVATIVE_SOURCE_NOT_GRANTED`) and web mints `dcr.scopes` verbatim; this is a consent-model change. The builder proposes the question at DCR; the owner approves the exact text and scopes; the enclave matches the ciphertext to the approved intent.
3. Gateway places the compute job after grant commit. Enclave hydrates source scopes, verifies the question matches the approved intent, builds a bounded prompt, sends it over the Phala relay.
4. PS decrypts the answer, records lineage owner-side, encrypts an answer-only DTO to the builder. Durable before complete. Two receipts: compute and access.

Today: question registrations live in one PS's SQLite; web starts compute without awaiting, then mints the grant; payload includes question, evidence, and sources.

### 4. Sandbox TTL and wake

1. Idle TTL: `warm → expiring` atomically; cancel if a job arrives. Destroy sandbox, tmpfs, plaintext SQLite. Keep only encrypted manifest and index caches.
2. Next job: Gateway creates or joins one per-user startup assignment on an admitted node.
3. Node derives the wallet, unseals, injects, starts the enclave profile. PS verifies its own registration, reconciles manifest and tombstones, hydrates, reports readiness.
4. Inference ciphertext is retryable on any node because every node derives the same key.

Today: `/health` is process health only and green during reconciliation; PS never checks at execution that it is still registered.

### 5. Operator adds a TEE

1. Operator runs `scripts/tee/provision` (dstack tooling, pinned `app_id`, approved compose, pinned image) and registers the node's expected identity via an operator-only endpoint (separate operator secret, not `CRON_SECRET`).
2. Node answers a nonce challenge; verifier checks quote, OS/TCB, `app_id`, `compose_hash`, transport key, KMS-root fingerprint.
3. Node verifies the PS image, runs a KMS derivation canary, heartbeats `ready`.
4. Operator admits. Gateway alone reserves capacity.
5. Drain: stop claims, finish, wipe, destroy.

Today: no node, admission, or capacity state exists. KMS authorization and Gateway admission are separate gates; a wrong KMS root looks healthy but derives every wallet wrong, hence the canary. Outer-CVM attestation does not approve the PS image the agent pulls; image digest pinning does.

### Invariants across workflows

- Registration, chain activation, node presence, process health, scope readiness, grant readiness, answer readiness are separate states. Registration never implies data is ready.
- Gateway checks declared metadata; the runtime reauthorizes against signed artifacts immediately before plaintext. Gateway is refuse-only.
- Every claim and completion is fenced and idempotent; side-effecting work has stronger serialization.
- Gateway sees signed control metadata, never plaintext, questions, results, owner signatures, or keys.
- Node agent is in every user's TCB; sandboxes never receive dstack or host-control sockets.
- Revocation reaches Gateway placement, runtime execution and result fetch, storage delegation, and KMS release.

## Ownership

Legend: `+` new, `~` edit, `−` deprecate after a real user runs the new path end to end.

### personal-server-ts

```text
packages/core        ~ scope-filtered sync port, signed-artifact reauth (grant, registration, builder key),
                       chain revocation check, answer-only derivative DTO, portable question intents,
                       ECIES result envelope, readiness state
packages/server      ~ enclave profile: key-provider port (no key.json), env scrub, dev UI off,
                       drain/readiness endpoints; fix the published image (vanaorg/personal-server
                       exits with ERR_MODULE_NOT_FOUND @opendatalabs/vana-sdk, Spike 3)
                     + jobs/ worker: pull, claim, execute, commit (runtime-agnostic)
                     ~ desktop profile: collector and owner-local server only; tunnel optional, then removed
packages/enclave     + node agent: heartbeat, claim, sandbox lifecycle, dstack key agent, envelope sealing
                       (spike/enclave has dstack port + fake, paths, wallet, sealing; spike/sandbox has the gVisor launcher)
packages/lite        − retire after PS Lite stops being registered and the enclave serves real users
deploy/dstack        + CVM compose pinning agent + PS digests
scripts/tee          + provision, admit, drain, list
```

Dependency direction: `enclave` imports `server` and `core` public APIs; nothing in `core` or `server` imports `enclave` or touches the dstack socket. The sandbox never receives the dstack socket, host filesystem, Docker socket, or another user's mounts.

### data-gateway

```text
api/v1/jobs          + builder submit (with ?wait=25), status, result fetch; runtime claim, heartbeat, complete, fail
api/v1/tee-nodes     + attestation challenge, heartbeat; operator admit, drain, list
api/v1/identity      + identity-only derivation request; sealed master-signature store (Postgres row,
                       delete on revoke incl. backups)
api/v1/servers       ~ Gateway URL as serverUrl; several identities per owner; V3 nonce/deadline;
                       replay and retired-epoch refusal; desktop migration (retiring, stale)
api/v1/inference     ~ quota attributed to the builder behind the job; remove unchallenged attestation route
lib/rate-limit       + per-builder and per owner-builder token buckets at job admission (none exists today)
lib/receipts         + price, payer, paymentState on every job; access and compute receipts
lib/liveness         ~ one server-liveness predicate replacing the current three
                       (writes: any non-revoked server; lineage reads and inference: confirmed|finalized and paid)
lib/tee              + DCAP verifier, measurement policy, KMS derivation canary
lib/operator-auth    ~ operator secret or allowlist separate from cron secret
db                   + tee_nodes, jobs, job_attempts, result_handles, identity_records, sealed_secrets,
                       question_intents
storage              + private R2 bucket for large ciphertext results (no object storage exists today)
cron                 + expire claims, purge result handles, mark stale registrations
```

Pull-based: nodes heartbeat and claim, no inbound connections. Queue in Postgres with `FOR UPDATE SKIP LOCKED` (existing `settlement_outbox` pattern). Vercel caps functions at 300 s; Postgres is Neon over WebSocket.

### vana-sdk

```text
protocol/jobs        + job, claim, heartbeat, result-handle types shared by Gateway, PS, agent
protocol/identity    + enclave identity evidence types
protocol/eip712      ~ registration and deregistration typed data gain nonce and deadline (V3)
crypto/envelope      + ECIES message envelope with inner binding (job, grant, deadline, builder key) + signature
direct/              ~ one read call: submit → wait/poll → decrypt; binary results; direct read hidden behind
                       migration flag
direct/access-request-client ~ DCR returns the Gateway URL
ingest/              + client-side collect, encrypt, upload, register data points (mobile and web, no PS)
protocol/personal-server-write ~ through the Gateway job path (v1.1)
personal-server-lite/ − retire owner-binding message with PS Lite
```

Job protocol types live here, not in `packages/enclave`, so Gateway, PS, and agent import one definition. SDK docs state: builder private key is a server secret; browser apps read through their own backend.

### unity-surfaces

```text
apps/account
  lib/signing        ~ reuse registration and owner-binding intents; + attested-channel delivery of the master signature
  DCR API            ~ return Gateway URL; question intents to Gateway; derived-scope-only, owner-signed grants
apps/web
  features/personal-server − PS Lite runtime and relay client
                     + enclave client: identity prep, evidence check (KMS cert chain, app_id), registration submit,
                       prewarm, status
  consent            + "Enable your always-on Personal Server": identity, evidence, revocation guarantee,
                       one consent, two signatures
                     + two user states (on, ready for apps); diagnostics view for internal states
                     ~ DCR approval: owner approves question text and scopes; derived-scope-only grant;
                       await answer readiness
                     + one Personal Server screen: your data, your apps, every grant with revoke
apps/mobile, mobile-shell − WebView PS Lite, relay, ps bundle
                     + ingest via SDK with a limited connector set; sign-in triggers prewarm; same consent screens
apps/desktop         ~ collector and owner-local only; one-prompt migration to Gateway URL registration;
                       tunnel optional, then gone
```

### vana-storage

```text
auth/gateway-client  ~ adopt the inference relay's liveness predicate; revocation-aware cache (60 s positive cache today)
middleware/auth      = blob GET/HEAD stay public by decision; security rests on keys
blobs                = no conditional PUT needed in v1 (single executor per user); range reads only if profiling justifies
```

### Other repositories

- `vana-smart-contracts`: `~` `DataPortabilityServers` V3 adds `nonce` and `deadline` to `ServerRegistration` and `ServerDeregistration`. `serverAddress` stays a permanent global claim; `publicKey` immutable; grant content an off-chain URI.
- `personal-server-relay`, `vana-frp`: `−` after SDK migration. Load-bearing today; keep running through the transition.
- Builder apps such as `playlist-shelf-app`: `~` async job UX through the SDK; drop reopen-tab guidance.

## Sequencing

1. Derisking slice: `packages/enclave`, enclave profile, `api/v1/jobs`, `api/v1/tee-nodes`, `protocol/jobs`. One node, one test user, one scripted builder, one raw read, sandbox recreated on a second node mid-test.
2. Identity and consent: `api/v1/identity`, Account signing, consent and Personal Server screens.
3. Builder migration: SDK envelope and job flow, DCR to Gateway URL, contracts V3.
4. Inference: intents, derived-scope grants, DCAP wired, rate limits, receipts.
5. Deprecations.

### Wake experiment

Done in parts on 2026-09-02 (Spikes 1 to 4, `docs/260902-enclave-spike-results.md`): derivation identical across CVMs and compose updates; local queue submit → claim p95 220 ms at 50 jobs/min with 3 workers, `?wait=25` result p95 534 ms; sandbox cold start 7.5 s p50. Hydration measured 2026-09-02 (50 MB owner: 65 s p95 to sync complete on 1 vCPU). Queue on a Vercel preview measured the same day (submit→claim p95 1.6 s at 50/min, three workers); decision 20's trigger did not fire, with little margin. Remaining: the chained run (job through the preview queue to a CVM sandbox) once the node agent and job routes are real code.

**Identity flow verified end to end (2026-09-03).** Node agent (`packages/enclave`, registry-free compose in `deploy/dstack`) on two Phala CVMs under one `app_id`, Gateway preview (`api/v1/identity`) with a Neon branch, scripted owner (`scripts/e2e-identity.ts`): prepare, evidence verify against the live KMS root, V2 registration, sealed delivery, idempotency, three negatives, revoke to epoch 2, all pass; a delivery encrypted to node A's evidence key was unsealed by node B through product code. Agent boot to healthy 124 s including CVM boot (install at boot; production pins an image digest). Still unverified: concurrent density and the chained wake run.

## Open

1. Anna's sign-off on the June reversal, revocation wording, and the no-second-wrap stance. Blocks ratification.

Resolved 2026-09-02: owner-approved question intents; blob reads stay public; sealed ciphertext in Gateway Postgres; raw-read version pinned at admission; attestation via Gateway admission plus KMS cert chain; no second wrap; 5 min revocation staleness window.

Step 2 contract (endpoints, SDK types, tables, signing intents, PR order): `260902-identity-contract.md`. Resolved there 2026-09-02: identity endpoints unauthenticated in v1; sealing AAD and key paths carry the epoch; Gateway mirrors SDK identity types with a devDependency shape test.

## Review log

2026-09-02, Maciej: all blocking items incorporated (decisions 9 to 12, 15 to 18, desktop migration, sign-off section). Decisions as given recorded as 1, 2, 5 to 8, 19 to 21. Dismissed: naming a per-user-CVM trigger; multiple sandboxes per CVM is the design (decision 13), not a staging step. Questions answered: desktop out of read path (decision 3); no rotation in v1 with DRK plan; latency estimates and `?wait` tier; V1 rule exceptions; two signatures at signup.

## Code facts (verified 2026-09-01)

Checkouts: `personal-server-ts 1ce460d`, `data-gateway 3d0d754`, `vana-sdk 42be961`, `unity-surfaces ed26254a`, `vana-storage 1961dcf`, `vana-smart-contracts f37545c`, `personal-server-relay b00101d`, `vana-frp a711769`, `playlist-shelf-app 72ae070`.

- `packages/server/src/keys/server-account.ts` writes a random `key.json`; `ServerAccount` interface exists as the injection seam; `packages/lite` and `mcp/grantee.ts` generate more random keys.
- `packages/core/src/sync/workers/download.ts` syncs owner-wide; `listDataPointsByOwner` has no scope filter.
- `CLOUD_MODE` disables local approval and interactive login but fetches `PS_ACCESS_TOKEN` from GCE metadata.
- `data-gateway`: Vercel functions, Neon Postgres, Drizzle, no object storage, no rate limiting, no admin UI, crons for settle and metrics (Datadog). Server lifecycle `pending|submitting|confirmed|finalized|failed`; `serverAddress` globally unique; relayer submits on-chain.
- `data-gateway/api/v1/servers.ts:469-482`: 503 when the server-registration fee is enabled on chain.
- `vana-sdk` ECIES: native `secp256k1` (Node) and `@noble` (browser), eccrypto-compatible; `encryptWithWalletPublicKey` already encrypts to EOA keys. Two direct readers exist. `session-relay` has an init → poll → claim → webhook shape.
- `unity-surfaces/apps/account/.../personal-server-intent-service.ts` signs registration (EIP-712) and owner binding (`vana-master-key-v1`) via Privy; desktop silent-signing requires a trust token. Web keeps the master signature in `localStorage` for 8 h; desktop in the OS keychain; mobile in secure storage.
- `vana-storage/src/auth/gateway-client.ts:25-52` checks only owner match, so revoked, pending, failed, and unpaid servers keep writing; positives cached 60 s. Blob `GET/HEAD` skip auth. PUT overwrites; `If-None-Match` exists, range does not.
- `IDataPortabilityServers.sol`: `Server { owner, serverAddress, publicKey, url }`, `updateServer(url)` only, no fee, per-user `untrustServer`. Gateway settles via `DataPortabilityServersV2.registerServerWithSignature` and `deregisterServerWithSignature`.
- Inference E2EE: `derivatives/e2ee/attestation.ts` (report checks, `verifyEvidence` TODO), `phala.ts` (per-field encryption), `suite.ts` (X25519, HKDF, AES-GCM), `aad.ts`, `derivatives/inference.ts` (sign exact bytes); Gateway `api/v1/inference/chat/completions.ts`, `aci/attestation.ts`, `docs/INFERENCE_RELAY.md`. `bootstrap.ts` enables E2EE by default but wires no evidence verifier.
- PS read path today: `policy/data-read.ts` (builder, grant, scope, grantee, owner, expiry; deliberately ignores `grant.status` and `paymentStatus`), `api/index.ts` (x402 payment then read; tombstones; raw branch skips `reportReadFulfillment`), `sync/workers/download.ts`. Compute: `derivatives/compute.ts`, `prompt.ts`; questions in `server/src/storage/question-store.ts` (SQLite).
- `pdpp` is the portability protocol spec; no TEE material. Its `connector-child-environment.ts` is the env-allowlist precedent.
