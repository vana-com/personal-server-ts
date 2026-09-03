# Identity contract (step 2)

Status: design, resolved 2026-09-02 (Kahtaf)  
Parent: `260901-personal-server-gateway-enclave-architecture.md`, decisions 9 to 13, 19, 24, 26

Binding: architecture doc decisions 9-13, 19, 24, 26 (`personal-server-ts/docs/260901-personal-server-gateway-enclave-architecture.md`), Spikes 0-2 (`docs/260902-enclave-spike-results.md`). Repos: `/Users/kahtaf/Documents/workspace_vana/{data-gateway,vana-sdk,unity-surfaces,personal-server-ts,personal-server-ts-spike-enclave}`.

## 1. Flow

Actors: **Web** (apps/web enclave client), **Account** (apps/account intents, Privy signer), **GW** (data-gateway), **Agent** (node agent in the CVM, `personal-server-ts/packages/enclave`, does not exist yet), **Chain**.

1. Owner opens "Enable your always-on Personal Server" in Web. Web calls `POST /v1/identity {ownerAddress, chainId}` (unauthenticated, idempotent; the response is public data, cf. public `GET /v1/servers?owner=` at `data-gateway/api/v1/servers.ts:56-69`).
2. GW picks a node (`ENCLAVE_AGENT_URL` + `ENCLAVE_AGENT_SECRET` env in step 2; `tee_nodes` selection once step 1 merges) and calls Agent `POST /agent/v1/identity {ownerAddress, chainId, epoch}`. Agent computes `userPsId` itself (`spike-enclave/packages/enclave/src/identity/paths.ts:33-43`), derives the wallet at `walletPath` (`identity/wallet.ts:69-85`, raw key bytes), reads `info()` (`dstack/real.ts:62-71`: `app_id`, `compose_hash`, `instance_id`) and `quote(keccak256(userPsId || address))` (`dstack/real.ts:99-118`), returns `EnclaveIdentityEvidence`. No sandbox starts.
3. GW verifies evidence (section 3: two-link secp256k1 chain to pinned KMS root + `app_id` allowlist), upserts `identity_records` (`state='prepared'`), returns `IdentityResponse` incl. `serverUrl = GATEWAY_PUBLIC_ORIGIN` (`data-gateway/lib/web3-signed.ts:233-240`).
4. Web re-verifies the same chain in the browser with SDK `verifyEnclaveIdentityEvidence` against the SDK-pinned anchor and shows one consent with the revocation guarantee.
5. **Registration signature (owner, EIP-712, V2 today).** Web calls Account intent `personal_server.server_registration.v1` (`unity-surfaces/apps/account/src/lib/signing/personal-server-intent-service.ts:164-325`) with `serverAddress=evidence.address`, `serverPublicKey=evidence.publicKey`, `serverUrl=IdentityResponse.serverUrl`. Privy signs silently (`:275-283`); external wallets go through the signing exchange (`:201-212`). Typed data = SDK `buildPersonalServerRegistrationTypedData` (`vana-sdk/packages/vana-sdk/src/protocol/personal-server-registration.ts:174-191`, types `eip712.ts:139-146`).
6. Web submits `POST /v1/identity/{userPsId}/register` with `Authorization: Web3Signed <sig>` (bare EIP-712 sig, same as `POST /v1/servers`, `data-gateway/lib/auth.ts:11-28`). GW checks the body equals the identity row (address, publicKey, serverUrl) and runs the existing registration path (extracted from `api/v1/servers.ts:245-620`): row in `servers` with `status='pending'` (`db/schema.ts:192`), `identity_records.state='registered'`. **`confirming` (decision 19) = `servers.status IN ('pending','submitting')`**; no new enum on `servers`.
7. **Master signature (owner, EIP-191 `vana-master-key-v1`).** Web calls new Account intent `personal_server.enclave_delivery.v1` with the evidence. Account verifies evidence, signs `vana-master-key-v1` via Privy (existing `signOwnerBindingWithPrivy`, `constrained-silent-signing.ts:191`), builds `MasterSignatureDelivery`, ECIES-encrypts it to `evidence.publicKey` (SDK `NodeECIESProvider`, `crypto/ecies/node.ts:50`), returns ciphertext only. Web posts `POST /v1/identity/{userPsId}/secret`.
8. GW relays ciphertext blind to Agent `POST /agent/v1/secrets/seal`. Agent decrypts with the wallet key, checks `recoverServerOwner(masterSignature) == ownerAddress` (SDK `crypto/keys/derive.ts:59-66`) and `enclaveAddress == derived`, seals (`sealing/envelope.ts:49-66`, AAD = userPsId), returns the envelope. GW stores `sealed_secrets`; `identity_records.state='sealed'`. Product state _on_ = registered AND sealed.
9. `/v1/cron/settle` settles `registerServerWithSignature` as today (`data-gateway/lib/settle.ts:1817`); `servers.status` -> `confirmed|finalized|failed`. `failed` rolls the identity back to `prepared` (decision 19).
10. Revoke = existing `DELETE /v1/servers/:address` (`api/v1/servers/[address].ts:159-412`); the same transaction retires the identity and hard-deletes `sealed_secrets` (section 3). Re-enable derives epoch+1 (new path suffix, new address, decision 12).

**V3 forward compatibility.** `IdentityRegistrationRequest.version` discriminates `'v2' | 'v3'`; `identity_records.registration_version` stores it; V3 adds `nonce, deadline` to the same `ServerRegistration` primaryType (contract change, step 3). Bridge for replay (decision 11): GW refuses a registration whose `serverAddress` belongs to a retired `identity_records` row (`409 IDENTITY_RETIRED`); Agent refuses to derive/seal for `epoch < current` (retired epoch).

**Agent HTTP surface (minimum, `personal-server-ts/packages/enclave/src/agent/http.ts`, reachable only from GW with `Authorization: Bearer <ENCLAVE_AGENT_SECRET>`):**

- `GET /agent/v1/health` -> `{appId, composeHash, instanceId, osVersion}` (from `DstackInfo`, `dstack/client.ts:17-26`).
- `POST /agent/v1/identity` `{ownerAddress, chainId, epoch}` -> `EnclaveIdentityEvidence`.
- `POST /agent/v1/secrets/seal` `{ownerAddress, chainId, epoch, enclaveAddress, ciphertext}` -> `{envelope, secretHash}` | `422 OWNER_MISMATCH | 409 EPOCH_RETIRED`.

## 2. vana-sdk `protocol/identity`

File `vana-sdk/packages/vana-sdk/src/protocol/identity.ts`. Ships as `@opendatalabs/vana-sdk/protocol/identity` with no entry-point change: tsup emits every `src/**/*.ts` unbundled (`tsup.config.ts:6-19`) and `package.json:93-100` exports `./*` -> `dist/*.js` (Account already imports `.../protocol/personal-server-registration`, `constrained-silent-signing.ts:2-7`). Also re-export from `index.node.ts`/`index.browser.ts` next to `protocol/eip712` (`index.node.ts:167`). Browser-safe: `verifyEnclaveIdentityEvidence` uses `@noble/curves` recovery, no `secp256k1` native.

```ts
import type { Address, Hex } from "viem";
import type { ServerRegistrationMessage } from "./eip712";

export const ENCLAVE_IDENTITY_EVIDENCE_VERSION = 1;
export const USER_PS_ID_DOMAIN = "vana.ps-enclave.v1"; // = enclave paths.ts:16
export const ENCLAVE_WALLET_PURPOSE = "vana.ps-enclave.wallet.v1"; // = paths.ts:23
export const MASTER_SIGNATURE_DELIVERY_VERSION = "vana.ps-enclave.delivery.v1";
export const SEALED_ENVELOPE_VERSION = 1; // = envelope.ts:22

export type UserPsId = Hex; // keccak256(encodePacked(["string","uint256","address"], [DOMAIN, chainId, owner]))
export function userPsId(chainId: number, ownerAddress: Address): UserPsId; // byte-identical to paths.ts:33-43

export interface EnclaveIdentityEvidence {
  v: typeof ENCLAVE_IDENTITY_EVIDENCE_VERSION;
  userPsId: UserPsId;
  chainId: number;
  ownerAddress: Address;
  epoch: number; // path suffix: users/{id}/wallet/ethereum/secp256k1/v{epoch}
  address: Address;
  publicKey: Hex; // 65-byte uncompressed 0x04..; publicKeyToAddress(publicKey) == address
  appId: Hex; // 20 bytes (dstack app_id)
  composeHash: Hex; // 32 bytes
  osImageHash?: Hex; // UNVERIFIED that info()/tcb_info exposes it on 0.5.9; omit when absent
  purpose: string; // ENCLAVE_WALLET_PURPOSE (link 0 preimage input)
  signatureChain: [Hex, Hex]; // [appRoot over keccak256(purpose||":"||hex(pubkey)), kmsRoot over keccak256("dstack-kms-issued"||":"||appId||sec1c(appRootPub))]
  quote: Hex; // raw TDX quote; report_data = keccak256(userPsId || address). Stored, not parsed (DCAP = step 4)
  eventLog?: string;
  kmsRootFingerprint: Hex; // keccak256(uncompressed KMS root pubkey); must equal the pinned anchor's fingerprint
}

export interface IdentityRequest {
  ownerAddress: Address;
  chainId: number;
}
export type IdentityState = "prepared" | "registered" | "sealed" | "retired";
export interface IdentityResponse {
  identity: EnclaveIdentityEvidence;
  state: IdentityState;
  created: boolean;
  serverUrl: string; // exact ServerRegistration.serverUrl the owner must sign (Gateway origin)
  serverId?: Hex;
  serverStatus?:
    "pending" | "submitting" | "confirmed" | "finalized" | "failed";
  sealed: boolean;
}

export type IdentityRegistrationRequest =
  | { version: "v2"; message: ServerRegistrationMessage } // eip712.ts:216-221
  | {
      version: "v3";
      message: ServerRegistrationMessage & { nonce: string; deadline: string };
    }; // step 3, contracts V3
export interface IdentityRegistrationResponse {
  serverId: Hex;
  state: "registered";
  serverStatus: "pending";
}

/** Inner plaintext of the ECIES box. Owner authentication = recover(masterSignature) over MASTER_KEY_MESSAGE. */
export interface MasterSignatureDelivery {
  v: typeof MASTER_SIGNATURE_DELIVERY_VERSION;
  userPsId: UserPsId;
  epoch: number;
  enclaveAddress: Address;
  ownerAddress: Address;
  masterSignature: Hex; // 65 bytes, EIP-191 over MASTER_KEY_MESSAGE (crypto/keys/derive.ts:26)
  issuedAt: number; // unix s; agent rejects if |now - issuedAt| > 600
}
export interface SealedSecretSubmission {
  userPsId: UserPsId;
  epoch: number;
  enclaveAddress: Address;
  ciphertext: Hex; // ECIES iv(16)||ephemPub(65)||ct||mac(32) to evidence.publicKey (crypto/ecies/interface.ts:10)
}
export interface SealedSecretResponse {
  sealed: true;
  secretHash: Hex;
  sealedAt: string;
} // secretHash = sha256(ciphertext)

/** Persisted envelope, mirror of enclave sealing/envelope.ts:31-40; Gateway treats it as opaque text. */
export interface AesGcmBox {
  iv: string;
  ciphertext: string;
  tag: string;
} // base64
export interface SealedEnvelope extends AesGcmBox {
  v: typeof SEALED_ENVELOPE_VERSION;
  wrappedContentKey: AesGcmBox;
}

export interface EnclaveTrustAnchors {
  kmsRootPubkey: Hex;
  appIds: Hex[];
} // per chainId constants exported here
export interface ExpectedIdentity {
  ownerAddress: Address;
  chainId: number;
  epoch: number;
}
export const MASTER_SIGNATURE_DELIVERY_MAX_AGE_SECONDS = 600;
// Throws. Checks pubkey -> address, both chain links (compressed-key preimages,
// raw app_id), anchors.kmsRootPubkey in COMPRESSED form (as kmsInfo().k256Pubkey
// reports it), appId allowlist, purpose, and that userPsId/owner/chainId/epoch
// equal `expected` (userPsId recomputed). Fails closed on empty anchors.
export function verifyEnclaveIdentityEvidence(
  e: EnclaveIdentityEvidence,
  anchors: EnclaveTrustAnchors,
  expected: ExpectedIdentity,
): Promise<void>;
// Rejects unless masterSignature recovers to e.ownerAddress over MASTER_KEY_MESSAGE.
export function buildMasterSignatureDelivery(
  e: EnclaveIdentityEvidence,
  masterSignature: Hex,
  now?: number,
): Promise<MasterSignatureDelivery>;
// Rejects unless publicKeyToAddress(publicKey) == d.enclaveAddress.
export function encryptMasterSignatureDelivery(
  d: MasterSignatureDelivery,
  publicKey: Hex,
  ecies: ECIESProvider,
): Promise<Hex>;
```

**New EIP-712 owner signature: none in v1.** The delivered master signature is itself an owner EIP-191 signature; recovery binds it to `ownerAddress` and hence to `userPsId` (Agent recomputes it). Adding a `MasterSignatureDelivery` typed-data signature would be a third prompt for external wallets, contrary to the "two signatures" decision. Message versions: `ServerRegistration` V2 (domain `Vana Data Portability`/`1`, `eip712.ts:12-13`), `ServerRegistration` V3 (same primaryType, +`nonce`,`deadline`; step 3), `vana-master-key-v1` (unchanged), `vana.ps-enclave.delivery.v1` (plaintext envelope version, not signed).

## 3. data-gateway `api/v1/identity`

Caller identification today: write endpoints take a bare EIP-712 signature in `Authorization: Web3Signed <sig>` plus `ownerAddress` in the body and require recovered signer == owner (`api/v1/servers.ts:256-257, 373-396`); identity-bearing reads use `Web3Signed <base64url(payload)>.<sig>` request signatures (`lib/web3-signed.ts:22-45, 173-222`). No `x-vana-*` headers. Operator routes use `CRON_SECRET` bearer (`lib/operator-auth.ts:24-48`). CORS is `*` (`lib/cors.ts:3-8`).

| Method/path                            | Auth                                                                     | Request                       | Response                       | Codes / idempotency                                                                                                                                                                                        |
| -------------------------------------- | ------------------------------------------------------------------------ | ----------------------------- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /v1/identity`                    | none                                                                     | `IdentityRequest`             | `IdentityResponse`             | 200 (`created` flag); 400; 502 `ENCLAVE_UNAVAILABLE`; 502 `EVIDENCE_REJECTED`; 503 `ENCLAVE_NOT_CONFIGURED`. Idempotent: returns the live row (state != retired) without re-deriving.                      |
| `GET /v1/identity?owner=0x..&chainId=` | none (public, like `GET /v1/servers?owner=`)                             | query                         | `IdentityResponse`             | 200; 404                                                                                                                                                                                                   |
| `POST /v1/identity/:userPsId/register` | `Web3Signed <eip712 sig>`; signer == `message.ownerAddress` == row owner | `IdentityRegistrationRequest` | `IdentityRegistrationResponse` | 201; 200 if same signature already stored; 400 field != identity row; 401 bad sig; 404; 409 `IDENTITY_RETIRED`; 409 `ALREADY_REGISTERED` (different sig); 503 fee-enabled (`servers.ts:469-482` unchanged) |
| `POST /v1/identity/:userPsId/secret`   | none at GW (Agent authenticates by owner recovery; see Open 1)           | `SealedSecretSubmission`      | `SealedSecretResponse`         | 201; 200 same `secretHash`; 404; 409 `IDENTITY_RETIRED`; 409 `SECRET_MISMATCH` (different hash for the epoch; master signature is deterministic per decision 5); 422 `OWNER_MISMATCH` (from Agent); 502    |

Handlers: `api/v1/identity.ts`, `api/v1/identity/[userPsId]/register.ts`, `api/v1/identity/[userPsId]/secret.ts`; `vercel.json` rewrites specific-before-generic (`vercel.json:3-62` pattern), `register`/`secret` `maxDuration: 30`. Registration logic extracted from `api/v1/servers.ts:245-620` into `lib/servers.ts` `registerServer()` and reused by both routes (no behaviour change for `POST /v1/servers`).

**Drizzle (`db/schema.ts`, plus hand-written idempotent `db/migrations/0053_identity.sql`; `0052` is taken by `spike/jobs`; rules in `db/migrations/README.md`):**

```ts
identity_records: user_ps_id varchar(66), epoch integer default 1, PK (user_ps_id, epoch)
  owner_address varchar(42) NN, chain_id integer NN, enclave_address varchar(42) NN UNIQUE, public_key text NN,
  app_id varchar(42) NN, compose_hash varchar(66) NN, os_image_hash varchar(66), evidence text NN (JSON EnclaveIdentityEvidence),
  node_id text, state varchar(12) NN default 'prepared', registration_version varchar(4), server_id varchar(66) (-> servers.id, null until registered),
  prepared_at timestamp default now NN, registered_at, sealed_at, retired_at timestamp
  idx: identity_records_owner_idx (owner_address, chain_id); identity_records_state_idx (state)
sealed_secrets: user_ps_id varchar(66), epoch integer, PK (user_ps_id, epoch)
  envelope text NN (JSON SealedEnvelope), envelope_version integer NN default 1, secret_hash varchar(66) NN,
  sealed_by_node text, created_at timestamp default now NN
```

Text over jsonb matches existing conventions (`schema.ts:2-16` imports no `jsonb`). Derived `serverStatus` comes from a join on `servers` by `server_id`; no state is duplicated.

**Delete-on-revoke hook.** `api/v1/servers/[address].ts:389-400` does a single `update servers set revoked_at ...`. Wrap it in `db.transaction` (pattern `api/v1/servers.ts:533`) and add: `update identity_records set state='retired', retired_at=now() where enclave_address=$serverAddress and state!='retired'`; `delete from sealed_secrets where (user_ps_id, epoch) in (...)`. Hard delete, not soft. Neon PITR backups expire with the window (operational, no code). `POST /v1/identity` after retire derives `epoch+1`.

**Attestation verification v1 (`lib/tee/kms-chain.ts`, decision 26; DCAP deferred to step 4).** Checked, in order, before any row is written: (1) `publicKeyToAddress(publicKey) == address` (`viem/accounts`, as `servers.ts:328`); (2) recover app-root pubkey from `signatureChain[0]` over `keccak256(utf8(purpose || ":" || lowercase_hex(sec1_compressed(publicKey))))`; (3) recover KMS root from `signatureChain[1]` over `keccak256("dstack-kms-issued" || ":" || app_id_raw_20_bytes || sec1_compressed(appRootPub))` and compare to `ENCLAVE_KMS_ROOT_PUBKEY` env in compressed form (from `phala kms phala` / `DstackKms.kmsInfo().k256Pubkey`, spike doc Q4; encodings verified against dstack source and a live CVM vector, spike results doc "Chain vector"); (4) `appId ∈ ENCLAVE_APP_ID_ALLOWLIST` (csv env; the SDK ships the same values per chainId for the browser, GW env is authoritative, mismatch fails closed); (5) `composeHash` recorded, not enforced in step 2 (Spike 1 showed env updates rotate it; enforcement joins the `tee_nodes` measurement policy in step 1/4). Quote is stored opaque. Preimage encodings verified 2026-09-02; the live vector is pinned as a test in all three repos.

Tests: `tests/identity-handlers.test.ts` mocking `../db/index.js` and the agent client (pattern `tests/builders-post-handler.test.ts:24-37`); `tests/kms-chain.test.ts` with a generated chain (`@noble/curves`) plus the captured vector; Postgres-gated `tests/identity-postgres.test.ts` (`vitest.config.ts:6` include).

## 4. unity-surfaces `apps/account` signing

- **Reused, unchanged:** `personal_server.server_registration.v1` (`personal-server-intent-service.ts:164-325`; body `{serverAddress, serverPublicKey, serverUrl, chainId?, verifyingContract?}` parsed at `:595-635`; `serverUrl` must be https or localhost `:611-613`, satisfied by the Gateway origin). Signs exactly the SDK typed data (`constrained-silent-signing.ts:65-80`). External wallets: signing exchange rebuilds the typed data with the recovered owner (`signing-exchange-confirmation.tsx:412-420`).
- **Reused:** `personal_server.owner_binding.v1` = `vana-master-key-v1` (`:327-450`; Privy `signOwnerBindingWithPrivy` `constrained-silent-signing.ts:191`; desktop refused `:352-365`; external wallets `personal_sign` in the exchange `signing-exchange-confirmation.tsx:386`, stored encrypted `enc:v1:` `signing-exchange-store.ts:88-121`). Web caches it 8 h in localStorage (`apps/web/src/features/personal-server/owner-signature.ts:36-45`); that cache stays for PS Lite until step 5 and is not used for the enclave path.
- **New intent `personal_server.enclave_delivery.v1`** (`apps/account/src/lib/signing/enclave-delivery.ts`, route `src/app/api/v1/intents/personal-server-enclave-delivery/sign/route.ts`, mobile scope `personal_server.enclave_delivery.sign`). Body: `{ intent, evidence: EnclaveIdentityEvidence }`. Account: `verifyEnclaveIdentityEvidence(evidence, anchors)`; asserts `evidence.ownerAddress == wallet.address`; obtains the master signature (Privy silent, or exchange-stored for external wallets); `buildMasterSignatureDelivery`; ECIES to `evidence.publicKey` with `NodeECIESProvider` (`vana-sdk .../crypto/ecies/node.ts:50`, exported `index.node.ts:60`; equivalent string helper `WalletKeyEncryptionService.encryptWithWalletPublicKey(data, publicKey)` returns hex without `0x`, `crypto/services/WalletKeyEncryptionService.ts:60-91`). Response: `{ status: "signed", intent, submission: SealedSecretSubmission }`. The raw signature never reaches the web page on this path.
- **Attested channel v1, concretely:** ECIES (secp256k1, AES-256-CBC+HMAC, `crypto/ecies/interface.ts:9-34`) to the enclave wallet public key taken from evidence _after_ the chain check, carried over the Gateway as a blind relay (`POST /v1/identity/:id/secret` -> Agent). Confidentiality: only the key at `walletPath(userPsId, epoch)` decrypts, and that key exists only inside CVMs under the allowlisted `app_id` (key reuse, decision 24). Authenticity: ECIES has no sender auth, so the Agent authenticates the plaintext by recovering the master signature to the owner. Freshness: `issuedAt` (10 min).
- Web (`apps/web/src/features/personal-server/enclave/`): `prepareIdentity`, `verifyEvidence` (SDK, browser), `signRegistration` (existing `client.signTypedData`, `web-personal-server-session.ts:865`, decoupled from a booted PS Lite `:843-883`), `submitRegistration`, `deliverSecret`, `status`.

## 5. PR plan

1. **vana-sdk** `feat(protocol): enclave identity types and evidence verifier` — `src/protocol/identity.ts` (+`identity.test.ts`), exports in `index.node.ts`/`index.browser.ts`; optional `SERVER_REGISTRATION_V3_TYPES` stub in `eip712.ts` left for step 3. Publish a PR prerelease (`3.23.0-pr.<n>.<sha>`; precedent: account pins `3.13.4-pr.186.276dad0`, `apps/account/package.json:21`). SDK is at `3.22.0` (`package.json:3`).
2. **personal-server-ts** `feat(enclave): merge spike package + node agent identity endpoints` — merge `spike/enclave` `packages/enclave` (`ed161d3`); `identity/paths.ts` gains `epoch` (`walletPath(id, epoch)`, `sealingPath(id, epoch)`); `agent/http.ts` (3 endpoints, bearer secret); `agent/evidence.ts` builds `EnclaveIdentityEvidence` from `deriveEnclaveIdentity` + `info()` + `quote()`; `agent/seal.ts` (decrypt, recover, seal); tests on `dstack/fake.ts`. Depends on SDK pr-tag (bump from `3.14.0`, `packages/core/package.json:145`). Parallel to 3.
3. **data-gateway A** `feat(identity): schema, kms chain verifier, agent client` — `db/schema.ts`, `db/migrations/0053_identity.sql`, `lib/identity.ts`, `lib/tee/kms-chain.ts`, `lib/enclave-agent.ts`, `lib/servers.ts` (`registerServer` extraction), tests. **SDK consumption:** data-gateway has no SDK dependency (`package.json:36-41`) and mirrors EIP-712 types locally (`lib/eip712.ts:160-185`). Keep that: mirror the DTOs in `lib/identity-types.ts` with a header naming the SDK version, and add the SDK as a **devDependency only** for a shape-equality test. Local integration: `"@opendatalabs/vana-sdk": "file:../vana-sdk/packages/vana-sdk"` after `npm run build` in the SDK (resolves `dist/protocol/identity.js` through the `./*` export). Before merge: replace with the published pr-tag, refresh `package-lock.json`, and CI must fail on any `file:` spec.
4. **data-gateway B** `feat(identity): /v1/identity routes and delete-on-revoke` — three handlers, `vercel.json`, `api/v1/servers/[address].ts` transaction hook, env docs (`ENCLAVE_AGENT_URL/SECRET`, `ENCLAVE_KMS_ROOT_PUBKEY`, `ENCLAVE_APP_ID_ALLOWLIST`). Fake agent in tests; real agent on a Phala CVM for the preview run.
5. **unity-surfaces A** `feat(account): enclave delivery intent` — files in section 4; SDK bump to pr-tag; route tests mirroring `intents/personal-server-owner-binding/sign/__tests__/route.test.ts`.
6. **unity-surfaces B** `feat(web): enclave consent and Personal Server screen` — enclave client, consent UI, two user states.

## 6. Resolved 2026-09-02, confirmed 2026-09-03 (Kahtaf)

1. **Auth on `POST /v1/identity` and `/secret`: unauthenticated in v1.** Web has no silent generic request signer; the Agent's owner-recovery check authenticates the secret; per-owner and per-IP limits land with `lib/rate-limit` (step 4).
2. **Trust anchors for the browser**: constants in `protocol/identity.ts` keyed by chainId (1480, 14800); Gateway env is authoritative; mismatch fails closed.
3. **Sealing AAD binds `${userPsId}/${epoch}`**, and the wallet and sealing paths carry the epoch (`.../v{epoch}`). Lands in `packages/enclave` before the node agent; the Spike 2 fixture is regenerated.
4. **Register before seal.** _On_ requires both; a sealed-but-unregistered row is harmless and retried.
5. **`composeHash` recorded, not enforced** in step 2; enforcement joins the `tee_nodes` measurement policy.
6. **Gateway stays SDK-free at runtime**: identity DTOs mirrored in `lib/identity-types.ts`; the SDK is a devDependency for a shape-equality test (local `file:` during development, published pr-tag before merge).
7. **`kmsRootFingerprint = keccak256(uncompressed KMS root)`** everywhere; the SDK compares anchors in compressed form and accepts either encoding; Gateway env accepts both.
8. **DCAP quote verification stays at step 4.** Until then the owner/chain/epoch binding lives only in `report_data`; the bearer-authenticated Gateway-to-agent channel is the backstop.
9. **Fleet replicas share one `app_id`** (a different `app_id` cannot decrypt the fleet's jobs); each replica gets its own `NODE_ID`/`NODE_SECRET` via `phala cvms replicate -e <env-file>`.
10. **Account builds against throwaway vana-sdk #208** (main + escrow #186 + #207, dist-tag `pr-208`) until #186 merges; close #208 then.
11. **Web consent panel** ships behind `NEXT_PUBLIC_PS_ENCLAVE_ENABLED` (default off), copy marked draft in `enclave-copy.ts`, revoke disabled until the SDK has a deregistration builder.
12. **Web external-wallet owners are refused in v1 (2026-09-03, unity-surfaces #990 review).** The browser fallback that signed `vana-master-key-v1` and ECIES-encrypted client-side is removed (raw signature never in web JS, section 4). Account's signing exchange (`POST /api/v1/signing-exchanges`) accepts Desktop clients only, so Web shows a non-retryable "not supported yet" state. Decision 5 (external wallets in scope) still needs an Account change: open the exchange to Web sessions, or an Account-origin signing route that returns ciphertext only.
13. **Test-fleet anchors (2026-09-03).** The SDK anchor map stays empty until fleet provisioning. Web reads `NEXT_PUBLIC_PS_ENCLAVE_ANCHOR_OVERRIDE` (JSON `{kmsRootPubkey, appIds}`) in non-production builds only, ignored in production; it replaces the SDK anchor for the chain. Level C = the consent flow with a real Privy owner (prepare, browser verify, registration, sealed delivery, _on_); the builder job stays at level B because no owner-signed grant path exists without the owner's key.

### Critical files

- data-gateway/api/v1/servers.ts (registration path to extract; api/v1/servers/[address].ts for the revoke hook)
- data-gateway/db/schema.ts
- vana-sdk/packages/vana-sdk/src/protocol/eip712.ts (with new sibling protocol/identity.ts)
- unity-surfaces/apps/account/src/lib/signing/personal-server-intent-service.ts
- personal-server-ts-spike-enclave/packages/enclave/src/identity/wallet.ts (with identity/paths.ts, sealing/envelope.ts, dstack/real.ts)
