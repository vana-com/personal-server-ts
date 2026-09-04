# Jobs contract (step 1, derisking slice)

Status: design, 2026-09-03. Section 7 answers confirmed by Kahtaf 2026-09-03.
Parent: `260901-personal-server-gateway-enclave-architecture.md` decisions 3, 9, 13, 15, 19, 20, 22-24 (lines 29, 38, 42, 47, 54-59); Job model (:122-130); Workflows 2, 4, 5 (:149-185); Invariants (:187-194). Spikes 3 and 4 (`260902-enclave-spike-results.md` :145-262). Extends `260902-identity-contract.md` (agent surface :25-29, Gateway env :197). Repos: `/Users/kahtaf/Documents/workspace_vana/{vana-sdk-identity,data-gateway-identity,personal-server-ts-enclave}` (+ spikes `data-gateway-spike-jobs`, `personal-server-ts-spike-sandbox`).

## 1. Flow

Actors: **Builder** (SDK, server-side secret key, decision 7), **GW**, **Agent** (`packages/enclave`, one per CVM), **Sandbox** (PS enclave profile, one per owner), **Operator**.

1. Builder builds `JobRequest` (grantId, scope, pinnedVersion?, deadline, builderPublicKey), signs it as a Web3Signed payload with the builder key (SDK `buildWeb3SignedHeader`, `auth/web3-signed-builder.ts:56-68`; `uri=/v1/jobs/execute`), ECIES-encrypts `{request, auth}` to the owner's enclave public key (`GET /v1/identity?owner=` → `identity.publicKey`; key reuse, decision 24; wire `iv||ephemPub||ct||mac`, `crypto/ecies/interface.ts:10`), and calls `POST /v1/jobs?wait=25` with the outer body signed `Web3Signed` (spike `api/v1/jobs.ts:94-98`).
2. GW admits, refuse-only (decision 9): builder row exists (`builders.grantee_address`, `db/schema.ts:77-101`); owner identity live and sealed (`lib/identity.ts:19 findLive`, state `sealed`); grant row exists, `grantor==owner`, `grantee_id==builder.id`, not revoked (`schema.ts:374-435`); pins `pinnedVersion = data_points.expected_version` for (owner, scope) (`schema.ts:1359`; null when no row, UNVERIFIED that one row per (owner, scope) is the invariant); sets `price=0, payer='builder', paymentState='none'` (decision 15; settlement v1.1); enqueues idempotently (`repository.ts:75-106`). Holds up to 25 s (`wait.ts:19-37`), returns 200 inline or 202.
3. Agent long-polls `POST /v1/jobs/claim?wait=25` (Spike 4 recommendation, :192) with `Authorization: Bearer <nodeSecret>` + `X-Node-Id`; GW sweeps lapsed leases then claims in one `UPDATE … WHERE id IN (SELECT … FOR UPDATE SKIP LOCKED) RETURNING` (`repository.ts:127-148`), lease `claim_expires_at`, fencing on `claimed_by` (`:152-154`). Claim response carries the work order plus the owner's `sealedEnvelope` (ciphertext only, `sealed_secrets`).
4. Agent derives the enclave wallet key (`identity/wallet.ts:102`), ECIES-decrypts the request (`agent/ecies.ts` as used by `seal.ts:49`), checks inner binding `jobId == claimed id`, `deadline > now`, zeroes the key. Wallet never leaves the agent.
5. Agent wakes or creates the sandbox keyed `userPsId:epoch`: `unseal` (`sealing/envelope.ts:77-102`, AAD `userPsId/epoch` `:105`), inject `VANA_MASTER_KEY_SIGNATURE` + per-sandbox `PS_ACCESS_TOKEN` + public identity (`PS_SERVER_ADDRESS`, `PS_SERVER_PUBLIC_KEY`) into the container env only (spike `launcher.ts:174-188`), wait for `/health` then sync complete (`launcher.ts:263-307`). Heartbeats `POST /v1/jobs/:id/heartbeat` every `LEASE/3` while waking (spike worker `:26-27`).
6. Agent posts the plaintext `{request, auth}` to the sandbox `POST /enclave/v1/jobs/execute` (bearer `PS_ACCESS_TOKEN`, `bootstrap.ts:255-282`). PS re-authorizes before plaintext: recovers `auth` signer == `request.builder`; loads grant + builder rows from GW; verifies grant signature recovers to owner (SDK `verifyGrantRegistration`, `protocol/grants.ts:88`), builder signature recovers (`BUILDER_REGISTRATION_TYPES`, `eip712.ts:148-155`), `publicKeyToAddress(builder.publicKey)==granteeAddress`, `builder.id==grant.granteeId` (`policy/data-read.ts:155`), scope coverage (`:148`), expiry, `revokedAt` (`:113`; chain RPC check = step 4, TODO), own registration `serverAddress==PS_SERVER_ADDRESS` via `GET /v1/servers`. Reads the scope; asserts local version == `pinnedVersion` when pinned (else `VERSION_MISMATCH`, retryable); redacts (`api/index.ts:951`); ECIES-encrypts `JobResult` to `builder.publicKey` (`NodeECIESProvider.encrypt`, `crypto/ecies/base.ts:201`); returns ciphertext + sha256 + size. Plaintext never leaves the sandbox.
7. Agent `POST /v1/jobs/:id/complete {resultCiphertext, resultHash}` (fenced, `repository.ts:211-233`; `409 LEASE_LOST` on a stale lease, `http.ts:159-162`; `already_done` idempotent). Non-retryable errors → `POST /v1/jobs/:id/fail {reason}` (`:236-255`). Retryable errors → agent stops heartbeating; the lease lapses; another node re-claims (attempt < 3, else `expired`, `:271-293`; measured 13.8 s, spike :183).
8. Builder gets 200 inline or polls `GET /v1/jobs/:id` (404 for any other signer, `[id].ts:55-58`), decrypts with its private key (`WalletKeyEncryptionService.decryptWithWalletPrivateKey`, `:110`), verifies `jobId`/`scope`/`version` inside the plaintext. Result purged after 24 h (`types.ts:41`).
9. Sandbox TTL: `ready → expiring` after idle TTL; a claim for that owner cancels; else `docker rm --force --volumes` (`launcher.ts:250-252`) destroys tmpfs and SQLite (Workflow 4).
10. Operator: `scripts/tee/provision.sh` (`:59,90-102`) with a pre-generated `NODE_SECRET` in the initial env (env updates rotate `compose_hash`, Spike 1 :115), `POST /v1/tee-nodes` (operator secret) registers expected `app_id`/`compose_hash`/URL/secret hash; Agent heartbeats `POST /v1/tee-nodes/:id/heartbeat`; operator `admit`; `drain` stops claims, running jobs finish, sandboxes torn down, `removed`.

**Who signs what / which key encrypts what.** Builder key: signs outer `Web3Signed` and inner `auth`; result is encrypted _to_ it. Enclave wallet (`walletPath`, `paths.ts:48`): request is encrypted _to_ it; agent decrypts; it signs nothing in this slice. Owner: grant (EIP-712, GW `grants.signature`) and master signature (sealed). Node secret: bearer only. PS inside the sandbox: never signs (section 4b). GW: stores ciphertext, never decodes (`complete.ts:52` measures size only).

## 2. vana-sdk `protocol/jobs`

File `src/protocol/jobs.ts` (+ `crypto/envelope/job.ts` helpers; `crypto/envelope/` already holds `openpgp.ts:22,43`). Ships as `@opendatalabs/vana-sdk/protocol/jobs` unbundled (`tsup.config.ts:6-13`); re-export from `index.node.ts`/`index.browser.ts` next to `protocol/identity` (`index.node.ts:196`). Types only + pure helpers; no fetch client in this PR.

```ts
import type { Address, Hex } from "viem";
export const JOB_PROTOCOL_VERSION = 1;
export const JOB_OPERATIONS = ["raw_read", "inference"] as const; // = spike types.ts:8
export type JobOperation = (typeof JOB_OPERATIONS)[number];
export const JOB_STATES = [
  "queued",
  "claimed",
  "running",
  "completed",
  "failed",
  "expired",
  "cancelled",
] as const; // = types.ts:11-19
export type JobState = (typeof JOB_STATES)[number];
export type PaymentState = "none" | "reserved" | "settled"; // = types.ts:31
export const DEFAULT_LEASE_SECONDS = 30; // = DEFAULT_CLAIM_TTL_SECONDS, types.ts:35
export const MAX_LEASE_SECONDS = 300; // = types.ts:37
export const MAX_ATTEMPTS = 3; // = types.ts:39
export const MAX_WAIT_SECONDS = 25; // = types.ts:44; submit and claim
export const CLAIM_POLL_FLOOR_MS = 1000; // server-side re-check inside a held claim
export const MAX_INLINE_RESULT_BYTES = 1_048_576; // = complete.ts:18
export const DEFAULT_JOB_DEADLINE_SECONDS = 600;
export const MAX_JOB_DEADLINE_SECONDS = 3600;

/** Inner plaintext of the request box (ECIES to the enclave publicKey). */
export interface JobRequest {
  v: 1;
  jobId: string;
  owner: Address;
  builder: Address;
  builderPublicKey: Hex;
  grantId: Hex;
  scope: string;
  operation: JobOperation;
  pinnedVersion: string | null;
  deadline: string; /* ISO */
}
export interface JobRequestEnvelope {
  request: JobRequest;
  auth: string; /* "Web3Signed <b64>.<sig>" by builder over uri /v1/jobs/execute, bodyHash = sha256(JSON(request)) */
}
/** Outer body of POST /v1/jobs (signed Web3Signed by the builder). */
export interface JobSubmission {
  owner: Address;
  grantId: Hex;
  scope: string;
  operation: JobOperation;
  idempotencyKey: string;
  jobId: string;
  /* client uuid, echoed in JobRequest */ deadline?: string;
  requestCiphertext: string; /* base64 ECIES */
}
export interface JobStatus {
  jobId: string;
  state: JobState;
  operation: JobOperation;
  owner: Address;
  grantId: Hex;
  scope: string;
  pinnedVersion: string | null;
  attempt: number;
  price: string;
  payer: "builder";
  paymentState: PaymentState;
  createdAt: string;
  claimedAt: string | null;
  completedAt: string | null;
  failureReason: string | null;
  resultCiphertext?: string;
  resultHandle?: string;
  resultHash?: Hex;
  resultSize?: number;
  resultExpiresAt?: string;
} // = builderView http.ts:102-127
export interface ClaimRequest {
  leaseSeconds?: number;
  capacity?: number;
}
export interface ClaimResponse {
  job: {
    jobId: string;
    owner: Address;
    builder: Address;
    grantId: Hex;
    scope: string;
    operation: JobOperation;
    pinnedVersion: string | null;
    requestCiphertext: string;
    attempt: number;
    deadlineAt: string | null;
    claimExpiresAt: string;
    fencingToken: number; /* = attempt; every node write echoes it */
  };
  identity: {
    userPsId: Hex;
    epoch: number;
    enclaveAddress: Address;
    enclavePublicKey: Hex;
    sealedEnvelope: SealedEnvelope;
  };
} // nodeView http.ts:130-143 + identity
export interface HeartbeatRequest {
  leaseSeconds?: number;
  fencingToken: number;
}
export interface CompleteRequest {
  fencingToken: number;
  resultHash: Hex;
  resultSize: number;
  resultCiphertext?: string;
  /* inline <= MAX_INLINE_RESULT_BYTES */ resultHandle?: string; /* v1.1, R2 */
}
export interface FailRequest {
  fencingToken: number;
  reason: string; /* <= 1024, fail.ts:16 */
}
export interface FencedResponse {
  success: true;
  jobId: string;
  state: JobState;
  claimExpiresAt: string | null;
} // respondFenced http.ts:150-155
/** Inner plaintext of the result box (ECIES to builderPublicKey). */
export interface JobResult {
  v: 1;
  jobId: string;
  scope: string;
  version: string | null;
  contentType: string;
  body: string; /* base64 */
}
export type TeeNodeState = "pending" | "admitted" | "draining" | "removed";
export interface TeeNodeRegistration {
  nodeId: string;
  appId: Hex;
  composeHash: Hex;
  publicUrl: string;
  capacity: number;
  secret: string;
}
export interface TeeNodeHeartbeat {
  composeHash: Hex;
  instanceId: string;
  activeSandboxes: number;
  capacity: number;
}
export interface TeeNode {
  nodeId: string;
  appId: Hex;
  composeHash: Hex;
  publicUrl: string;
  state: TeeNodeState;
  capacity: number;
  activeSandboxes: number;
  lastHeartbeatAt: string | null;
}
// crypto/envelope/job.ts
export function sealJobRequest(
  e: JobRequestEnvelope,
  enclavePublicKey: Hex,
  ecies: ECIESProvider,
): Promise<string>;
export function openJobRequest(
  ciphertext: string,
  privateKey: Uint8Array,
  ecies: ECIESProvider,
): Promise<JobRequestEnvelope>;
export function sealJobResult(
  r: JobResult,
  builderPublicKey: Hex,
  ecies: ECIESProvider,
): Promise<{ ciphertext: string; hash: Hex; size: number }>;
export function openJobResult(
  ciphertext: string,
  builderPrivateKey: Hex,
  ecies: ECIESProvider,
  expect: { jobId: string },
): Promise<JobResult>;
```

Mapping: spike `lib/jobs/types.ts:8-46` constants are byte-identical; `JobRecord` (`:48-75`) stays Gateway-internal; the spike's `pinnedVersion: string` and `requestCiphertext: base64` (`api/v1/jobs.ts:192-199`) are kept. New versus spike: `jobId` chosen by the client (bound inside the ciphertext; the Gateway rejects a mismatch with the idempotency row), `fencingToken`, `identity` in the claim, `resultHandle`. `SealedEnvelope` imported from `protocol/identity.ts:166`.

**Amendments 2026-09-03 (from vana-sdk #209 review).** `openJobResult(ciphertext, builderPrivateKey, ecies, expect: { jobId; scope?; version? })`. `auth.bodyHash = sha256(canonicalJobRequestBytes(request))` where `canonicalJobRequestBytes` (exported) is JSON with keys sorted recursively, no whitespace, UTF-8; `sealJobRequest` encrypts the same bytes. Gateway views `GET /v1/grants/:id` and `GET /v1/builders/:address` carry the registration `signature` so the sandbox can re-verify (§1 step 6). Published as `3.22.0-pr.209.13d545d`.

**Amendments 2026-09-03 (from personal-server-ts #251 review and level-A run).** §1 step 1: the builder's inner `auth` audience is the configured Gateway origin, not the request URL. §7.1 confirmed in practice: only the storage client signs (`download`, `upload`, `delete`); the data-point listing is unsigned, so the enclave profile uses a public-read storage mode and no agent-side signer exists. The sandbox runs the PS as a child process from a fake runtime at level A. The enclave compose binds the nested Docker API to the compose network address with `--icc=false` and an iptables drop, requires `GIT_REF` to be a 40-hex commit verified after checkout, and publishes the sandbox port on the runtime host. Claim loop: concurrent runs up to `capacity`, every run aborted at the last confirmed `claimExpiresAt`. Level A `e2e:job` 13/13; level B for jobs pending a published PS image digest.

**Amendments 2026-09-03 (Fable reviews of data-gateway #103 and personal-server-ts #251).** Gateway: the env-configured agent fallback is disabled in production (503 when no admitted node is fresh); a claim whose owner has no live sealed identity fails the job (`OWNER_NOT_READY`) instead of burning attempts; a client `jobId` that collides returns 409 `JOB_ID_TAKEN`; `complete` verifies `resultHash == sha256(ciphertext)`; the held claim re-checks only stale leases, not the full sweep; operator bearer compare is constant-time. Enclave: Gateway transport failures retry with backoff; empty claims poll no faster than 1 s; a node key-derivation fault leaves the job to another node; sandbox secrets never appear on `docker` argv; `PS_IMAGE` and `GATEWAY_URL` are validated at boot; registry entries are destroyed before the container stops. Open for Kahtaf: admission ignores grant and builder `status`/`paymentStatus` (`lib/jobs/admission.ts`); recommended to keep for this slice and enforce with payments at step 4.

**Level B for jobs (2026-09-03, Phala dstack 0.5.9, two CVMs, `dp-rpc-moksha` preview with a Neon branch).** Raw-read job through a real gVisor sandbox in a CVM: 12 of 13 steps pass (the two-node lease-recovery step fails only because a real node claims the test jobs before the drain window; the same recovery passed at level A with two agents). Timings: submit to decrypted result cold 19 to 26 s (mean 22 s, 7 samples; claim, sandbox boot, hydration, first read), warm 1.1 to 1.6 s (mean 1.3 s, same sandbox); CVM boot to healthy agent 5.5 to 9 min with the in-CVM image build; admit to first heartbeat under 20 s. Findings, not yet patched: (1) `scripts/e2e-job.ts` has no env override for the DataRegistry contract, and the SDK default disagrees with the Gateway's env example; (2) `lib/tee/nodes.ts:72-91` returns the stale row when a removed node id is re-registered; (3) `NODE_ID`/`NODE_SECRET` live in the CVM's encrypted env, so `phala cvms replicate` without `-e` clones the node id, and an operator-side id that differs from the baked one fails silently; replicas MUST share the fleet `app_id` (a different `app_id` cannot decrypt the fleet's jobs, decision 26 as designed); (4) the remote driver cannot force a slow claim for the recovery step. Deploy findings deferred from review: no restart policy on the agent service; `provision.sh` drops the compose hash silently when extraction fails.

## 3. data-gateway

Auth conventions: builder = Web3Signed request signature (`lib/web3-signed.ts:173-200`, spike `http.ts:79-99`); node = `Authorization: Bearer <nodeSecret>` + `X-Node-Id` verified against `tee_nodes.secret_hash` (replaces `rejectUnauthorizedOperator`, spike `http.ts:47-58`); operator = `Bearer CRON_SECRET` (`lib/operator-auth.ts:24-48`; separate `OPERATOR_SECRET` env with fallback to `CRON_SECRET`, arch :179).

| Method/path                                             | Auth                         | Request → Response                                                      | Codes / idempotency                                                                                                                                                                                         |
| ------------------------------------------------------- | ---------------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /v1/jobs?wait=0..25`                              | builder                      | `JobSubmission` → 200 `{job: JobStatus}` \| 202 `{jobId,state,created}` | 400 `INVALID_WAIT/INVALID_BODY`, 401, 403 `BUILDER_UNKNOWN/GRANT_INVALID/OWNER_NOT_READY`, 413 (256 KiB, `jobs.ts:33`), 409 `JOB_ID_MISMATCH`; idempotent on (builder, idempotencyKey) (`repository.ts:89`) |
| `GET /v1/jobs/:id`                                      | builder                      | → `JobStatus`                                                           | 404 for non-submitter (`[id].ts:55-58`); `Cache-Control: no-store`                                                                                                                                          |
| `POST /v1/jobs/claim?wait=0..25`                        | node (state `admitted`)      | `ClaimRequest` → 200 `ClaimResponse` \| 204                             | sweep then claim (`claim.ts:49-55`) every `CLAIM_POLL_FLOOR_MS` until `wait` expires; `maxDuration: 30`; 403 `NODE_NOT_ADMITTED` (draining nodes get 204)                                                   |
| `POST /v1/jobs/:id/heartbeat`                           | node (admitted or draining)  | `HeartbeatRequest` → `FencedResponse`                                   | 409 `LEASE_LOST`, 404; also `fencingToken != attempt` → 409                                                                                                                                                 |
| `POST /v1/jobs/:id/complete`                            | node                         | `CompleteRequest` → `FencedResponse`                                    | 413 `RESULT_TOO_LARGE` (1 MiB), 400 `INVALID_RESULT_HASH`; `already_done` → 200 (`repository.ts:168-178`)                                                                                                   |
| `POST /v1/jobs/:id/fail`                                | node                         | `FailRequest` → `FencedResponse`                                        | as heartbeat                                                                                                                                                                                                |
| `POST /v1/tee-nodes`                                    | operator                     | `TeeNodeRegistration` → `TeeNode` (state `pending`)                     | 201; 200 same nodeId+secret hash; 409 different; a `removed` row re-registers in place as fresh `pending` (201, data-gateway #104)                                                                          |
| `POST /v1/tee-nodes/:id/heartbeat`                      | node (any state but removed) | `TeeNodeHeartbeat` → `{state}`                                          | records `compose_hash`, `instance_id`, `active_sandboxes`, `last_heartbeat_at`; mismatch with registered `app_id` → 403                                                                                     |
| `POST /v1/tee-nodes/:id/admit` \| `/drain` \| `/remove` | operator                     | → `TeeNode`                                                             | state machine pending→admitted→draining→removed; admit requires a heartbeat < 60 s and matching `compose_hash`                                                                                              |
| `GET /v1/tee-nodes`                                     | operator                     | → `TeeNode[]`                                                           | secret hash never returned                                                                                                                                                                                  |
| `GET /v1/cron/jobs-sweep`                               | cron                         | → `{requeued, expired, purged}`                                         | every minute: `expireStaleClaims` (belt and braces, spike :194) + null `result_ciphertext` past `result_expires_at`                                                                                         |

Handlers promoted from the spike verbatim where unchanged: `api/v1/jobs.ts`, `jobs/[id].ts`, `jobs/claim.ts`, `jobs/[id]/{heartbeat,complete,fail}.ts`, `lib/jobs/{types,repository,http,wait}.ts`, `vercel.json` rewrites (`:29-34`, specific-before-generic) and `maxDuration` (`:79`). New: `lib/jobs/admission.ts`, `lib/tee/nodes.ts` (registry + `selectNode`), `api/v1/tee-nodes.ts`, `api/v1/tee-nodes/[id]/{heartbeat,admit,drain,remove}.ts`, `api/v1/cron/jobs-sweep.ts`, `lib/jobs-types.ts` mirror of the SDK types (SDK-free at runtime, shape test, precedent `lib/identity-types.ts:1`).

**Claim SQL (spike, `repository.ts:127-148`, unchanged):** `UPDATE jobs SET state='claimed', claimed_by=$node, claimed_at=now(), claim_expires_at=now()+make_interval(secs=>$ttl), attempt=attempt+1, updated_at=now() WHERE id IN (SELECT id FROM jobs WHERE state='queued' ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING *`. Every node write: `WHERE id=$id AND claimed_by=$node AND state IN ('claimed','running')` (`:152-154`) plus `AND attempt=$fencingToken`. Sweep (`:271-293`): lapsed lease → `queued` while `attempt < 3` else `expired`; queued past `deadline_at` → `expired`. Claim additionally inserts `job_attempts`.

**Drizzle (`db/schema.ts`, migration `db/migrations/0054_jobs.sql`, idempotent, after `0053_identity.sql`):** the spike already names the table `jobs` (`schema.ts:1752-1753`, `0052_jobs.sql:15`); `0052` is not re-used, its DDL moves into `0054`.

```text
jobs: spike 0052_jobs.sql:15-51 columns (id uuid, owner_address, builder_address, grant_id, scope, operation, state, pinned_version bigint,
  request_ciphertext, result_ciphertext, result_hash, result_size, result_expires_at, claimed_by, claim_expires_at, claimed_at,
  completed_at, attempt, failure_reason, deadline_at, price numeric(78,0), payer, payment_state, idempotency_key, created_at, updated_at)
  + user_ps_id varchar(66) NN, epoch integer NN, chain_id integer NN, result_handle_id uuid NULL (-> result_handles); indexes as 0052:43-51
job_attempts: id bigserial PK, job_id uuid NN (-> jobs), attempt integer NN, node_id varchar(128) NN, claimed_at NN, ended_at,
  outcome varchar(16) (completed|failed|lease_lost|expired), failure_reason text; UNIQUE (job_id, attempt)
result_handles: id uuid PK, job_id uuid NN, bucket text NN, object_key text NN, size integer NN, hash varchar(66) NN, expires_at NN,
  created_at NN  -- created now, unused until private R2 (v1.1); inline cap 1 MiB
tee_nodes: id varchar(128) PK, app_id varchar(42) NN, compose_hash varchar(66) NN, instance_id text, public_url text NN,
  secret_hash varchar(66) NN, state varchar(12) NN default 'pending', capacity integer NN default 20, active_sandboxes integer NN default 0,
  last_heartbeat_at, admitted_at, drained_at, created_at NN; idx (state, last_heartbeat_at)
```

**Node selection for identity.** `lib/tee/nodes.ts selectNode(db)`: an `admitted` node with `last_heartbeat_at > now()-60s`, lowest `active_sandboxes/capacity`; `createAgentClient({baseUrl: node.public_url})` (`lib/enclave-agent.ts:61-65` already accepts `baseUrl`; the fleet-wide `ENCLAVE_AGENT_SECRET` env stays for GW→agent calls). `api/v1/identity.ts:57-58` and the secret handler switch to `selectNode`; when `tee_nodes` is empty and `ENCLAVE_AGENT_URL` is set, fall back to env (dev). `identity_records.node_id` (`0053:21`) is populated.

## 4. personal-server-ts

**(a) `packages/enclave` agent.** New modules, all behind ports so the fake runs without Docker:

- `sandbox/runtime.ts`: `SandboxRuntime { start(spec: SandboxSpec): Promise<SandboxHandle>; stop(id): Promise<void>; inspect(id) }`, `SandboxSpec = { userPsId, epoch, env, image }`, `SandboxHandle = { id, origin }`. `sandbox/docker-runtime.ts` promotes spike `launcher.ts:29-34, 149-197, 206-254` fixed to gVisor: `runtime=runsc-ptrace`, `--user 1000:1000 --read-only --cap-drop ALL --security-opt no-new-privileges:true --tmpfs /data:rw,noexec,nosuid,nodev,size=256m,uid=1000,gid=1000,mode=0700` (`:164-172`), no mounts, env `CLOUD_MODE=true DEV_UI_ENABLED=false TUNNEL_ENABLED=false ENCLAVE_MODE=true PERSONAL_SERVER_ROOT_PATH=/data` (`:174-181`) + `VANA_MASTER_KEY_SIGNATURE`, `PS_ACCESS_TOKEN`, `PS_SERVER_ADDRESS`, `PS_SERVER_PUBLIC_KEY`, `SYNC_ENABLED`. Drop the `key.json` entrypoint hack (`:189-195`); the sandbox has no key.json. Docker CLI targets the trusted runtime container (`DOCKER_HOST=tcp://sandbox-runtime:2375`, section 4c). Readiness = `/health` then `/v1/sync/status` + `/v1/data` count (`:274-307`).
- `sandbox/registry.ts`: `Map<"userPsId:epoch", { handle, state: starting|ready|expiring|destroyed, lastUsedAt, accessToken }>`; `SANDBOX_IDLE_TTL_SECONDS` (600), `SANDBOX_MAX` (20; 240 is a RAM ceiling only, spike :252-254); LRU-evict idle `ready` when full; a claim for an `expiring` owner cancels teardown.
- `jobs/claim-loop.ts`: `while (!draining) claim(wait=25) → run → …`; `jobs/run.ts`: heartbeat timer (`lease/3`), decrypt (`identity/wallet.ts:102` + `agent/ecies.ts`), `registry.acquire()` → unseal (`sealing/envelope.ts:77`) → `runtime.start` → `POST {origin}/enclave/v1/jobs/execute` → `complete`/`fail`; `LEASE_LOST` aborts silently. `jobs/gateway-client.ts`: claim/heartbeat/complete/fail/node-heartbeat with `NODE_SECRET`, `X-Node-Id`.
- `agent/main.ts` (`:13-18`) also starts the claim loop and node heartbeat (every 20 s); `agent/bootstrap.ts:19-36` gains `GATEWAY_URL`, `NODE_ID`, `NODE_SECRET`, `SANDBOX_RUNTIME=docker|fake`, `PS_IMAGE` (digest), `SANDBOX_MAX`, `SANDBOX_IDLE_TTL_SECONDS`, `LEASE_SECONDS`. New agent HTTP routes: none for GW (agent pulls); add `GET /agent/v1/health` fields `activeSandboxes`, `draining`; `POST /agent/v1/drain` (bearer) for operator scripts.

**(b) `packages/server` enclave profile.** `ENCLAVE_MODE=true` (in addition to `CLOUD_MODE`, `bootstrap.ts:513`): (1) new entry `src/enclave-main.ts` reads `VANA_MASTER_KEY_SIGNATURE` once, `delete process.env.VANA_MASTER_KEY_SIGNATURE`, passes `ownerSignature` via the existing option (`bootstrap.ts:78, 197-198`), refuses `VANA_OWNER_PRIVATE_KEY` (`:200`), forces `devUi.enabled=false`, `tunnel.enabled=false` (loader `config/loader.ts:34-42`) so `psLiteBootstrap` (`app.ts:389`, `routes/ui.ts:28-36`) and frpc never see the secret; (2) key-provider port: `createServer({ serverAccount })` (`bootstrap.ts:78`) receives a `PublicOnlyServerAccount { address, publicKey }` whose `signTypedData/signMessage` throw `ServerSigningUnavailableError`, skipping `loadOrCreateServerAccount(key.json)` (`:231-232`); (3) `src/jobs/worker.ts executeJob(env: JobRequestEnvelope, deps): Promise<{ciphertext, hash, size}>` (runtime-agnostic; desktop could host it) doing section 1 step 6 by calling `verifyDataReadPolicy` (`core/policy/data-read.ts:68-71`) with the Gateway-backed ports (`core/ports/index.ts:24-29`) plus a new `signed-artifacts.ts` pre-check (grant/builder signature recovery), then the storage read used by `handlePersonalServerDataRequest` (`core/api/index.ts:992`, redaction `:1284`); (4) route `POST /enclave/v1/jobs/execute` (bearer `PS_ACCESS_TOKEN`) mounted only under `ENCLAVE_MODE`.

**PS signing decision: the PS never signs in v1.** Recommendation: the only server signatures on the read path are `signRecordDataAccess` for x402 (`core/payment/x402.ts:233`; payment off in the enclave, `bootstrap.ts:192`) and `signGrantRegistration` (`core/signing/signer.ts:29`; removed for the enclave, decision 10); the raw branch skips `reportReadFulfillment` (arch :335). Consequences: `policy/data-read.ts` unchanged in shape but gains the signed-artifact pre-check and the own-registration check; `signAddData` unavailable, so the sandbox cannot upload (builder writes are v1.1; the sync upload worker is disabled in enclave mode); receipts move to Gateway job state (decision 15). An agent-side signing endpoint is not added; revisit at step 4 if receipts need a server signature.

**(c) Compose.** `deploy/dstack/docker-compose.enclave.yml` (from spike `docker-compose.sandbox.yml:5-7, 26-28, 37-41`): `agent` (mounts `/var/run/dstack.sock` only, plus `DOCKER_HOST` pointing at the runtime) and `sandbox-runtime` (`docker:27-dind`, privileged, `--cgroupns=host`, holds the nested Docker socket, no dstack socket, `runsc` release pinned by sha512 and installed as `runsc-ptrace`). Sandbox image = `PS_IMAGE` pinned by digest; the published `vanaorg/personal-server@sha256:dc6dfd…` fails with `ERR_MODULE_NOT_FOUND @opendatalabs/vana-sdk` (spike :242), the spike's rebuilt image adds SDK 3.14.0 (`compose.sandbox.yml:86-89`); fix the Dockerfile in `packages/server` and publish a digest before level B. `docker-compose.agent.inline.yml:4-29` (git-clone bootstrap) stays for dev; `scripts/tee/provision.sh` gains `--compose` default to the enclave compose and `NODE_SECRET` in the env file (`:90`).

## 5. e2e

`scripts/e2e-job.ts` (pattern `scripts/e2e-identity.ts:102-131 runStep`, `:287-488` steps; runner `e2e-identity-local.sh`): steps 1-6 = identity flow (prepare, verify, register, seal). Then: 7 register a throwaway builder (`BUILDER_REGISTRATION_TYPES`, `eip712.ts:148-155`, `scripts/register-builder.ts:14-18` pattern) via `POST /v1/builders`; 8 owner signs a grant (`GRANT_REGISTRATION_TYPES` + `grantRegistrationDomain`, `eip712.ts:65,118-126`; GW `api/v1/grants.ts:6 recoverGrantRegistrationSigner`) via `POST /v1/grants`; 9 seed one record through the PS write path `POST /v1/data/:scope` with an owner Web3Signed header (`scripts/e2e-write-api.ts:1-22`; spike `scripts/hydration-fixture.ts:3`); 10 submit `?wait=25`, expect 200 inline, `openJobResult`, assert plaintext; 11 negatives: revoked grant (`DELETE /v1/grants/:id` owner-signed) → job `failed` `GRANT_REVOKED`; wrong builder key (request encrypted to a random key / `auth` by another key) → `failed` `BUILDER_MISMATCH`; expired lease: start agent A with `WORK_DELAY_MS=120000`, SIGKILL its process group after 5 s (spike gotcha :183), agent B completes, assert `attempt=2`, and A's late `complete` gets 409.

**Level A (no Docker on this machine):** GW stand-in `scripts/dev-server.ts` + `npm run dev:pg` (identity-local prerequisites); agent with `SANDBOX_RUNTIME=fake` (`sandbox/fake-runtime.ts`): boots the PS in-process via `createServer()` (`scripts/e2e-read-scope.ts:39` precedent) on a random port with the same env the container would get, `SYNC_ENABLED=false`, so data comes from step 9's write and `pinnedVersion` is null. Covers: queue, admission, ECIES both ways, unseal via `DSTACK_FAKE=1` (`agent/bootstrap.ts:30-34`), registry TTL, fencing, lease recovery, all negatives. **Level B (Phala CVM):** gVisor isolation, real unseal, hydration and pinned version against Moksha (`dp-rpc-dev`, spike :268), sandbox recreated on a second node mid-test (drain node A, node B claims), cold-start budget (7.5 s + sync, spike :248, :277).

## 6. PR plan

1. **vana-sdk** on #207 (`247f7c0`): `src/protocol/jobs.ts`, `src/crypto/envelope/job.ts` (+ tests), index re-exports; publish `3.22.0-pr.<n>.<sha>` (pin precedent `packages/enclave/package.json:35`). Blocks 2 and 3 at type level only: both mirror or pin; start against `file:` and swap to the pr-tag before merge (identity contract PR plan 3).
2. **data-gateway** on #100 (`6c1feae`): `db/schema.ts`, `db/migrations/0054_jobs.sql`, `lib/jobs/*` (spike + admission), `lib/jobs-types.ts`, `lib/tee/nodes.ts`, `api/v1/jobs*`, `api/v1/tee-nodes*`, `api/v1/cron/jobs-sweep.ts`, `vercel.json`, `api/v1/identity*.ts` → `selectNode`, tests (`tests/jobs-handlers.test.ts:31-38` mock pattern, `tests/jobs-repository-postgres.test.ts`), `scripts/jobs-worker.ts` kept as a fake node. Independent of 3 at runtime (contract by HTTP).
3. **personal-server-ts** on #245 (`506b761`): `packages/enclave/src/{sandbox,jobs}/*`, `agent/{main,bootstrap,http}.ts`, `packages/server/src/{enclave-main,jobs/worker,routes/enclave-jobs}.ts`, `packages/core/src/policy/signed-artifacts.ts`, `deploy/dstack/docker-compose.enclave.yml`, `scripts/tee/provision.sh`, `scripts/e2e-job.ts`, `package.json` script `e2e:job`, SDK bump. Depends on 1 (imports `protocol/jobs`) and on 2 for the level-A run.

Level-A run order: SDK build → GW `dev:pg` + `0053` + `0054` + `dev:server` → agent (`DSTACK_FAKE=1 SANDBOX_RUNTIME=fake`) → `POST /v1/tee-nodes` + admit → `npm run e2e:job` → second agent for the lease-recovery step.

**Full e2e joins (2026-09-03, builder app → desktop data → TEE PS → result).** Three joins between proven legs: (1) desktop-uploaded data hydrated by the sandbox: the desktop bundles personal-server-ts core whose default `dataRegistry` (`packages/core/src/schemas/server-config.ts:25`, `0x8f1e…1867`) matches what the dp-rpc-moksha Vercel project actually runs (verified 2026-09-03 with `vercel env pull`, production and preview), while the SDK's generated addresses, the docs and data-gateway `.env.example` say `0x8C87…Cb7C`; both addresses are live proxies on Moksha (`0x8f1e…` is DataRegistryV2, the one the dev Gateway signs against; `0x8C87…` is the older registry the docs list); decision 2026-09-04 (Kahtaf): follow the deployed dev environment, so the Gateway env example and the e2e default move to `0x8f1e…` and test Gateways use it; the desktop cannot send a Vercel bypass header, so test previews run unprotected for the window; a desktop registration and an enclave registration for one owner coexist (`servers.serverAddress` unique, owner only indexed; `GET /v1/servers?owner=` newest first). (2) Owner-signed grants: the web flow signs grants with the PS Lite delegate key, which the sandbox rejects (decision 10); Account gains intent `personal_server.grant_registration.v1` and web an owner-signed grant path for enclave owners (unity-surfaces `feat/owner-signed-grant`). (3) Builder half against an existing owner: `scripts/e2e-job.ts` gains `E2E_BUILDER_ONLY=1` with `OWNER_ADDRESS`, `GRANT_ID`, `BUILDER_PRIVATE_KEY` (personal-server-ts `feat/e2e-job-existing-owner`).

**Level B, run 3 (2026-09-03, heads personal-server-ts 5919438, data-gateway 02b91d9).** Inline image-id path boots the jobs runtime; `verify_agent_node_id` passes as written. Jobs 12 of 13 again: the recovery step stays unprovable because `WORK_DELAY_MS` did not reach the replica (defect, fix in flight). Density on one `tdx.small`: N=5 concurrent fresh owners all missed the 25 s wait; 4 of 5 jobs stuck at attempt 3 in sandbox acquire, one completed at 72 s; RAM not measurable on the production dstack image. Conclusion: `SANDBOX_MAX=20` is unproven at any instance size; the derisking claim for decision 13 needs a `tdx.2xlarge` rerun after the acquire path is fixed. New defects: stage failures log only `error.name`; `replicate.sh` never surfaces its generated `NODE_SECRET`; re-registering a non-removed `pending` node id returns the stale row (contract choice, open).

**Full e2e, attempt 1 (2026-09-03).** Real Privy owner, Level C identity, owner-signed grant minted through the new Account intent from the web data-connection approval screen, builder-only driver (`E2E_BUILDER_ONLY=1`): identity and grant checks pass, the job is admitted, claimed and executed on the Phala node, then fails `SIGNED_ARTIFACT_INVALID`. Root cause, reproduced offline: the Gateway grant view returns `expiresAt` as an ISO timestamp while `GrantRegistration.expiresAt` is uint256 seconds, and `signed-artifacts.ts` passes the view value verbatim, so every grant with an expiry fails sandbox re-verification. Levels A and B never saw it because the scripted grants used `expiresAt = "0"`. Fix: normalise the view value before recovery and register expiring grants in the e2e (personal-server-ts #258); the Gateway view now also carries `expiresAtSeconds` (data-gateway #105). Second defect from the same probe: `grants.expires_at` is a naive `timestamp` column, so a Gateway process outside UTC (a local dev server) shifts the signed expiry by its offset and breaks recovery; Vercel's UTC hid it (fixed: `timestamptz` column with migration 0055, data-gateway #106).

**Fleet placement rule (2026-09-04).** A CVM's public URL is `<app_id>-<port>.<node domain>`, so two replicas of one `app_id` on the same Phala physical node share a hostname and only one is reachable; the operator scripts' nodeId cross-check then reports the older CVM. Replicas of a fleet go on distinct physical nodes (`--node-id`), and a rolling replacement on the same node must delete the old CVM first.

**Full e2e, attempt 2 (2026-09-04, node rebuilt from the expiry fix).** Identity, grant and signature re-verification pass; the job fails `SCOPE_NOT_FOUND`: the sandbox hydrates from the core default `https://storage.vana.org`, while the Moksha dev environment stores blobs at `https://storage-dev.vana.org` (`environments.json` `dev.storageApiUrl`), so a real owner's data is never downloaded. The enclave entry honours only `GATEWAY_URL`; the agent forwards no storage endpoint. Levels A and B missed it because the scripted seed wrote to the same default host, which also means spike data landed in the production storage namespace under chain 14800. Fix: `STORAGE_API_URL` through agent, compose, operator scripts, enclave entry and the e2e driver (personal-server-ts `fix/enclave-storage-endpoint`).

**Full e2e, attempt 3 (2026-09-04, node updated in place from `847fc88` with `STORAGE_API_URL`).** Identity and grant pass; the job loses its lease three times and expires. Cause (agent container log): `Unknown sandbox environment key: STORAGE_API_URL` at `sandbox-acquire`, because `sandbox/runtime.ts` allowlists sandbox env keys and the storage fix did not extend it; level A ran without the variable, so the fake runtime's identical check never fired (fixed: personal-server-ts #261). Operational notes: a replica inherits its source compose, so a compose change must go through `phala deploy --cvm-id <uuid>` on the existing CVM (same `app_id`, the KMS key and the sealed identity survive; the new compose hash needs a new `tee_nodes` row because heartbeats match on it); `phala logs` returns only the first ~300 lines, the dashboard log panel has the runtime lines.

**Full e2e PASSED (2026-09-04 04:20Z, personal-server-ts `44e9294`, data-gateway `dd9d5d6`).** Builder (registered grantee, `E2E_BUILDER_ONLY=1` driver) → owner-signed grant `spotify.profile` minted by the real Privy owner through web + Account (Level C) → `POST /v1/jobs` on the `dp-rpc-moksha` preview → claimed by the Phala node (`app_id 0xec9a…`, dstack 0.5.9, gVisor sandbox) → sandbox PS hydrates the owner's blob from `storage-dev.vana.org` → ECIES result decrypted by the builder: `spotify.profile` version 3, 6 top-level keys. B1 sealed identity, B2 grant verification, B3 raw read, B4 wrong-key rejection all pass, twice. Cold (new sandbox, hydration) submit to decrypted result 34.8 s; warm (same sandbox, 10 min idle TTL) 2.1 s. Level B jobs numbers (22 s cold on scripted seed data) hold; the extra cold time is the real owner's multi-scope hydration.

**Builder app end to end (2026-09-04 04:50Z).** Lorebook (a registered test app, branch `feat/enclave-jobs-read`: vana-sdk `pr-210`, `VANA_READ_MODE=enclave`) running locally: DCR created from its UI against the local web app, owner approved, owner-signed grant minted through Account, web completed the DCR via the new `delivery: "enclave"` path (unity-surfaces `fix/web-enclave-dcr-complete`: the browser-PS reachability probe is skipped and the Gateway recorded as the durable destination), Lorebook polled `ready_for_read`, submitted the raw-read job through `createJobsClient().readRaw`, decrypted the result and rendered the owner's Spotify profile. First attempt failed only on that probe (`personal_server_unreachable` after the grant existed); the CLI path (`pnpm enclave:read`) read the same grant in 13 s before the fix. Reviewed the same night (two Fable passes, fixes via Codex): web `/complete` with `delivery: "enclave"` now verifies the grant on the DCR network's Gateway (grantor = owner, `granteeId` = the builder id from `GET /v1/builders/{grantee address}`, scopes cover the request, not revoked or expired), returns 503 `gateway_unavailable` on transient Gateway failures (client retries) and 400 `grant_not_found` on a definitive miss, persists `personal_server.delivery = "enclave"` with no Personal Server URL, and the DCR status exposes `delivery` and omits `personalServerUrl`; Lorebook acknowledges the read so the web page completes, long-polls the job (`wait=25`, route `maxDuration` 60) and maps a scope mismatch to a terminal 403. Follow-up: the vana-sdk DCR status allowlist drops `delivery`, so SDK consumers cannot branch on it yet.

**Level B, run 5: density and recovery (2026-09-04, heads personal-server-ts `09c9b32`, data-gateway `4bc2437`, preview `dp-rpc-moksha` + Neon branch).** Density on one `tdx.2xlarge` (16 vCPU, 32 GB, `SANDBOX_MAX=20`), N concurrent fresh owners, each a cold sandbox: N=5 5/5 (p50 19.7 s, p95 20.0 s), N=10 10/10 (p50 19.3 s, p95 19.7 s), N=20 20/20 (p50 24.6 s, p95 25.3 s, max 25.6 s, peak `activeSandboxes` 20), no failures. Decision 13's `SANDBOX_MAX=20` on `tdx.2xlarge` holds; the earlier `tdx.small` failure was 1 vCPU contention. Two-node recovery: 12 of 13 again. `WORK_DELAY_MS` on a freshly provisioned slow node works (the replica defect was inherited compose env, see below), the driver detects the slow claim, but draining the slow node does not free the job: drain only stops new claims while `startLease()` in `jobs/run.ts` keeps renewing the in-flight lease and `heartbeatClaim` (`lib/jobs/repository.ts:212`) renews on the fencing token alone, so the job completes on the drained node 137 s later. Recovery needs a crash lever (stop the CVM), which the scripts do not have; deferred. Defects: agent `POST /agent/v1/drain` stops the node heartbeat with no resume route (`agent/main.ts:100-109`); a CVM stopped and started after a drain cycle crash-looped on `sandbox-runtime` (platform, not reproduced elsewhere).

## 7. Open questions (answers applied overnight, confirmed 2026-09-03 by Kahtaf)

1. **PS signing inside the sandbox.** Recommend: never in v1 (section 4b); no agent signing endpoint. Revisit if step-4 receipts need `signRecordDataAccess`.
2. **Inline result cap.** Recommend 1 MiB inline (spike `complete.ts:18`, base64 text validated to 1 MB, spike :191); `result_handles` table created empty; R2 v1.1.
3. **Long-poll vs 1 s poll.** Recommend `claim?wait=25` with a 1 s server-side re-check: same DB statement count as the 1 s poll, ~25x fewer invocations, submit→claim p95 ≈ 1 s with one idle node; fall back to 1 s client poll (`jobs-worker.ts:25`) if Vercel function-seconds on the held claim exceed the invocation savings in the preview run (decision 20 trigger).
4. **Node bearer vs signed heartbeats.** Recommend per-node bearer (`secret_hash`) for v1, generated before `phala deploy` so no env update rotates `compose_hash`; attested node sessions (DCAP, `lib/tee`) replace it in step 4 (spike `http.ts:41-45` TODO).
5. **Sandboxes per CVM.** Recommend `SANDBOX_MAX=20` on `tdx.2xlarge` for v1 and raise only after a concurrent-density measurement (240 is RAM-only, spike :254); idle TTL 10 min.
6. **Builder auth binding.** Confirmed: `auth.bodyHash = sha256(canonicalJobRequestBytes(request))` (keys sorted recursively, no whitespace, UTF-8); audience = configured Gateway origin.
7. **Admission ignores grant and builder `status`/`paymentStatus`** (`lib/jobs/admission.ts`). Confirmed for this slice; enforced together with payments at step 4.
8. **Public API changes in personal-server-ts #245** approved under the visibility rule: `redactEnvelopeForGrantee` exported, sync adapter `reads` option, `createServer` `profile`/`serverAccount`, `AppDeps.profile`/`AppDeps.jobWorker`, `createSyncManager` `transferMode`.
