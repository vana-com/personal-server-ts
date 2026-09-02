# Spike results

## Spike 0: dstack facts

Date: 2026-09-02. Read-only; no CVMs. Restored by the coordinator after a concurrent rewrite dropped it.

Sources: dstack repo `Dstack-TEE/dstack` master `9826215` (docs/guest-api-v0.md, guest-api-v1.md, attestation-tdx.md, onchain-governance.md, usage.md, kms/README.md, kms/src/crypto.rs, kms/src/main_service.rs, dstack-util/src/system_setup.rs, os yocto/mkosi docker daemon.json); npm `@phala/dstack-sdk` 0.5.8 (latest published); Phala CLI 1.1.21; `@phala/cloud` 0.4.0; docs.phala.com pages cited inline.

### Q1. Key derivation call

- v0 (dstack OS 0.5.x, SDK 0.5.8): `client.getKey(path?, purpose?, algorithm?)` → `{ key: Uint8Array(32), signature_chain: Uint8Array[2] }`. Only `path` enters the KDF: `HKDF-SHA256(salt="RATLS", IKM=app root secp256k1 key, info=path, L=32)`. `purpose` is only echoed into chain link 0; `algorithm` (secp256k1 default, k256, ed25519 ≥ 0.5.7) does not domain-separate. Derivation is flat (`a/b` is not a child of `a`). https://github.com/Dstack-TEE/dstack/blob/master/docs/guest-api-v0.md ; https://docs.phala.com/phala-cloud/key-management/get-a-key
- v1 (dstack OS 0.6.0, SDK 0.6.0 unreleased): `getKey(domain, algorithm)` with a different KDF (`salt="dstack-guest-v1"`). "v1 keys are different keys." v0 stays served on 0.6 agents, frozen at 0.5.11 behaviour. https://github.com/Dstack-TEE/dstack/blob/master/docs/guest-api-v1.md
- Socket: SDK probes `/var/run/dstack.sock`, `/run/dstack.sock`, `/var/run/dstack/dstack.sock`, `/run/dstack/dstack.sock`. Mount `/var/run/dstack.sock:/var/run/dstack.sock`.
- Predecessor: `TappdClient` on `/var/run/tappd.sock` (0.3.x); `DeriveK256Key` = `GetKey` byte for byte. `toViemAccountSecure` SHA-256-hashes the key first; `toViemAccount` uses raw bytes. https://docs.phala.com/phala-cloud/references/migration-from-dstack-v03

Consequence: pin SDK 0.5.8 and OS 0.5.x; an OS major bump to 0.6 `/v1` re-keys every wallet. Fix the wallet helper (raw bytes) once and never change it.

### Q2. Scope to app_id; stability; setting it

- KMS derives the app root key from KMS root and `app_id` only (`derive_k256_key(root, app_id)`, context `[app_id, "app-key"]`, `kms/src/crypto.rs:11-27`). `compose_hash` and `instance_id` are not inputs. Instance-scoped keys exist only for disk encryption.
- "The app id does not change after the upgrade" (docs/usage.md). Replicas share one `app_id` via `phala cvms replicate` / `phala instances add`. https://docs.phala.com/phala-cloud/cvm/replicating-cvms
- Custom `app_id`, Phala KMS: `phala deploy --custom-app-id <id> --nonce <n>`; pair from `phala api /kms/phala/next_app_id -f counts=N` → `{app_id, nonce}`. Formula not published. On-chain KMS: `app_id` is the `DstackApp` contract address (`KmsAuth.deployAndRegisterApp`), reuse via `--kms-contract`. Default when unset: Phala assigns the next nonce-derived id; self-hosted without KMS uses `sha256(app-compose.json)[..20]`, which changes with compose. https://docs.phala.com/phala-cloud/key-management/deploying-with-onchain-kms

Consequence: second and later nodes are `replicate`, not fresh deploys (whether a second `deploy` with the same pair is accepted is unverified; Spike 1 step 3 tests it).

### Q3. Compose changes under one app_id

- `compose_hash = sha256(app-compose.json)` covering `docker_compose_file`, `allowed_envs`, public flags, pre_launch/init scripts, key_provider. Env value changes alone do not change it (`phala envs update`). https://docs.phala.com/phala-cloud/key-management/updating-with-onchain-kms
- Phala KMS: owner runs `phala deploy --cvm-id <id> -c new.yml`; Phala's control plane authorises; no `addComposeHash`. On-chain KMS: `DstackApp` owner calls `addComposeHash`/`removeComposeHash`; several hashes can be live; multisig flow via `--prepare-only` then `--commit`. https://docs.phala.com/phala-cloud/key-management/multisig-governance

Consequence: "rolling upgrades allow old and new measurements" is an on-chain KMS property. On Phala KMS the approver is the workspace account.

### Q4. What attestation binds; KMS root; chain verification

- TDX quote: MRTD = OVMF; RTMR0 virtual hardware; RTMR1 kernel; RTMR2 cmdline + initrd; RTMR3 event log records compose hash, app id, instance id, key provider. Verifier replays the event log. `report_data` is caller-supplied. https://github.com/Dstack-TEE/dstack/blob/master/docs/attestation-tdx.md
- KMS root k256 public key: `DstackKms.kmsInfo().k256Pubkey` on chain, KMS RPC `GetMeta`, or `phala kms phala`. Pin it out of band.
- App key chain (v0): link 0 = app root key over `keccak256(purpose || ":" || hex(pubkey))`; link 1 = KMS root over `keccak256("dstack-kms-issued" || ":" || app_id || sec1_compressed(app_root_pubkey))`. Verify link 1 against the pinned anchor and confirm `app_id` is ours. No SDK ships a chain verifier. https://github.com/Dstack-TEE/dstack/blob/master/docs/guest-api-v0.md#verifying-a-chain
- Hardware: Intel DCAP (`dcap-qvl`), Phala `POST /api/v1/attestations/verify`, or `dstack-verifier`.
- One KMS root per KMS instance; Phala KMS is one off-chain root for the cloud; on-chain KMS nodes are Phala-operated, governed per chain.

Consequence: the owner-surface evidence bundle is `{quote, event_log, signature_chain, app_id}` anchored at the pinned k256 root. It is a secp256k1 chain, not X.509. Attestation does not bind the inner sandbox.

### Q5. Runtimes inside the CVM

- Guest `daemon.json` registers `sysbox-runc` (Sysbox 0.6.7 in the rootfs) and `nvidia`. No `runsc`. `kernel.unprivileged_userns_clone = 1`; `CONFIG_USER_NS=y`, `CONFIG_SECCOMP_FILTER=y`.
- No compose-level validation rejects `privileged`, `cap_add`, or `runtime` (only `allowed_network_modes` is validated); dstack's own gateway compose runs privileged inside a CVM. Whether Phala's control plane rejects these is UNVERIFIED (Spike 3 step 1).
- No `/dev/kvm` in the guest (`CONFIG_KVM_GUEST=y` only); TDX 1.0 has no nested virtualisation. gVisor KVM platform is out; `systrap` works.
- `init_script` runs before dockerd on every boot and could install a runtime, at the cost of a new compose hash. Untested.

Consequence: Spike 3 order is sysbox-runc system container, then gVisor systrap inside sysbox, then plain hardened container.

### Q6. Phala CLI 1.1.21

`phala cvms create` removed in 1.1.20; `phala deploy` creates and updates.

```text
phala api /kms/phala/next_app_id -f counts=1
phala deploy -n <name> -c compose.yml --custom-app-id <id> --nonce <n> --image <slug> --instance-type tdx.small --node-id <id> --kms phala --wait
phala cvms replicate <cvm-id> --node-id <id>
phala envs update <cvm-id> -e .env
phala deploy --cvm-id <id> -c new.yml --wait
phala cvms get <id> --json ; phala cvms attestation <id> --json ; phala cvms logs <id>
phala cvms delete <id> --force
```

### Also recorded

- Production images on 2026-09-02 (`phala os-images --prod --json`): `dstack-0.6.0-rc0`, `dstack-0.5.9-bd369a8c`, `dstack-0.5.8-6427f4f5`, plus nvidia variants. Nodes: `prod9` (id 18) and `prod5` (id 26) on host v0.6.0 in US-WEST-1; `prod1-v03x` (id 4) on v0.3.6.
- 0.3 → 0.5: `DeriveK256Key(path)` = `GetKey(path)` byte for byte; socket renamed. 0.5 → 0.6: v0 stays available; v1 is a new key space.
- Disk encryption key is per `instance_id`; replicas cannot read each other's disks.

### Contradictions with the architecture doc (now fixed in the doc)

1. Path string is the only domain separation; `secp256k1` in the path is a label, not an algorithm selector. 0.6 `/v1` re-keys.
2. Rolling upgrades with old and new measurements live at once is on-chain KMS only.
3. State the KMS mode; it decides who approves a compose hash. (Decision 26: Phala KMS.)
4. Evidence is a secp256k1 signature chain anchored at `kmsInfo().k256Pubkey`, not an X.509 chain.
5. `removeDevice` exists only on on-chain KMS.
6. Spike 1 step 3 must use `replicate`.
7. Spike 3 must start from sysbox-runc, not gVisor.

One section per spike, see docs/260902-enclave-derisking-spikes.md.

## Spike 1: deterministic identity

Date: 2026-09-02. Operator: Codex on profile `volod-vanas-projects` (`phala status`). CVMs: `spike-identity-1` `7b07c002-8213-418c-8c04-a94a2df6eead` on prod9/node 18; replica `spike-identity-1-rep-s8yvy` `d7a7650e-1a00-4c1f-b746-ee3e6b4e199d` on prod5/node 26; `spike-identity-3` `0e30159d-f49a-4efe-90f0-ad434a850e40` on prod9/node 18 (`phala cvms get <uuid> --json`). dstack OS `0.5.9`, image `dstack-0.5.9-bd369a8c`, SDK `@phala/dstack-sdk@0.5.8` (`phala os-images --prod --json`; probe output). Final spike commit: `ed161d3` on `spike/enclave`, not pushed.

Sources: dstack v0 guest API and KDF facts in Spike 0; `@phala/dstack-sdk@0.5.8`; Phala CLI 1.1.21. The registry-free probe is `spikes/identity/docker-compose.inline.yml`.

App-ID pairs: A `6dda237112dcd6e81806ea5fb82ed478f3ec97f0`, nonce 12 (`phala api /kms/phala/next_app_id -f counts=2`, used for CVM 1 and its replica). Pair B `08456abbc6a6d65a52cf10b3f56fea451cf2eef4`, nonce 13 was consumed concurrently by unrelated `spike-sandbox-sysbox`; the attempted deploy returned `ERR-02-008` and created nothing (`phala cvms list --json | jq '[.items[] | select(.appId == "08456...")]'`). Fresh pair C `24fe217ed41abca37998916bee8793909a5fe5de`, nonce 16 (`phala api /kms/phala/next_app_id -f counts=1`) was used for CVM 3.

### Numbers

All key values came from `phala logs --cvm-id <uuid> --stderr -n 40`; metadata came from `phala cvms get <uuid> --json`.

| step             | node / instance ID                                 | app ID / compose hash                                                  | address / sealing-key SHA-256                                                                                     | result and command                                                                                          |
| ---------------- | -------------------------------------------------- | ---------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| 2 baseline       | prod9 / `e8537021e00663c192fa6cadf43711085a19264b` | A / `f38049645f3c389608ee3e5e4751d32c1933f5d7b3e6133306f10e63b296ae6b` | `0x2e1034E5337f8cDbed78AC1F8EF049Fd3696545e` / `6e0ae9b8108a0b5881b88f2da82d23b9218f58f8ec67b561d6e2a9f4348bce1c` | baseline; `phala deploy --cvm-id 7b07... -c spikes/identity/docker-compose.inline.yml --wait --json`        |
| 3 replica        | prod5 / `5be13fabee0cf323431ca10d039ff555302bfbda` | A / `f38049645f3c389608ee3e5e4751d32c1933f5d7b3e6133306f10e63b296ae6b` | same / same                                                                                                       | pass; `phala cvms replicate 7b07... --node-id 26`                                                           |
| 4a env-only      | prod9 / same as baseline                           | A / `40e30126276c3f63a3cb7caf37da8d2d3c7776a61538ad14290c56bc6d60378a` | same / same                                                                                                       | pass; `phala envs update 7b07... -e PROBE_ENV_BUMP=1`                                                       |
| 4b compose rev 1 | prod9 / same as baseline                           | A / `2ee3eb441c993363d3798e13abb0e01760d99a3199fb454519334d4d068a75de` | same / same                                                                                                       | pass; `phala deploy --cvm-id 7b07... -c spikes/identity/docker-compose.inline.yml --wait`                   |
| 5 different app  | prod9 / `ea01f9616aaefbc839429cdcc5df001b51c93b31` | C / `429248aed18a897af2bf7a46140c61ddb16cba89f2b6c26686974c7fc88b0271` | `0xaA5eCa280B5a9267ecb5bE0A87Ff86a2681cA09A` / `8b1f1ff169b83dd23f4ef76d58bec96e94e3de76c73332578ed8499a36ffe2cd` | differs as required; `phala deploy -n spike-identity-3 ... --custom-app-id 24fe... --nonce 16 --node-id 18` |

For steps 2 through 4, wallet signature chain was identical: link 0 `ee2ea6cfbad4f67ebabb07bd4ce5ed09ff57e81af3136e6776465336b23902a96a0ec6bbec170c6d1745328592cb28492333fccf44f3694cc99dcbfb5c45427c01`; link 1 `0eff924cb21ca7dcc68a2d3284fdf8b96d66327b5cbc721c13ab16454098b9ef09910f91dad8a509e991dfe14cd5a87cbac50582971039dbf8f10505cc684fad00` (same log command). CVM 3 links differed: `bdd3e1b795dd8e5e777c97ce37d7a38f3153d9a3b180daee04b0bfb5732e09c3417dba7c77963b66ee6ea79731a41b58da6b739720d2eba4a557efd0582a1d0001` and `b4fcff85aaf6e14ff7c8457bcf6162063038d692a784b1c1324b51486e14678a6666dddefe5e87b0aaa2614c789c3a3f029b736f854f0fecba558f8ea3edcfe501`.

| metric                                          |        value | runs | command                                                                                                                           |
| ----------------------------------------------- | -----------: | ---: | --------------------------------------------------------------------------------------------------------------------------------- |
| deploy return to first observed probe, CVM 1    |         14 s |    1 | timestamps from `date -u +%FT%TZ` around deploy and 10 s log polling; `node -e "...Date.parse(observed)-Date.parse(returned)..."` |
| replicate return to first observed probe, CVM 2 |         50 s |    1 | same                                                                                                                              |
| deploy return to first observed probe, CVM 3    |         52 s |    1 | same                                                                                                                              |
| attestation JSON                                | 66,811 bytes |    1 | `phala cvms attestation 7b07... --json > spikes/identity/attestation-1.json; wc -c ...`                                           |

The attestation's `app_id` matched A and RTMR event payload matched baseline compose hash `f380...ae6b` (`rg 'app_id|compose_hash|f380...' attestation-1.json`). Step 4b required no separate KMS prompt, transaction, `--prepare-only`, or `--commit`; `phala deploy` alone authorized the new measurement.

Unexpected fact: on Phala KMS, `phala envs update` changed the attested/control-plane compose hash (`f380...ae6b` to `40e3...378a`). The initial compose hardcoded `PROBE_ENV_BUMP=0`, so the first update still printed `0`; the final list-inheritance compose later printed `1` and again changed the hash. Environment values therefore affect Phala's effective measurement even though they do not alter the YAML bytes.

Kill criteria: **passed**. The same app ID and user path produced the same address and sealing key across nodes, env update, and compose updates. Different app ID produced a different address.

Consequence for the architecture doc: in “Identity and keys,” keep deterministic app-ID/path-derived wallets and stateless replicas. Correct the env-update claim: Phala KMS env updates preserve keys but rotate the effective `compose_hash`; attestation policy and rollout logic must treat encrypted-env updates as new measurements. Keep dstack v0/SDK 0.5.8 pinned because v1 re-keys.

## Spike 2: seal and unseal across nodes

Date: 2026-09-02. Operator and CVMs: same as Spike 1 nodes A and B. Implementation: `packages/enclave/src/sealing/envelope.ts`; CVM probe: final `spikes/identity/docker-compose.inline.yml`; fixture generator and committed throwaway fixtures: `spikes/identity/generate-spike2-fixture.ts`, `spikes/identity/fixtures/`.

### Numbers

| metric                    |                                                                            value | runs | command                                                                                                         |
| ------------------------- | -------------------------------------------------------------------------------: | ---: | --------------------------------------------------------------------------------------------------------------- |
| plaintext JSON            |                                                                      1,025 bytes |    1 | `node --import tsx spikes/identity/generate-spike2-fixture.ts`; `wc -c` / `metadata.json`                       |
| OpenPGP ciphertext        |                                                                      1,126 bytes |    1 | same; `wc -c spikes/identity/fixtures/ciphertext.bin`                                                           |
| sealed signature envelope |                                                                   307 JSON bytes |    1 | CVM 1 `SPIKE2_SEAL` from `phala logs --cvm-id 7b07... --stderr -n 80`                                           |
| cross-node unseal         |                                                                      4.871031 ms |    1 | CVM 2 `SPIKE2_UNSEAL` from `phala logs --cvm-id d7a7... --stderr -n 60`                                         |
| plaintext SHA-256         | `c66c5818e5bb48e2a01d55786f6d62a1ee269849f7868d8b80f464e1c3fad3d2`, match `true` |    1 | same CVM 2 log; local expected value from generator                                                             |
| wrong-user negative       |                       AES-GCM `Unsupported state or unable to authenticate data` |    1 | `phala envs update d7a7... ... -e SPIKE2_ACTION=unseal -e TEST_USER_PS_ID=spikeuser2`; poll same log            |
| local envelope tests      |                                                            2 files, 9 tests pass |    1 | `npm test -- packages/enclave/src/sealing/envelope.test.ts packages/enclave/src/sealing/spike2-fixture.test.ts` |

Flow: CVM 1 received the throwaway `MASTER_SIG` with `phala envs update ... -e MASTER_SIG=... -e SPIKE2_ACTION=seal -e TEST_USER_PS_ID=spikeuser1`. CVM 2 received only the base64 envelope, committed ciphertext, expected hash, and action through encrypted env. It re-derived the identical sealing-path key, unwrapped the 65-byte master signature, derived `spike.fixture` with Vana SDK 3.14.0, and decrypted the fixture. Replaying the identical envelope with `TEST_USER_PS_ID=spikeuser2` failed authentication before releasing plaintext.

Kill criterion: **passed**. Node B unwrapped Node A's envelope under the same app ID and recovered the exact local plaintext.

Consequence for the architecture doc: keep stateless cross-node sealing with the app-ID/path-derived key and AAD-bound user ID; no per-node wallet or sealing-secret persistence is required. Record the envelope version and pinned dstack key API as migration boundaries.

Cleanup: all three spike identity CVMs were deleted with `phala cvms delete <exact-uuid> --force`; `phala cvms list --json | jq '[.items[] | select(.cvmName | startswith("spike-identity-"))]'` returned `[]` at 2026-09-02T17:44:26Z. No production or unrelated CVM was modified.

## Spike 4: blind job queue

Date: 2026-09-02. Operator: kahtaf (local machine). CVMs: none (Gateway-only spike). Commit: `33a1062` on `spike/jobs` (worktree `../data-gateway-spike-jobs`, not pushed; `89f1c8b` queue + handlers + tests, `33a1062` worker + load driver). Not deployed to Vercel or Neon: numbers below are local Postgres behind a `vercel dev` stand-in, see "Environment".

### Files (data-gateway, branch `spike/jobs`)

- `db/schema.ts`: `jobs` table (uuid id, owner/builder/grant/scope/operation, state, pinned_version, request/result ciphertext as base64 text, result hash/size/expiry, lease `claimed_by` + `claim_expires_at`, `claimed_at`, `completed_at`, attempt, failure_reason, deadline_at, price/payer/payment_state, idempotency_key). Indexes: unique `(builder_address, idempotency_key)`, claim `(state, created_at)`, partial lease sweep `(claim_expires_at) WHERE state IN ('claimed','running')`, `(builder_address, created_at)`.
- `db/migrations/0052_jobs.sql`: hand-written, idempotent, per `db/migrations/README.md` rules (the drizzle journal is deliberately stale; local uses `db:push`). README updated.
- `lib/jobs/types.ts` (states, operations, TTL/attempt/wait constants, `TODO(move-to-sdk)`), `lib/jobs/repository.ts` (`submitJob` idempotent via `ON CONFLICT DO NOTHING` + re-read; `claimNextJob` = one `UPDATE ... WHERE id IN (SELECT ... FOR UPDATE SKIP LOCKED) RETURNING`; `heartbeatClaim`, `completeJob`, `failJob` fenced on `claimed_by AND state IN (claimed, running)`; `expireStaleClaims` requeues lapsed leases while `attempt < 3`, else `expired`, and expires queued jobs past `deadline_at`), `lib/jobs/wait.ts` (250 ms poll loop), `lib/jobs/http.ts` (node auth = `rejectUnauthorizedOperator` + `X-Node-Id`, `TODO(tee-attestation)`; builder auth = `verifyWeb3SignedRequest`, `TODO(job-admission)`; builder/node views; HTTP code constants).
- Handlers: `api/v1/jobs.ts` (POST, `?wait=<0..25>`, 202 `{jobId,state,created}` or 200 `{job}`), `api/v1/jobs/[id].ts` (GET, 404 for any signer but the submitting builder), `api/v1/jobs/claim.ts` (sweep then claim; 200 or 204), `api/v1/jobs/[id]/{heartbeat,complete,fail}.ts` (409 `LEASE_LOST` when fenced). `vercel.json`: six rewrites (`/v1/jobs/claim` before `/v1/jobs/:id`), `api/v1/jobs.ts` `maxDuration: 30`.
- Tests: `tests/jobs-repository-postgres.test.ts` (real Postgres, gated by `JOBS_POSTGRES_URL`/`F06_POSTGRES_URL`, throwaway schema, runs 0052: idempotency, 16 concurrent claimers over 5 jobs get 5 distinct winners, fencing, lapsed-lease recovery with attempt 2, MAX_ATTEMPTS expiry, deadline expiry), `tests/jobs-handlers.test.ts` (11 handler tests over a mocked repository: 401/202/200-inline/202-timeout/400 wait cap, 404 stranger, X-Node-Id, 204, work order excludes result side, 409).
- `scripts/jobs-worker.ts` (fake node: claim every 1 s, `WORK_MS` 200, heartbeat every TTL/3 on long jobs, 4 KB random result + sha-256), `load-tests/jobs-load.ts` (open-loop N/min for D s, wait fraction, per-job intervals, p50/p95 JSON; tsx, since k6 is not installed here and the driver needs viem signing).
- personal-server-ts `spikes/jobs/`: `dev-server.ts` (vercel.json-driven stand-in for `vercel dev`), `run-matrix.sh`, `recovery.mts`, `conn-sampler.mts`, `start-pg.mjs`, `results/*.json` (raw driver output), `results/matrix.log`, `results/recovery.log`.

### Environment (why the numbers are local-only)

No Docker, no Postgres, no k6 on this machine; `vercel dev` is logged in but the checkout is not linked to a project and linking touches the account, so it was not run. Postgres 18.4 (`embedded-postgres` in the scratchpad, `timezone=UTC`, port 5433, same URL as `scripts/dev-up.sh`), schema via `NEON_URL=... USE_LOCAL_DB=1 npm run db:push`. Gateway = `spikes/jobs/dev-server.ts`: one Node process routing `vercel.json` rewrites to the real handlers with the `@vercel/node` request shape (parsed body, path params in `req.query`, replayable body stream). Consequences: one shared `pg` pool (so connection counts are meaningless for Neon), no cold starts, no per-invocation billing. Wall clock on Postgres and driver is the same machine; `submit -> claim` and `claim -> complete` are server timestamps (`claimed_at - created_at`, `completed_at - claimed_at`), `submit -> result` is the client clock.

### Numbers

180 s per run, 50% of submissions as `?wait=25` clients, worker `WORK_MS=200`, claim poll 1 s. Every run: 0 errors, every job `completed`, every wait client answered inline (inline fraction 1.0; 0 x 202 for wait clients). Command per run (from the worktree, Gateway on :3000, N workers started as `GATEWAY_URL=http://localhost:3000 NODE_ID=w<i> npx tsx scripts/jobs-worker.ts`):
`npx tsx load-tests/jobs-load.ts --rate <R> --duration 180 --wait-fraction 0.5 --out spikes/jobs/results/jobs-w<W>-r<R>.json` (driver: `spikes/jobs/run-matrix.sh`).

| workers | jobs/min | n   | submit->claim p50 / p95 ms | claim->complete p50 / p95 ms | submit->result wait p50 / p95 ms (n) | submit->result poll p50 / p95 ms (n) | submit HTTP 202 p50 / p95 ms | inline | max pg conns |
| ------- | -------- | --- | -------------------------- | ---------------------------- | ------------------------------------ | ------------------------------------ | ---------------------------- | ------ | ------------ |
| 1       | 1        | 3   | 867 / 967                  | 218 / 219                    | 288 / 288 (1)                        | 1613 / 1632 (2)                      | 11 / 36                      | 1/1    | 2            |
| 1       | 10       | 30  | 539 / 968                  | 208 / 227                    | 1054 / 1312 (9)                      | 1030 / 1541 (21)                     | 9 / 41                       | 9/9    | 2            |
| 1       | 50       | 150 | 490 / 976                  | 210 / 223                    | 801 / 1311 (76)                      | 1054 / 1582 (74)                     | 18 / 32                      | 76/76  | 2            |
| 3       | 1        | 3   | 562 / 863                  | 212 / 225                    | none drawn (0)                       | 1057 / 1581 (3)                      | 23 / 40                      | n/a    | 3            |
| 3       | 10       | 30  | 343 / 858                  | 210 / 224                    | 581 / 1311 (13)                      | 1031 / 1565 (17)                     | 16 / 47                      | 13/13  | 3            |
| 3       | 50       | 150 | 93 / 220                   | 207 / 219                    | 517 / 534 (66)                       | 533 / 551 (84)                       | 12 / 20                      | 66/66  | 3            |

Reading: `submit -> claim` is the worker's 1 s claim poll, not the database (uniform 0..1 s with one worker, p50 ~500 ms; three workers polling out of phase bring p50 to 93 ms at 50/min). `claim -> complete` = 200 ms fake work + ~10 ms for the complete call. `submit -> result` for pollers is quantised by the driver's 500 ms status poll. Queue and handlers add ~10-20 ms per call locally (`submit HTTP 202`). Postgres connections: 2-3 (one pool), see Environment. Function-seconds per job cannot be measured without Vercel; the structural fact is that at 3 workers the claim poll alone is 180 invocations/min (259k/day) regardless of load, each doing the lease sweep UPDATE plus the claim UPDATE, which on Vercel + Neon is the dominant cost at low load.

Other runs: `JOBS_POSTGRES_URL=postgres://gateway:gateway@localhost:5433/gateway npx vitest run tests/jobs-repository-postgres.test.ts` 7/7 pass (0.6 s); `npx vitest run tests/jobs-handlers.test.ts` 11/11; full suite `JOBS_POSTGRES_URL=... npm test` 67 files / 1672 tests pass, 5 files skipped (other Postgres-gated suites); `npm run typecheck`, `npm run lint`, `npm run format:check` pass.

### Claim recovery (worker killed mid-job)

Command: `REPO=$PWD npx tsx spikes/jobs/recovery.mts` (Gateway on :3000). Worker `victim` with `WORK_MS=120000 CLAIM_TTL_SECONDS=15` (heartbeat every 5 s) claims the job (state `running`, attempt 1); after 7.5 s the whole process group gets SIGKILL; worker `rescuer` (`WORK_MS=200`) starts polling. Result (`results/recovery.log`): lease lapsed 15 s after the last heartbeat, the rescuer's next claim swept it back to `queued` and claimed it; job `completed`, `attempt 2`, `claimed_by rescuer`, kill -> complete **13.8 s** (= remaining lease ~13 s + 1 s poll + 0.2 s work). A late `complete` from the victim's node id would get 409 `LEASE_LOST` (covered by the Postgres test). Gotcha found on the way: `tsx` forks a child Node process, so SIGKILL on the tsx parent alone leaves the worker running and it finished the job itself; the script kills the process group.

### Kill criteria

Not tripped locally: p95 submit -> claim at 50 jobs/min with three workers = 220 ms (criterion: > 2 s), no connection exhaustion (2-3 connections). **The criterion is defined for Vercel + Neon and cannot be passed or tripped by these numbers**: one warm Node process and a local pg pool remove cold starts, per-invocation connection setup, Neon WebSocket latency and the 250 ms wait-poll cost that the criterion is about. Status: **pending the preview run below**.

### Consequences for the architecture doc

- Job model: the row shape held; add `claimed_at`, `completed_at`, `deadline_at`, `failure_reason` (needed for the measured intervals and the deadline rule). `result_ciphertext` as base64 text is fine to 1 MB; the R2 handle path remains v1.1.
- Job model, "Runtimes pull": the 1 s claim poll sets the submit -> claim floor (p50 = half the poll interval per idle worker) and is the dominant invocation count on Vercel (60/min/worker even when idle). Decide before launch: either a long-poll claim (`POST /v1/jobs/claim?wait=25`, same loop as the builder fast tier) or adaptive backoff when 204. Either drops idle invocations by ~25x and makes submit -> claim sub-second at p95 with one worker.
- Job model, "`FOR UPDATE SKIP LOCKED`": the claim is one statement (`UPDATE ... WHERE id IN (SELECT ... FOR UPDATE SKIP LOCKED) RETURNING`), so it needs no explicit transaction and one round trip to Neon; 16 concurrent claimers over 5 jobs produced 5 distinct winners in the Postgres test.
- Job model, lease: `claim_expires_at` + `claimed_by` fencing + sweep-before-claim recovers a dead node in `TTL - time since last heartbeat + poll interval` with no cron; the `cron: expire claims` row in the data-gateway ownership table becomes optional (belt and braces), not required.
- Workflows / Infrastructure: the `?wait=25` tier returned inline for 100% of wait clients at every load, because the fake node finishes in ~1.3 s; the inline fraction is a property of node latency (Spike 3 cold start + hydration), not of the queue. Function `maxDuration` for `api/v1/jobs.ts` must be >= 30 s (set); on the Hobby plan that is at the 60 s cap, fine.
- Trust: `authenticateBuilder` records the signer as `builder_address` and nothing else is checked (`TODO(job-admission)`: builder registration, grant validity, rate limit). Node auth is the operator secret + `X-Node-Id` (`TODO(tee-attestation)`). The Gateway never decodes either ciphertext (size is measured from the base64, hash is node-reported); keep that as an invariant in "Invariants across workflows".
- Decision 20 trigger: undecided until the preview numbers exist.

### Preview deployment (operator, not run)

```bash
# Neon branch + schema (Neon URL and Vercel project come from the operator's environment; never commit them)
neonctl branches create --project-id "$NEON_PROJECT_ID" --name spike-jobs --parent main
export NEON_URL="$(neonctl connection-string spike-jobs --project-id "$NEON_PROJECT_ID" --pooled)"
psql "$NEON_URL" -v ON_ERROR_STOP=1 -f db/migrations/0052_jobs.sql     # idempotent; or NEON_URL=... npm run db:push

# Vercel preview from the spike branch (worktree ../data-gateway-spike-jobs)
vercel link --yes --project "$VERCEL_PROJECT"                            # once per worktree
vercel env add NEON_URL preview spike/jobs <<<"$NEON_URL"                # branch-scoped preview var
vercel env add CRON_SECRET preview spike/jobs <<<"$(openssl rand -hex 32)"   # node routes require it on preview
PREVIEW_URL="$(vercel deploy --yes 2>/dev/null)"                         # prints https://data-gateway-<hash>-<team>.vercel.app
# if the team has Deployment Protection on, add `-H "x-vercel-protection-bypass: $BYPASS"` to the curl/fetch
# calls below or disable it for this deployment; the load driver and worker do not set that header yet.

# Three workers, then the same matrix against the preview (the signed audience is the preview origin)
export GATEWAY_URL="$PREVIEW_URL" CRON_SECRET="<the value added above>"
for i in 1 2 3; do NODE_ID=w$i npx tsx scripts/jobs-worker.ts > worker-$i.log 2>&1 & done
for R in 1 10 50; do npx tsx load-tests/jobs-load.ts --rate $R --duration 600 --wait-fraction 0.5 --out load-tests/results/preview-w3-r$R.json; done
# Neon connections during the 50/min run (Neon console > Monitoring, or):
psql "$NEON_URL" -c "select count(*) from pg_stat_activity where datname = current_database()"
# Function duration: Vercel dashboard > Observability > Functions, filter path /api/v1/jobs and /api/v1/jobs/claim, 50/min window.
# Kill test: NODE_ID=victim WORK_MS=120000 CLAIM_TTL_SECONDS=15 npx tsx scripts/jobs-worker.ts & then `kill -9` its node child and start a rescuer.

# Tear down
pkill -f jobs-worker.ts; vercel remove "$PREVIEW_URL" --yes; neonctl branches delete spike-jobs --project-id "$NEON_PROJECT_ID"
```

Kill criterion to apply to the preview numbers: p95 submit -> claim > 2 s at 50 jobs/min with three workers, or Neon connections exhausted. Expect submit -> claim to stay poll-dominated (~0.5 s p50 per idle worker) plus Neon round trips; the number to watch is the `submit HTTP 202` column (pure gateway + Neon cost per call) and the claim route's function seconds.
