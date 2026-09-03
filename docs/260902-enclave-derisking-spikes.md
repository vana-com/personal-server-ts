# Enclave derisking spikes

Status: execution plan for subagents  
Date: 2026-09-02  
Parent: `260901-personal-server-gateway-enclave-architecture.md` (decisions 19 to 21, Wake experiment)

## Purpose

Prove or kill the four assumptions the architecture rests on before any product code is written. Output is numbers and facts in `docs/260902-enclave-spike-results.md`. Code is reusable: it lands in its target package as the first real module, with tests against fakes, and the spike is a thin script over it.

## Ground rules

- Work in git worktrees on branch `spike/<name>` so the main checkouts stay untouched: `personal-server-ts` → `../personal-server-ts-spike-<name>`, `data-gateway` → `../data-gateway-spike-<name>`. Commit on the spike branch; never push without asking.
- Reusable placement: dstack key agent and sealing → `personal-server-ts/packages/enclave/src/`; sandbox launcher and compose → `packages/enclave/` and `deploy/dstack/`; jobs table and handlers → `data-gateway/api/v1/jobs/`, `lib/jobs/`; shared job types → `vana-sdk/packages/vana-sdk/src/protocol/jobs.ts` (copy locally if the SDK worktree is out of scope, mark `TODO(move-to-sdk)`). Spike scripts live in `spikes/<name>/` and only call those modules.
- Follow the repo's existing patterns (Drizzle migrations, `VercelRequest` handlers, vitest, biome or eslint as present). Code must pass the repo's typecheck and lint.
- Abstract the vendor: a `DstackClient` port with a fake implementation for tests; the real one is the only file that imports the dstack SDK.
- Never touch production: no `dp-rpc.vana.org`, no mainnet, no real user data. Gateway runs locally (`data-gateway/scripts/dev-up.sh`, `USE_LOCAL_DB=1`, `vercel dev`) or on a Vercel preview with a Neon branch.
- TEE work runs on Phala Cloud in the existing workspace, dstack OS 0.5.8 or newer. Name every CVM `spike-<name>-<n>`. Destroy CVMs when the spike ends.
- Secrets (Phala API token, Neon URL) come from the operator's environment. Never write them to disk or to this repo.
- Step 0 of every spike is reading upstream docs for the exact API. Do not build on remembered API shapes. Record the doc URL and version in `RESULTS.md`.
- Record every number with the command that produced it. A spike with no numbers is not done.
- Kill criteria are binding. If one trips, stop, write it up, do not work around it.

## Spike 0: dstack facts (done 2026-09-02, see `docs/260902-enclave-spike-results.md`)

Goal: replace assumptions in the architecture doc with cited facts.

Questions, each answered with a doc link:

1. Exact SDK call for deterministic key derivation inside a CVM (`getKey`? path and purpose arguments? socket path?). Package name and version.
2. Is derivation scoped to `app_id`? Is `app_id` stable across compose updates when set explicitly? How is a custom `app_id` set on Phala Cloud (dashboard, CLI flag, on-chain KmsAuth)?
3. Which compose changes are allowed under one `app_id` without KMS re-authorization? Who approves a new `compose_hash`?
4. What does the quote bind: `app_id`, `compose_hash`, OS image, instance id? Where is the KMS root public key published?
5. Does dstack OS 0.5.x allow an alternative container runtime (gVisor `runsc`) or privileged containers? Is nested virtualization exposed?
6. Phala CLI commands to create, update, and destroy a CVM from a compose file with an explicit `app_id`.

Deliverable: `docs/260902-enclave-spike-results.md` section "dstack facts". Update the architecture doc's Identity section with citations.

Kill: none. This spike informs the others.

## Spike 1: deterministic identity (passed 2026-09-02, see `docs/260902-enclave-spike-results.md`)

Goal: the same user wallet on any node with the same `app_id`, and after a compose update.

Steps:

1. Compose with one container running a 40-line Node script: read `app_id` from the dstack info endpoint, derive `users/<testUserPsId>/wallet/ethereum/secp256k1/v1`, print the address, derive `users/<testUserPsId>/secrets/master-signature/v1`, print `sha256(key)`. Also print the quote's `app_id` and `compose_hash`.
2. Deploy as `spike-identity-1` with `phala deploy --custom-app-id <id> --nonce <n>` (pair from `phala api /api/v1/kms/phala/next_app_id?counts=1`) on a dstack 0.5.x image. `phala cvms create` no longer exists. Record outputs.
3. Second CVM under the same `app_id` via `phala cvms replicate <cvm-id> --node-id <id>` (a second `deploy` with the same id is unverified). Record. Compare.
4. Bump an env value only (`phala envs update`, no compose hash change) and then change the compose (`phala deploy --cvm-id <id> -c new.yml`, new compose hash). Record both. Compare.
5. Deploy under a different `app_id`. Confirm the address differs.
6. Destroy all three.

Record: addresses and key hashes per step; whether step 4 required KMS re-authorization; time from `deploy` to first log line; `phala os-images --prod --json` output (which OS versions new deployments get); SDK `getKey(path)` v0 semantics (purpose and algorithm do not enter the KDF) and whether the wallet uses raw bytes or `toViemAccountSecure`.

Kill: step 3 or 4 yields a different address. Then deterministic identity without persisted secrets is not available and the architecture needs sealed wallet files or one CVM per user.

## Spike 2: seal and unseal across nodes (passed 2026-09-02)

Goal: a master signature sealed on node A decrypts a real blob on node B.

Steps:

1. Locally: generate a test wallet, sign `vana-master-key-v1` with the SDK, derive a scope key with `deriveScopeKey`, encrypt a 1 KB JSON blob with the SDK's OpenPGP envelope. Keep signature and ciphertext as fixtures.
2. Node A script: receive the signature over HTTPS (TLS to the CVM is fine for the spike; the attested channel is Spike 4's concern), generate a random content key, encrypt the signature with it (AES-256-GCM, AAD = `testUserPsId`), wrap the content key with the sealing key from Spike 1. Print the envelope.
3. Node B script (second CVM, same `app_id`): take the envelope, unwrap, decrypt the signature, derive the scope key, decrypt the fixture blob, print `sha256(plaintext)`.
4. Negative: tamper AAD to a different `userPsId`; confirm unseal fails.
5. Destroy both.

Record: envelope size; unseal time; confirmation the plaintext hash matches; the negative result.

Kill: node B cannot unwrap with the Spike 1 key. Same consequence as Spike 1.

## Spike 3: sandbox inside the CVM (passed 2026-09-02; hydration and density unverified)

Goal: know how a per-user sandbox can run inside dstack, what it costs, and how fast it starts.

Steps:

1. Spike 0 found dstack OS ships `sysbox-runc` (registered in the guest `daemon.json`), no `runsc`, and no `/dev/kvm`. Preference order: (1) `runtime: sysbox-runc` system container per user; (2) gVisor `runsc` with the `systrap` platform inside a sysbox container; (3) plain container with user namespaces, seccomp, no capabilities, read-only root. First deploy one compose with `runtime: sysbox-runc` and one with `privileged: true` to confirm Phala's control plane accepts them (unverified). Record which level works and why the stronger ones do not.
2. Compose: a "node agent" container holding the dstack socket, plus the chosen sandbox runtime. The agent starts a sandbox running `personal-server-ts` `packages/server` (current image, `CLOUD_MODE=true`, tunnel and dev UI off) with `VANA_MASTER_KEY_SIGNATURE` injected as env. The sandbox must not see `/var/run/dstack.sock` or the Docker socket; prove it with `ls` from inside.
3. Measure cold start: agent `start` to PS `/health` 200. Ten runs.
4. Measure hydration: point the PS at a local Gateway and storage with one owner having 1 MB and 50 MB of encrypted blobs. Time `/health` to sync complete. (Sync is owner-wide today; note the number as the upper bound targeted hydration must beat.)
5. Measure memory per idle sandbox and per active sandbox; derive sandboxes per `tdx.2xlarge`.
6. Tear down a sandbox; confirm tmpfs and SQLite are gone.

Record: isolation level achieved; cold start p50 and p95; hydration times; memory per sandbox; density.

Kill: no isolation stronger than a plain container is possible, and the plain container leaks the dstack socket or host namespaces. Then the shared-CVM design needs one CVM per user, which changes cost and cold start.

## Spike 4: blind job queue on Vercel plus Neon (local run done 2026-09-02, preview run pending; see `docs/260902-enclave-spike-results.md`)

Goal: claim latency, poll cost, and the `?wait` tier under realistic load.

Steps:

1. Branch `data-gateway`. Add a `spike_jobs` table (id, owner, state, claimed_by, claim_expires_at, result_ciphertext, price, payer, payment_state) and three handlers: `POST /v1/spike/jobs` (accepts `?wait=<s>`), `POST /v1/spike/jobs/claim` (`FOR UPDATE SKIP LOCKED`, sets expiry), `POST /v1/spike/jobs/:id/complete`. Copy the drain pattern from `api/v1/settle.ts`. Reuse `lib/operator-auth.ts` for the claim endpoint.
2. Worker script: polls `claim` every 1 s, sleeps 200 ms, posts a fake 4 KB ciphertext result.
3. Deploy to a Vercel preview with a Neon branch.
4. Load with the existing `load-tests/` tooling or k6: 1, 10, 50 jobs per minute for 10 minutes each, one worker, then three workers.
5. Measure submit to claim, claim to complete, submit to result for `?wait=25` clients, and the fraction of `wait` calls that return inline versus `202`.
6. Measure Neon connection count and Vercel function duration at 50 jobs per minute. Expire a claim by killing a worker mid-job; confirm another worker recovers it.

Record: p50 and p95 for each interval at each load; inline fraction; connections; function seconds per job.

Kill: p95 submit to claim above 2 s at 50 jobs per minute with three workers, or Neon connections exhausted. Then decision 20's trigger fires before launch and a dedicated queue is v1 scope.

## Wake experiment (about half a day, after 1 to 4)

Chain the spikes: a job submitted through the Spike 4 Gateway is claimed by the Spike 3 agent on a Phala CVM, which unseals via Spike 2 and returns a result. Measure submit to first byte, p50 and p95, warm and cold, 1 MB and 50 MB owner. Twenty runs each. These four numbers replace every estimate in the architecture doc.

## Results file

`docs/260902-enclave-spike-results.md`, one section per spike, this shape:

```text
## Spike N: <name>
Date, operator, CVM names, dstack OS version, commit
Facts (with links)
Numbers (table: metric, p50, p95, runs, command)
Kill criteria: passed | tripped (what)
Consequence for the architecture doc: section, change
```

## Order and parallelism

Day 1: Spike 0, then Spikes 1 and 4 in parallel. Day 2: Spikes 2 and 3 in parallel. Day 3: wake experiment, update the architecture doc, destroy every CVM.
