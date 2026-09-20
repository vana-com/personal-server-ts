# Lorebook #1 merge + enclave read proof — 2026-09-14

Hosts: `app-dev.vana.org` (61), `lorebook-opendatalabs.vercel.app` (18),
`dp-rpc.moksha.vana.org` (7), amplitude (3). **Zero preview/mainnet hosts.**

## Merge and deploy

|             |                                                                                                                                                    |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| PR          | vana-com/lorebook#1 `feat(vana): read approved data through enclave jobs`, MERGEABLE/CLEAN at `f200964`, Vercel SUCCESS                            |
| Merge       | squash (head-pinned) → `main` **e2af0a1**                                                                                                          |
| Prod deploy | `dpl_9gEP7qpFqXykri4234bgVP3fN4EC` (lorebook-qawnwxddw), Ready 25 s, aliased `lorebook-opendatalabs.vercel.app`; Vercel check on `e2af0a1` success |
| Rollback    | `dpl_7rbuBShejZacsGEBR4WiD7XgH5of` (lorebook-211qy2ksb)                                                                                            |

**Env — no change needed, re-verified independently.** Every name the PR reads is
already in production (`VANA_READ_MODE=enclave`, `VANA_GATEWAY_URL`,
`VANA_DEFAULT_NETWORK/ENV`, `VANA_ACCESS_REQUEST_BASE_URL`,
`VANA_APPROVAL_APP_BASE_URL`, `APP_URL`, `VANA_PRIVATE_KEY`, KV/Redis).
`VANA_NETWORKS`/`VANA_ENVS` are TS constants, not env; `VANA_PRIVATE_KEY` is only
newly referenced by the local CLI `scripts/enclave-read.ts`.

## Read proof (owner mk-a, DCR `dcr_15692bd71b7b46a6a55ed49b0d3d9323`, one run, zero retries)

| Row              | Result                                                                       | Evidence                                                                                                                                            |
| ---------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| job created      | **PASS** job `0031e12e-cc79-42b6-80de-725cc63ef10a`, scope `spotify.profile` | submitted 22:29:26.7Z; resume record `lorebook:delivery:v1:enclave-job:<dcr>`                                                                       |
| job executed     | **PASS** `state: completed`                                                  | same record, well inside its 22:39:26Z deadline                                                                                                     |
| result decrypted | **PASS**                                                                     | `GET /api/vana/read → 200` (data, not 202/state); page renders `kahtaf`, 19 following, portrait line — `out/lorebook-read/grant-read/01-result.png` |
| ACK sent         | **PASS**                                                                     | `readThenAcknowledge` acks on every success; no `[vana/read] acknowledgeRead failed` in the deploy's runtime log                                    |
| hosts            | **PASS** clean                                                               | `out/lorebook-read/hosts.json`                                                                                                                      |

Timings (fleet prewarmed during consent, `POST /v1/prewarm 202` at 22:29:23.0Z):
read starts 22:29:25.8Z → job submitted +0.9 s → completed and rendered inside the
single 60 s read call, last call 22:29:35.8Z. **Warm only — no second read, so no
cold/warm pair.**

The prior blocker is closed: `status` now calls
`assertGrantReadReady(status, { requirePersonalServerUrl: !shouldUseEnclaveRead(status) })`,
so the enclave route no longer trips `DIRECT_ACCESS_NOT_APPROVED`.

## Leftovers

- Gateway exposes no owner-public job read: `GET /v1/jobs` → 405, `GET /v1/jobs/<id>`
  → 401. Job state came from Lorebook's own resume record instead; I did not reuse
  Lorebook's bearer.
- Two receipts the brief cited never existed in the repo:
  `260914-lorebook-pr1-prep.md`, `260914-fleet-roll.md`. The env claim attributed to
  the prep receipt is re-verified above from source; the fleet-roll state is unverified.
- Failed DCR `dcr_a95eb9bf…` from the pre-merge build was left consumed, not retried.
- Driver `scratchpad/lorebook-consent.mjs` run as `PHASE=lorebook-read`; outputs under
  `…/launch-handoff-260914/browser-e2e/out/lorebook-read/{results,network,hosts}.json`.
