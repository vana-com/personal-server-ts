# mainnet-prod1 — step 3 staging plan

Companion to `260914-mainnet-tee-plan.md` §4. Step 1 (code + tests) is on `main`.
**Nothing here has been run.** Every command below is a Phala or Doppler mutation and needs
Kahtaf's go per step. Node choice is settled: **prod9, node id 18** (`260915 day/mainnet-node-options.md`).

## 0. What the manifest already pins

`deploy/dstack/fleets/mainnet-prod1.json` carries `provisioning` (nodeId 18 / prod9 / US-WEST-1,
`kms: phala`, `image: dstack-0.5.9-bd369a8c` — the image the Moksha fleet is measured against, and
≤ the `dstack-0.5.10` prod9 offers), `CHAIN_ID=1480`, `GATEWAY_URL=https://dp-rpc.vana.org`,
`MCP_PUBLIC_ORIGIN=https://mcp.vana.org`, `MCP_APPROVAL_URL=https://app.vana.org/personal-server`,
its own `mainnet-prod1-*` secretRef names, and a net-new controller
(`MCP_MIGRATION_REQUIRED=0`, `MCP_STATE_REQUIRED=0` — `scripts/tee/README.md` steps 5 and 10).

A plain render exits **1** and names 22 placeholders: 21 values that only exist once the CVMs are
measured, plus `operatorPublicKeySpkiBase64`, which needs the mainnet operator key minted (step 1
below). Nothing can be signed until both are filled.

```sh
python3 scripts/tee/render-fleet.py --manifest deploy/dstack/fleets/mainnet-prod1.json \
  --images-env ci-docker-<head7>/images.env --out rendered-mainnet/   # exit 1 today
```

## 1. Secrets to mint first, and where

Login keychain (`security add-generic-password -s <item> -a <account> -w`), read inline per command,
never written to disk:

| Item                                           | What                                                                                                               |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `mainnet-prod1-operator`                       | ed25519 signing key for fleet configs. Its SPKI fills `operatorPublicKeySpkiBase64`. **New key — never Moksha's.** |
| `mainnet-prod1-fleet-gateway-token`            | Gateway → controller                                                                                               |
| `mainnet-prod1-fleet-controller-gateway-token` | controller → Gateway                                                                                               |
| `mainnet-prod1-fleet-controller-admin-token`   | admin listener bearer                                                                                              |
| `mainnet-prod1-worker-1-agent-secret`          | worker agent                                                                                                       |
| `mainnet-prod1-worker-1-node-secret`           | worker node secret                                                                                                 |
| `mainnet-prod1-agent-bypass`                   | only if the Gateway sits behind Vercel protection; `dp-rpc.vana.org` is public, so expect to drop it               |

Doppler `dp-rpc/prd`, net-new (Doppler is the source of truth; never write Vercel env directly):
`ENCLAVE_ROLLOUT_POLICY` (chain 1480, `defaultMode: legacy`, empty `owners`), `FLEET_ENABLED`,
`FLEET_CONTROLLER_URL`, `FLEET_CONTROLLER_ADMIN_URL`, `FLEET_CONTROLLER_ADMIN_TOKEN`,
`FLEET_CONTROLLER_GATEWAY_TOKEN`, `FLEET_GATEWAY_TOKEN`, `FLEET_RECOVERY_TOKEN`,
`ENCLAVE_KMS_ROOT_PUBKEY`, `ENCLAVE_APP_ID_ALLOWLIST`, `OPERATOR_SECRET`,
`STORAGE_API_URL=https://storage.vana.org`.

**Blocker before any of it:** `dp-rpc/prd` is still missing `CHAIN_ID`, `RPC_URL`, `NEON_URL`,
`GATEWAY_PUBLIC_ORIGIN` and `CRON_SECRET`, which exist only as Vercel-only values
(`260914-env-audit-gateway.md`). Re-add those **unchanged** first, or a resync blanks the live
legacy mainnet deployment.

Also blocking, outside this repo: `wrangler secret put ACCOUNT_AUTH_PRIVATE_JWK --env production` on
`vana-storage` (currently empty), and the MCP DNS pair below — no Cloudflare credential exists on
this machine.

| record                                 | value                              |
| -------------------------------------- | ---------------------------------- |
| CNAME `mcp.vana.org`                   | `_.dstack-pha-prod9.phala.network` |
| TXT `_dstack-app-address.mcp.vana.org` | `<controller-app-id>:8788`         |

Until both resolve, drop `mcp-tls` and serve MCP on
`https://<app-id>-8788.dstack-pha-prod9.phala.network`; `DNS_SETUP_MODE=wait` otherwise blocks the
CVM for 3600 s.

## 2. Exact sequence (level A, `scripts/tee/README.md`)

| #   | Command                                                                                                                                                                                                                                                                                                                         | Go                    | Est.                 |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- | -------------------- |
| 1   | `phala api /kms/phala/next_app_id -f counts=1` — once per role, keep each `{app_id, nonce}`                                                                                                                                                                                                                                     | per call              | 1 min                |
| 2   | `phala deploy -n mainnet-personal-server-<role> -c <compose> --custom-app-id <id> --nonce <n> --image dstack-0.5.9-bd369a8c --instance-type tdx.small\|tdx.medium --disk-size 20G --node-id 18 --no-dev-os --kms phala -e <dummy-env> --json` — `FLEET_SIGNED_CONFIG={}` in a 0600 env file so the first boot opens no listener | **per CVM**           | 3–5 min              |
| 3   | `phala api /cvms/<uuid>` until `status: running` (`--wait` returns when the record exists, not the CVM)                                                                                                                                                                                                                         | none                  | 1–2 min              |
| 4   | `python3 scripts/tee/harvest-identity.py --nodes nodes.json > identities.json` — instance id, compose hash, mr-kms, key-provider SPKI, MRTD/RTMRs all come from the event log                                                                                                                                                   | none                  | 1 min                |
| 5   | Fill the 22 placeholders from `identities.json` + the operator SPKI, then `render-fleet.py --stage --settle`                                                                                                                                                                                                                    | **per node**          | 5–10 min             |
| 6   | `node scripts/tee/sign-fleet.cjs --apply` per node → `phala envs update <uuid> -e <sealed.env> --json`; the restart is what boots the signed config                                                                                                                                                                             | **per node**          | 3 min                |
| 7   | Health: worker `GET :8787/agent/v1/health`, controller `POST :8791/fleet/v1/status`, each with its bearer — all 200                                                                                                                                                                                                             | none                  | 78–87 s after step 6 |
| 8   | **First deploy only:** `POST :8791/fleet/v1/activate`                                                                                                                                                                                                                                                                           | **go**                | 1 min                |
| 9   | Per worker vs the Gateway: `POST /v1/tee-nodes`, wait for a heartbeat carrying the staged compose hash, `POST /v1/tee-nodes/<node-id>/admit`                                                                                                                                                                                    | **per worker**        | 2 min                |
| 10  | Harvest `kmsRootPubkey` + worker `appId` → fill `MAINNET_ANCHOR` in vana-sdk `identity.ts`, publish, repin                                                                                                                                                                                                                      | Kahtaf (version bump) | 0.5 d + wait         |
| 11  | Re-sign the controller with `MCP_STATE_REQUIRED=1` **only after** a real owner MCP connection has written sealed state (a DCR does not)                                                                                                                                                                                         | **go**                | 3 min                |

Reference: zero → 3 admitted CVMs, MCP ingress and Gateway rows in **13 min** on prod9, 2026-09-11.

## 3. Rollback

- Before step 8 nothing serves: every CVM is fail-closed on `FLEET_SIGNED_CONFIG={}` or a signed
  config whose controller has never been activated. `scripts/tee/destroy.sh <uuid>` is a clean undo.
- After step 9, per worker: Gateway `POST /v1/tee-nodes/<node-id>/drain` (one-way to removed), then
  re-admit only after a fresh heartbeat.
- The legacy mainnet path is untouched throughout: `ENCLAVE_ROLLOUT_POLICY` for 1480 stays
  `defaultMode: legacy` with an empty `owners`, so no owner reaches the fleet until a cohort is
  added. Emptying `owners` is the whole-slice rollback and needs no CVM change.
- Do **not** flip `app.vana.org` / `account.vana.org` / `dp-rpc.vana.org` aliases at any point.

## 4. Still open for Kahtaf

- Worker count: the manifest templates one `tdx.medium` worker at capacity 4 (Moksha runs four).
- `NEXT_PUBLIC_PS_MAINNET_DISABLED` is `false` in Doppler dev **and** prd today, so Web already
  offers mainnet with no fleet behind it. Set it `true`, or populate the 1480 allowlist, before
  step 9.
- Confirm the prod Privy policy already allows `owner_ingestion.add_data.v1` / `.storage.v1` /
  `.gateway.v1`; a policy change needs its own go.
- Peer policies still carry no chain discriminator. The renderer now refuses a manifest mixing
  chains or KMS roots, but binding `chainId` into `FleetPeerIdentity` would change the signed config
  format and require re-signing the live Moksha fleet. Worth its own PR before a second chain's
  fleet ever shares an operator.
