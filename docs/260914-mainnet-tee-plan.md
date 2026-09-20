# Mainnet (1480) TEE slice — plan

Read-only planning. Companion to action 4 of `260914-claude-fable-launch-handoff.md` / runbook's
"Separate actual-mainnet TEE capability and smoke." Does not block mainnet-off deploy or Moksha launch.

## 1. Code changes

**Gateway — keep per-deployment CHAIN_ID (recommended), don't refactor to chain-keyed single deployment.**
`CHAIN_ID` is read directly from `process.env` at 8+ call sites: `data-gateway-fold`
`api/v1/identity.ts:32`, `api/v1/jobs.ts:194`, `api/v1/prewarm.ts:166`, `api/v1/grants.ts:522`,
`lib/settle.ts:1428`, `lib/deposit-authorization.ts:126`, `lib/escrow.ts:65,92`, `lib/eip712.ts:39`.
Proven in `260914-gateway-preview-proof.md` row 9: a 14800-configured deployment 400s
`CHAIN_MISMATCH` on `chainId:1480` before admission — one deployment cannot serve both chains.
Existing split already does this: `dp-rpc` = 1480 (live, legacy), `dp-rpc-moksha` = 14800. Reuse
`dp-rpc` for mainnet TEE; add TEE env additively, don't touch its existing legacy vars.

**Account ingestion — chain-key it, don't dual-chain one process.** `unity-surfaces-987-sync`
`apps/account/src/lib/signing/owner-ingestion.ts`: `INGESTION_CHAIN_ID = 14_800` (line 30),
storage prefix hardcoded `/v1/chains/14800/blobs/` (line 80, doesn't even use the const),
`body.chainId !== INGESTION_CHAIN_ID` rejects everything else (line 248-249), outbound
`chainId: 14_800` (line 359). Account already deploys one-chain-per-project
(`ACCOUNT_VANA_CHAIN_ID`: dev=14800, prd=1480 — `260914-env-audit-unity.md` §2), so make
`INGESTION_CHAIN_ID` read from that same env var instead of hardcoding — small, low-risk fix,
matches Gateway's per-deployment pattern rather than adding branching logic.

**Fleet chain guard — three sites, worker path already supports both chains.**
`personal-server-launch` `packages/enclave/src/agent/bootstrap.ts:41-54` already types
`SupportedChainId = 1480 | 14800`. Three call sites still hard-block 1480:
`central/bootstrap.ts:92-93` (`if (chainId !== 14800) throw`),
`fleet/security-config.ts:180` (`env.CHAIN_ID !== "14800"`),
`fleet/worker-runtime.ts:53-54` (`if (sandbox.chainId !== 14800) throw`). Widen all three to accept
1480 alongside 14800, with a new mainnet fleet manifest (`deploy/dstack/fleets/mainnet-prod1.json`,
doesn't exist yet) — own `CHAIN_ID=1480`, own secretRefs, own KMS root/app ids (do not reuse Moksha's).

**SDK anchors — sequenced after the fleet exists, not before.** `vana-sdk-launch`
`packages/vana-sdk/src/protocol/identity.ts:189`: `[VANA_MAINNET_CHAIN_ID]: emptyAnchor()`, fails
closed by design (`kmsRootPubkey==="0x"`). Can't fill with real values until the mainnet CVM is
staged and measured — harvest `kmsRootPubkey`/`appId` from the live controller/worker first, then
patch, publish, and repoint consumers (same unreleased-major-bump caution as `260914-sdk-release-path.md`).

## 2. Infra

- **Fleet**: new CVMs, new app ids, fresh KMS root (do not derive mainnet trust from Moksha's).
  Node choice (reuse the Phala prod5 host or a dedicated one) is Kahtaf's call — isolating mainnet
  KMS root argues for a separate node.
- **Doppler `dp-rpc/prd`**: currently missing `CHAIN_ID`, `RPC_URL`, `NEON_URL`,
  `GATEWAY_PUBLIC_ORIGIN`, `CRON_SECRET` entirely — they exist only as orphaned Vercel-only values
  (`260914-env-audit-gateway.md` §1/§GAPS-4). Re-add those _unchanged_ before adding anything new,
  or a resync could blank live legacy config. Net-new: `ENCLAVE_ROLLOUT_POLICY` (1480 cohort),
  `FLEET_ENABLED`/`FLEET_CONTROLLER_URL`/`_ADMIN_URL`/`_ADMIN_TOKEN`/`_GATEWAY_TOKEN`/`_RECOVERY_TOKEN`
  (mainnet fleet's own), `ENCLAVE_KMS_ROOT_PUBKEY`, `ENCLAVE_APP_ID_ALLOWLIST`, `OPERATOR_SECRET`,
  `STORAGE_API_URL=https://storage.vana.org`.
- **Storage prod `ACCOUNT_AUTH_PRIVATE_JWK`**: `wrangler secret list --env production` on
  `vana-storage` returns **empty** despite `ACCOUNT_AUTH_CLIENT_ID=vana-storage` implying
  client-assertion auth is expected there (`260914-env-audit-ps-storage.md` §b). Blocking gap —
  `wrangler secret put ACCOUNT_AUTH_PRIVATE_JWK --env production` required before any mainnet
  owner-ingestion storage claim can verify.
- **MCP DNS for mainnet**: needs its own `MCP_PUBLIC_ORIGIN` (distinct from `mcp-dev.vana.org`) and
  a `_dstack-app-address.<host>` TXT record to the new controller instance id. No Cloudflare
  credential exists on this machine (`260914-fleet-roll.md` open item 1) — Kahtaf must run this step.
- **Privy prod policies**: dev/prd already use separate Privy apps (`260914-env-audit-unity.md` §2).
  Confirm the prod Privy policy already allows the `constrained-silent-signing` intents
  (`owner_ingestion.add_data.v1`, `.storage.v1`, `.gateway.v1`) — if not, that's a policy change
  requiring targeted Kahtaf go per the runbook's pause boundaries, not something to assume.

## 3. Proof (mirrors `260914-gateway-preview-proof.md`, run against real `dp-rpc` + mainnet fleet)

1. Selected cohort: `ENCLAVE_ROLLOUT_POLICY` chain `1480` `{"defaultMode":"legacy","owners":{"<wallet>":"tee"}}`.
2. Selected wallet: setup → register → cold read → warm read → MCP, against `dp-rpc.vana.org` +
   `storage.vana.org` + the new mainnet fleet.
3. Unselected owner / wrong chain: prepare 200 → register `409 rollout_setup_paused`; direct
   `chainId:14800` against the mainnet deployment → `400 CHAIN_MISMATCH` (this time real, not blocked
   like preview row 9 — a genuine 1480 Gateway now exists).
4. Off→on→off: existing legacy bindings survive; new enrollment follows policy version.
5. Explicit disable: `DELETE /v1/servers` on the test owner → next `register` → `409 IDENTITY_RETIRED`.
6. Return cohort to empty/off after smoke unless Kahtaf approves the next cohort.

## 4. Ordered steps, approvals, estimates

| #   | Step                                                                                                     | Approval                                       | Est.           |
| --- | -------------------------------------------------------------------------------------------------------- | ---------------------------------------------- | -------------- |
| 1   | Widen 3 fleet chain guards; chain-key owner-ingestion; SDK anchor plumbing (no real values)              | none — code + tests                            | 0.5–1 d        |
| 2   | Provision: node/app-id decision, Doppler `dp-rpc/prd` fleet vars, Storage prod secret, MCP DNS host name | **Kahtaf, before any provisioning command**    | unbounded wait |
| 3   | Render/stage new mainnet CVMs                                                                            | go per node stage                              | ~20–30 min     |
| 4   | Sign + apply (starts CVMs)                                                                               | go per apply                                   | ~15 min        |
| 5   | Gateway-rotate each worker against `dp-rpc`                                                              | go per worker                                  | ~15 min        |
| 6   | Harvest real anchors → patch SDK → publish/pin                                                           | Kahtaf sign-off (merge strategy, version bump) | 0.5 d + wait   |
| 7   | Deploy `dp-rpc` w/ new env; Account/PS w/ guard removed + cohort policy                                  | targeted go (canonical host/DB, Privy check)   | 0.5 d          |
| 8   | Run proof matrix (§3), capture receipts                                                                  | none beyond step 2 wallet/target authorization | 0.5 d          |
| 9   | Return cohort to empty; propose next cohort                                                              | Kahtaf decides next cohort/stop condition      | —              |

Total: 1–3 engineer-days code+proof (matches handoff estimate), plus unbounded approval/provisioning time.

## 5. Risks to existing mainnet Lite users

- `dp-rpc/prd` Doppler is missing core connectivity vars today (§2) — any blind resync before
  capturing current Vercel-only values risks blanking the _live_ legacy deployment's config.
- Owner-ingestion's hardcoded `14800` is an accidental safety rail keeping prod Account from ever
  attempting mainnet ingestion. Removing it without explicit prod `ACCOUNT_OWNER_INGESTION_STORAGE_AUD`
  /`_GATEWAY_AUD` values risks a misconfigured prod deploy signing claims against dev hosts
  (`storage-dev.vana.org`, `dp-rpc.moksha.vana.org` are the code defaults).
  Set both explicitly in prd, not by default fallback.
- Loosening the fleet's `CHAIN_ID !== 14800` guards is a config-integrity risk, not just a code
  change: a misrouted `CHAIN_ID` could point a mainnet-configured controller/worker at the Moksha
  Gateway or vice versa. Manifest + Doppler project must stay strictly separated per chain.
- `NEXT_PUBLIC_PS_MAINNET_DISABLED` is `false` in both Doppler dev and prd today
  (`260914-env-audit-unity.md` §4) — Web already exposes mainnet as selectable with no working fleet.
  Pre-existing, independent of this plan, but this slice must not ship before that's set `true` /
  the rollout policy allowlist is populated, or unselected mainnet owners could reach TEE setup UI.
- No change to existing mainnet identity/DCR/MCP routing: this slice only adds a new TEE path for
  an explicit cohort. Legacy stays default for everyone else — verify with an "off, new legacy
  owner" proof row before any mainnet TEE code ships, per the runbook's acceptance matrix.
