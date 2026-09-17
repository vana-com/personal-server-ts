# Codex handoff — 2026-09-17 ~00:00Z (Claude weekly limit imminent)

Orchestrator role moves to Codex (gpt-5.6-sol, medium). Everything below is current as of writing; verify live before acting.

## 0. Ground rules (Kahtaf, binding)

- Author `Kahtaf Alam <kahtaf@gmail.com>`; NO attribution/co-author lines in commits, PR bodies, comments. Style: /Users/kahtaf/.claude/CLAUDE.md (terse, no superlatives, minimal diffs, constants over magic values).
- E2E over unit. Bugs found along the way get FIXED (PR → review → deploy with rollback id), not logged — unless production-money/config (then STOP and ask Kahtaf).
- Production: rollback id recorded before every deploy; ledger check (no migrations unless stated first); never flip app/account/dp-rpc canonical aliases by hand; `mobile.vana.org` stays pinned to `dpl_35RPcRKq2N3WBHUjmJtyC4yZ4Qn8` (vana-mobile Ignored Build Step guard) — re-check after every unity promotion; Doppler is the source of truth for env (Lorebook is the exception: Vercel env only).
- Unity promotions dev→main: the repo workflow auto-opens the PR; post the checklist (commits carried, no migrations/new env reads, rollback ids per alias, base smoke), approve via `gh pr review <n> --approve` (Kahtaf's gh login), `gh pr merge <n> --merge`, wait for prod via Vercel REST, smoke vs base, re-check mobile pin. Receipts: overnight-260915/mainnet/step9/18/22/28/31 show the exact procedure.
- Never poll canonical/production hosts faster than every 2 min from this machine (Vercel Security Checkpoint). Read state via Vercel REST/DB, not curl loops. Never print secrets (keychain by name; Doppler `--plain` into env only).
- Mainnet owners: mn-1 `0x4816087388e8730248e4fef2578ff1e1ec1ab89f` (tee cohort, driver profile browser-e2e/out/profiles/mn-1 + demo/profiles/demo-mcp), legacy throwaway `0xe4dae4ec6cf9968527b505657f216e7bc5f323fd` (profile vc-1). Kahtaf's owner `0xabae1ae71b5a299e3a3ac50d4a3f844ee5ea4766` — never touch. No new mainnet owners without Kahtaf. Driver knob `MAINNET_WRITE_BUDGET` counts production writes.
- Fleet rolls (personal-server-ts scripts/tee/render-fleet.py): sign controller + worker in ONE pass; `--instance-ids` from the Gateway admission record for replicas sharing an app id, but never trust PRE-roll tee_nodes ids — ground truth is the per-uuid staged compose read-back; re-sign the controller whenever a worker pin changes; shape gate: rendered vs live compose may differ only in image/GIT_REF lines. Runbook note: ps #319; manifests: `deploy/dstack/fleets/mainnet-prod1.json` (#320, real values) and `moksha-prod5.json` (#316/#318).
- One deploy owner per Vercel project at a time (three sessions deployed dp-rpc-moksha within 10 min today).

## 1. What is live (mainnet)

- TEE fleet prod9: controller ec5f71b5 (instance b5399a83, compose cfd190f1…), worker-1 ea776e4e (instance 74ab19f7, compose bcad9d9d…); mcp.vana.org 401 (OAuth challenge) = healthy; controller admin needs `-d '{}'`; `/v1/tee-nodes` needs operator bearer (keychain `mainnet-prod1-operator`/`spike-agent`).
- Gateway dp-rpc (main): fee parity live — `JOB_FEES_ENFORCED=true` (dp-rpc/prd, dpl_3fC4tATH; later main merges #142 798f267e re-revocation, #143 0662f50d data-point lane; current prod deployment = latest READY from main). Enclave job reads charged like legacy (10000 USDC.e data_access); MCP reads zero-rated + stamped `unbilled` (documented hole: builder can read free over an approved MCP client).
- Storage (vana-storage main): job-results route + owner-scoped keys (prod dad0c48d); gateway emits owner-scoped result URLs.
- Lorebook production = mainnet default, network-aware endpoints, SDK 4.2.0 (dpl_DkiaPLhn); builder 0x6a9A4cfaC8123f56c182a949b7aeBa9469ac68a4 attributed to Kahtaf's Account (step27) and escrow funded 0.5 USDC.e (now ~0.46, 4 reads used).
- Unity main 4128faf6: MCP approval page (network label, copy, provisioning states), Reconnect-after-takeover fix, single consent "Working" indicator, mobile access-history fix, builder claim flow, MCP connections Web side (guarded until the ingress routes roll), relay defaults. account.vana.org dpl_7pgxGXky (ACCOUNT_OWNER_INGESTION_MCP_AUD set), app.vana.org dpl_ELPKY5uy.
- SDK 4.2.0 (job fee consent), personal-server-ts main: #313 controller 400, #314 receipt signing, #321 ingress owner MCP-connection routes — #321 NOT yet on any fleet (needs next controller roll, Moksha then mainnet).
- Grants: 5033 + 81 wedged mainnet grants backfilled and settled (step19/21).
- Demo videos: v2 finals in overnight-260915/demo/video-{a,b}/final-v2.mp4 (or final.mp4 if v3 not finished), video-c/final.mp4 (legacy path). v3 (16:9 1920x1080 50/50, controller→worker log panes, captions, NO tx segment) was being produced by Codex from briefs/videos-v3-codex.md (+ videos-v3-UPDATE.md); check demo/video-*/final.mp4 mtime and briefs/RESULT.md.

## 2. Open items (priority)

1. Mainnet access-settlement lane backlog (~96k unsettled access payments, growing ~73/min; arrival ~160/min likely the load generator). Fix = data-gateway PR #136 relayer lanes (rebase over #143, same SELECT) + Doppler dp-rpc/prd `SETTLE_RELAYER_LANES`, `SETTLE_FACILITATOR_LANES` (lanes 2–7 funded 1 VANA, facilitator role set). Kahtaf: ON HOLD — ask before doing. Receipt step35 (Codex diagnosis in /Users/kahtaf/Documents/workspace_vana/data-gateway-accesslane/RESULT.md).
2. Controller roll to ship ps #321 (MCP connections routes) — Moksha canonical first, then mainnet; then e2e the Web "connected MCP clients" section on app-dev/app.vana.org; then drop the vestigial mcp-tls from Moksha worker 87c32ca4 in a dedicated roll.
3. Moksha: 39+5 `submitting` server rows wedged since the Aug-28 relayer swap block 18 data points; needs an operator-verification slice (do not loosen classifyStuckTxWithProvenance).
4. Relay infra: expired cert on control.34.16.49.200.sslip.io:8443; control.*.vana.org names serve *.vana.com certs.
5. Product: MCP is not just-in-time (coarse vana:read; request_scope_access advisory only; docs Phase 3 ahead of code); "Add selected" scopes has no enclave route; Lorebook consent pill ≠ MCP status component; paste-free builder claim; access-feed.ts nonce claim suspicion; grant revoked while status=pending matches no drain branch (Codex P1, pre-existing).
6. MCP connector icon in claude.ai = vana.org favicon via Google (Kahtaf dropped it).

## 3. Where things are

- Receipts + INDEX: /Users/kahtaf/Documents/workspace_vana/e2e-proof-2026-09-09/fleet-overnight/launch-handoff-260914/overnight-260915/mainnet/ (step9–step35, INDEX.md). Briefs for every slice: overnight-260915/briefs/*.md (reuse their structure). Rules: overnight-260915/rules/.
- Demo rig: overnight-260915/demo/tools (README), demo/video-{a,b,c}/runbook.md, retake scripts; real Chrome profile copy demo/profiles/chrome-copy (claude.ai + cloud.phala.com signed in) driven over CDP :9222 (launch per demo/video-b/runbook.md; quit its pid only).
- Worktrees created today (safe to remove when their PRs are merged): data-gateway-{fixes,keyowner,resettle,rerevoke,dplane,accesslane,jobfees,reregister}, personal-server-{fixes,keyowner,jobfees,mcpclients}, unity-surfaces-{mcp-approval,dcr-working,ps-leadership,account-builders,mcpclients}, vana-sdk-jobfees, vana-storage-{jobresults,keyowner}.
- Claude memory: ~/.claude/projects/-Users-kahtaf-Documents-workspace-vana-personal-server-ts/memory/ (tee-path-state.md top section = current state; demo-recording-method.md; phala-cloud-and-codex-ops.md for acpx/phala facts).
- Codex via acpx: `npx -y acpx --cwd <dir> --model gpt-5.6-sol codex sessions ensure`, `… codex set reasoning_effort medium`, run detached: `setsid <script that runs: npx -y acpx --cwd <dir> --approve-all --model gpt-5.6-sol --format text --timeout 14400 codex -f <brief>>` (a plain `nohup … &` from a tool shell gets killed; setsid or a `(zsh run.sh &)` subshell survives). Codex writes RESULT.md where told; sometimes into its worktree instead — check both.

## 4. Overnight 2026-09-17 outcome (04:00–05:00Z) — morning queue

- R1 step36: MCP owner routes rolled on Moksha (controller da363ba3, workers afab7e29 ×2 — mcp-tls removed from 87c32ca4) and mainnet (controller 3082a74e, worker cceb9f2a); mainnet manifest re-pinned (#323). Both owner-list routes 401 = mounted.
- R2 step37/38: Moksha wedged servers swept (21 finalized), pending-then-revoked grants finalize locally; migration 0065 (additive) on both DBs; data-gateway #144 merged; dp-rpc dpl_DcAuNNfL (rb dpl_4u4Dz1Py), dp-rpc-moksha dpl_HHAe7ZG7 (rb dpl_BqfPxnXq). Open: 39 old data-point submissions still predecessor-gated (separate slice).
- R3 step39: unity #1086 → dev, promotion #1087 → main 513b30f1 (app dpl_vaNLftp8 rb dpl_ELPKY5uy; account dpl_bgLcWigV rb dpl_7pgxGXky); paste-free builder claim, access-feed six-key claim fix, "Add selected" feature-detected on `capabilities.widen`.
- MORNING (in order): (1) unity #1088 (R1's enclave session fix) is on dev — promote dev→main with the checklist so the "connected MCP clients" list works on app.vana.org; then browser-verify with mn-1 (read-only, do not revoke the Vana connection). (2) Merge ps #322 (widening route, CI green) and roll controllers (Moksha then mainnet) so "Add selected" lights up; verify. (3) GO LANES still pending Kahtaf. (4) 39 predecessor-gated Moksha data-point submissions: own slice.
