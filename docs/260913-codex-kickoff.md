# Codex kickoff — TEE path: deep architecture review, then productionize

**Superseded launch ordering — September 14:** architecture review (Task 1) is complete. Follow the [current production plan](260906-production-plan.md) and [Claude Fable launch handoff](260914-claude-fable-launch-handoff.md): deploy with one chain-aware rollout policy and retained mainnet Lite, prove rollout and selected mainnet smoke, expand, then retire Lite. The old Task 2 order and six-decision approval gate below are historical; do not repeat the review or require all six approvals. Larger findings remain follow-up work unless a concrete launch blocker emerges. Existing targeted operational hard stops remain. The checkout/head table below is historical; use the [current source inventory](../../e2e-proof-2026-09-09/fleet-overnight/launch-handoff-260914/source-inventory.md).

You are the orchestrator for the Vana personal-server TEE path. Kahtaf owns decisions; you own the work. Delegate reads and edits to subagents; keep the main thread to briefs, verification and decisions. Kahtaf has ADHD: every reply leads with the next action, numbered steps, ≤ 5 items, concrete time estimates, no preamble. Docs you write for him are one screen; evidence goes to receipts.

## Read first (in this order, ~20 min)

1. `/Users/kahtaf/.claude/projects/-Users-kahtaf-Documents-workspace-vana-personal-server-ts/memory/tee-path-state.md` — heads, fleet, rules, open items.
2. `/Users/kahtaf/.claude/projects/-Users-kahtaf-Documents-workspace-vana-personal-server-ts/memory/phala-cloud-and-codex-ops.md` — every operational gotcha learned the hard way.
3. `/Users/kahtaf/.claude/projects/-Users-kahtaf-Documents-workspace-vana-personal-server-ts/memory/kahtaf-working-style.md` and `feedback-orchestrate-delegate.md`.
4. `docs/260910-autoscale-closeout.md`, `docs/260908-lite-retirement-launch-gates.md`, `docs/260911-controller-ha-and-directory-resize.md`, `docs/260906-production-plan.md` §7.1 (this repo, branch `codex/personal-server-architecture`, uncommitted).
5. Receipts: `/Users/kahtaf/Documents/workspace_vana/e2e-proof-2026-09-09/fleet-overnight/` — `autoscale-slices.md`, `reviews/*.md`, `doppler/README.md`, `gateway-pool-loop/README.md`, `rehearsal-prod9/README.md`.

## Where things are

| Repo                         | Checkout                                                                                                                                                      | Head / PR                                                                                                                                                                                                     |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| personal-server-ts           | `/Users/kahtaf/Documents/workspace_vana/personal-server-fleet-controller` (deploy checkout, detached)                                                         | `feat/enclave-primitives` @ `919932f` = PR #245 (base main). Fold branches into it; never merge to main/dev.                                                                                                  |
| data-gateway                 | `/Users/kahtaf/Documents/workspace_vana/data-gateway-fleet`                                                                                                   | `feat/identity-schema` @ `c7c73ba` = PR #100 (base main).                                                                                                                                                     |
| unity-surfaces               | `/Users/kahtaf/Documents/workspace_vana/unity-surfaces-moksha-integration`                                                                                    | `feat/account-enclave-delivery` @ `df5618f3` = PR #987 (base dev). node_modules are hand-wired symlinks: never plain `pnpm install`.                                                                          |
| Fleet (preview, Phala prod5) | manifest `deploy/dstack/fleets/preview-prod5.json`; tooling `scripts/tee/{render-fleet.py,sign-fleet.cjs,gateway-nodes.cjs}`; runbook `scripts/tee/README.md` | controller + 4 tdx.medium workers @ `d7fd1a0`; Gateway pool loop live; laptop ticker `scratchpad/pool-loop-ticker.sh` (PID in `.pid`) POSTs settle/jobs-sweep/pool-loop every 60 s; prober `scratchpad/soak/` |
| Secrets                      | Doppler `dp-rpc`/`dev_moksha` → Vercel `dp-rpc-moksha` Preview; keychain `spike-b3-*` for operator/signing                                                    | deploy the Gateway preview from a real `git clone --shared` with origin = GitHub URL                                                                                                                          |

## Rules (hard stops → ask Kahtaf)

Never: merge to dev/main; touch canonical dev/prod hosts or DBs; touch the shared Privy signer or any Privy policy; change the attestation verifier or peer policy; delete a CVM; create Vercel or Doppler projects; type credentials/OTP; put the Phala CLI login token (Volod's personal token in `~/.phala-cloud/credentials.json`) anywhere. Secrets: read per command from keychain/Doppler with `--silent`/`--plain`, never into files or logs. One agent at a time mutates a fleet; pause the ticker from a detached shell during rolls. Every code change: gates (`npm run build`, `npm test`, `npm run lint:eslint`, `npm run format:check` for PS; package.json scripts for the others), draft PR against the base branch, fold with `--no-ff`, receipts under `e2e-proof-2026-09-09/fleet-overnight/<slice>/`. A proof is a linked receipt for the exact ref, not a green unit test.

## Task 1 — deep architecture review (complete; historical brief)

Review the whole TEE path as built, against the designs it claims to implement:
`docs/260908-tee-fleet-controller-design.md`, `260908-tee-fleet-coordination-design.md`, `260901/260902-*` (architecture and spikes), `packages/enclave/src/fleet/CONTRACT.md`, and the production plan.

Axes, each a separate subagent, findings only, file:line verified, no praise:

1. **Trust model** — what is measured vs signed vs trusted-by-config; the Gateway as a non-TEE component (Gateway-attested revocation, blind job queue); operator key outside the TEE; app-key-only sealing (MCP state, wallets); per-instance signed directory. List every place a compromised Gateway, worker, or laptop can do harm, and what the design says about it.
2. **Availability** — controller SPOF (ingress + allocator in one CVM, 150–180 s MCP outage per roll), pool loop semantics (free = 0 trigger only; no cold-start-pressure signal; idle stop while latency rises), lease/renew/reap state machine after the 09-11 fixes, KMS failover behaviour, host defects (prod5 `/Info` 15 s).
3. **Data plane** — hydrate limits (256 MiB tmpfs, ~1.5 s/MB), sandbox confinement, envelope caching, access records (fail-open queue), sizing for prod (instance/disk).
4. **Auth and MCP** — OAuth token model (1 h access, 7 d rotating refresh, reuse detection), no per-connection revoke on the fleet ingress, POST-only ingress (no streaming/session), replay fence, queued-job auth window.
5. **Ops** — runbooks vs reality (from-scratch 13 min, rolls 12 min, rollback 15 min), tooling gaps (manual: app ids, first deploy, harvest, activate), Docker builds not bit-reproducible, three branches per fold, Publish Canary 403.

Output: `docs/260913-architecture-review.md`, ≤ 60 lines: a ranked table (severity, area, defect, file:line, smallest fix, size), then ≤ 6 decisions for Kahtaf with a recommendation each. Detail in `fleet-overnight/reviews/architecture-review-detail.md`. Verify every review claim in code before writing it; two of five "critical" findings in the last security review were wrong.

## Task 2 — productionize (historical order; superseded above)

Order (from `docs/260908-lite-retirement-launch-gates.md`):

1. vana-sdk #211 → main; data-gateway #100 → main with migrations 0059–0062 applied to the canonical DB first (`db/migrations/README.md` cutover list); personal-server-ts #245 → main. All three are Kahtaf's merges; you prepare: rebase on current main, resolve, gates, closeout review per PR, a one-screen merge note each.
2. Production fleet on the node Kahtaf names: `scripts/tee/README.md` "From-scratch fleet (level A)" + tooling; `prd_moksha` Doppler config gets the fleet keys; Vercel cron replaces the laptop ticker; custom MCP domain needs a Cloudflare Zone:DNS:Edit token from Kahtaf; boot with `MCP_STATE_REQUIRED=0`, re-sign to 1 after the first real connection. Rehearse rollback on it before calling it done.
3. Ingress split (controller HA memo decision 1) if Kahtaf says yes.
4. Lite removal: PS #299 + Unity #1043 merge after prod is smooth; then relay teardown.

## Report format

Per task: what landed (head, PR, receipt path), what is proven and how, what is left, decisions needed. Numbers in tables. No summaries of your reasoning.
