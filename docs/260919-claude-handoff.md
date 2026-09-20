# Vana A–E work: Claude continuation handoff — 2026-09-19

Snapshot assembled at 2026-09-19T20:22:35.742073+00:00 from local receipts and inherited operator reports; this is not a fresh infrastructure verification.
This document supersedes older current-status prose for this A–E task. Original receipts remain historical evidence, not runnable instructions.

## Claude orchestrator status — 2026-09-19 (live; supersedes sections below where they conflict)

Exclusive owner: Claude orchestrator since 20:55Z (Kahtaf confirmed Codex stopped; orphan Codex prd_moksha script killed). Receipt PREP/claude-handover-2046/ownership-receipt.json. Receipts root: PREP/claude-lifecycle/.

### Gateway fixes shipped tonight (each: exact-head independent review + reviewer-run real-Postgres fail-at-base/pass-at-head; CI skips the Postgres suite — disclosed)

- Pre-existing lie corrected: canonical Moksha was serving a CLI upload of a stale tree WITHOUT PR150 (p1b-source/). Redeployed exact 785023c1, then:
- PR151 `fix(pool): scope saturation revert to failed starts` — revertMember wiped pool-wide saturatedSince on ANY failed member action; saturation never survived a tick, so no spare ever started. Reachable without manual action.
- PR152 `confirmedDown` — stops emitted only where the controller already confirmed the member down are no longer reverted on provider rejection; ends the per-tick doomed stop against an already-stopped CVM.
- PR153 revert clobber — clearStickyDrain's unconditional admit fails (null health), and its generic revert replaced the WHOLE member entry, wiping the quarantine committed earlier in the SAME tick. Reviewer re-audited all same-tick action pairs; no clobber pair remains.
- Deployed head `fe68f7b289528be14906ef004448be399f0b942f`: Moksha `dpl_7xKmTqXwvvcMv41trVXM8twZ4Q3k`, mainnet `dpl_6AKwysXoBx9nyMbAh3kfjCMmDFQt`. Rollbacks recorded per deploy. Mainnet POOL flag still ABSENT (loop off) — unchanged all night.

### Moksha D lifecycle evidence (fixed code) — PROVED, independently audited

- W3 was already wedged at 20:28:32Z by the loop's own exhausted restart budget (NOT by the 21:05 guarded drain). After PR153 it settled `quarantined` 23:29:32.357Z; dry-run then clean.
- Capacity: 8/8 placed (4+4, then 3/3/2); `saturated_since` 23:36:32.292Z; W4 auto-started 23:37:32.358Z (debounce 60.066 s); W4 provider-running/health200/controller ADMITTED 23:42:23.224Z/Gateway admitted, manifest-matching identity.
- Ninth: real assignment for `0xbcffd885…` on **worker-4**, 9 live, 3/3/3, none >4. W3 quarantined untouched; W1/W2 pinned, restarts 0.
- Drain: idle_since 00:00:32.570Z → W4 draining 00:16:32.194Z → stopped 00:17:32.160Z, cooldown +5 min, provider terminal. Idempotence: 4 byte-identical ticks, final dry-run empty.
- Independent audit: `claude-lifecycle/independent-evidence-review-d-claude.{json,md}` — all 7 claims SUPPORTED, hashes recomputed, auditor's own live re-checks.

### Mainnet lifecycle — PROVED, independently audited

- Loop enabled on `dp-rpc/prd`; first-ever tick seeded exactly the 4 manifest members (W1/W2 pinned running, W3/W4 unpinned stopped); nothing started at zero demand.
- The 8 capacity owners were ALREADY sealed/finalized on 1480 (ledger `enrolled:false` flags are STALE). Enroll correctly skipped — `EXISTING_IDENTITY_REQUIRES_RECONCILIATION` is the fence working.
- Ninth `0x5f25a48a…` was genuinely unenrolled (404). Its register 409 was `SETUP_PAUSED`: `ENCLAVE_ROLLOUT_POLICY` chain 1480 `defaultMode:legacy`, 11 overrides, 8 owners `tee`, ninth absent. **Kahtaf approved (conversationally) adding exactly one override**, scoped to that addition and this registration's cost only — no broader fee/settlement permission. After the override + redeploy it enrolled: sealed, serverStatus confirmed, userPsId `0x59929617…` (≠ Moksha's), servers row confirmed/paid. Protected owner's policy entry proven byte-identical pre/post.
- Pending `:register` checkpoint event reconciled by removing that one key (read-only reconciliation had proven the action never landed); auditor judged it the fence's intended escape hatch, not a bypass.
- Capacity: 8/8 placed 4+4; `saturated_since` 01:21:03.164Z; **worker-3** auto-started 01:22:03.380Z (debounce 60.216 s); full manifest-matching readiness before counting 12.
- Ninth: real placement on worker-3 — 9 live, 4/4/1, none >4; W4 stopped untouched; W1/W2 pinned untouched.
- Drain: idle_since 01:36:03.380Z → draining 01:52:03.422Z → stopped 01:53:03.216Z, cooldown +5 min, provider terminal. Idempotence: 4 byte-identical ticks, dry-run empty.
- Independent audit: `mainnet-pool-live-proof/independent-evidence-review-mainnet-claude.{json,md}` — 8/10 SUPPORTED, 2 PARTIALLY_SUPPORTED (record-keeping), corrections since verified in its delta section.

### Final state (released)

- Moksha: flag 1, `dpl_7xKmTqXwvvcMv41trVXM8twZ4Q3k` (fe68f7b). W1/W2 running pinned r0; **W3 quarantined r1 (stuck, no recovery path)**; W4 stopped r0.
- Mainnet: flag 1, `dpl_48b81A5oPtaD5G5LdqfSprYzgf6F` (fe68f7b). W1/W2 running pinned r0; W3/W4 stopped r0.
- Exclusive Claude fleet/deploy ownership (20:55Z–02:4xZ) RELEASED. Durable record: STEP65/RESULT.md, STEP65/INDEX.md, BASE/mainnet/INDEX.md.

### Disclosed limitations / open defects

- **Quarantine has NO recovery path anywhere in code** (reviewer- and auditor-confirmed, pre-existing). Moksha W3 stays out of service; the pool runs 3 effective workers there. Comments claiming "requires an operator" describe an action that does not exist. Needs its own fix; manual DB edits prohibited.
- Moksha's proven spare was **W4, not W3**, for that reason. Mainnet's was W3, as designed.
- **"Landed and stayed" is not fully proven**: no assignment-level re-read exists between landing and drain on either fleet. Mainnet is partially closed (the ninth's single-occupant node went idle 5 min after the pinned pair); Moksha is ambiguous (its node hosted 3 placements, shared idle_since proves nothing). `claude-lifecycle/ninth-persistence-evidence.json`.
- Mainnet Config B (ninth enroll) leaves no augmented-config copy, so its executed bytes are not independently re-hashable — only timestamp/content consistency.
- Executed configs carry a stale, self-contradictory `executionNote` (documentation bug, not read by run.mjs).
- CI skips the real-Postgres suite; each reviewer stood up its own Postgres instead. `saturated_since` clearing at the start action is intended, not the PR151 defect.
- Harness has no bulk lease renewal; each capacity cycle needs a fresh reviewed lease plus removal of the 8 `:capacity-8` checkpoint keys (scripted, blessed, backups kept). Enroll is single-owner-per-invocation with 121 s pacing.
- Pacing guard now 121 s in both bundles; its error string still says `_120S`; `lastBatchAt` stamps at dispatch not completion (pre-existing).
- E (paid/private inference) remains BLOCKED and untouched; GO LANES still held.

## Ownership before execution

- The prior Codex fleet operator may STILL BE RUNNING. This documentation pass did not pause, interrupt, contact, or transfer any agent.
- Before any mutation, obtain an explicit handover from the previous operator/main task (or Kahtaf confirming it is stopped), inspect in-flight deployment/phase receipts, and establish one exclusive deploy/fleet owner. Do not infer stopped from silence or this file.
- Until handover, only local read-only preparation is permitted. Never run two operator loops or competing mutations against a project/fleet.
- Main Claude agent orchestrates, reasons, sequences, and accepts evidence; smaller agents implement, operate, test, and independently review. No self-review; no autoreview. Keep updates to milestones/blockers.

## Paths and reading order

- BASE = `/Users/kahtaf/Documents/workspace_vana/e2e-proof-2026-09-09/fleet-overnight/launch-handoff-260914/overnight-260915`.
- STEP65 = BASE + `/out/step65-d-pool-inventory`; PREP = STEP65 + `/moksha-pool-live-proof/ninth-owner-prep`.
- Read this file, `STEP65/CLAUDE-HANDOFF-SNAPSHOT.json`, latest PREP receipts by actual modification time, `STEP65/INDEX.md`, and `BASE/mainnet/INDEX.md`.
- Original scope: `/Users/kahtaf/.codex/attachments/703b02b3-e727-41aa-992f-6a661c9915ce/Pasted text.txt`; then BASE/rules/{COMMON,DAY-RULES,EVENING-RULES}.md and repository AGENTS.md. Later approvals below override the older scope restrictions where explicit.
- Historical architecture: docs/260910-autoscale-closeout.md and docs/260911-controller-ha-and-directory-resize.md. Older handoff and MORNING-REPORT are historical, not live inventories.

## Latest confirmed progress and uncertainty

- Gateway PR150 merged per operator report with exact-head guard: reviewed `01ca38fa9c054839e17ed23e4908a72409aef023`, merge `785023c1ffc12b2202d4dda94cb9516c4f87f927`. Independent review PASS; 11 unit and 12 real isolated PostgreSQL tests PASS; required CI green. No migration in this fix.
- Fix: strict canonical app/compose hex identity validation, followed by CAS using exact observed raw stored values; instance/freshness/draining/zero-active/race guards preserved. Worktree `/tmp/data-gateway-pool-resume-hex-260919`.
- Automatic deployments reported: mainnet `dpl_F3yidTNaqLtHN4CQU9kWFhgAQwvF`, Moksha `dpl_6waU1fJWKAy1xzkMKVzmq5ozLswV`. Last inherited report was build internally READY but deployment BUILDING. Reconcile actual deployment, commit, and canonical serving state; do not deploy again blindly.
- NEWER LOCAL RECEIPT: PREP/post-pr150-off-2019/receipt.json records authenticated pure dry-run HTTP200 disabled at `2026-09-19T20:18:30.503957+00:00`.
- NEWER LOCAL RECEIPT: PREP/enable-pr150-2020/doppler-enable-receipt.json records `dp-rpc/prd_moksha POOL_LOOP_ENABLED=1`, command exit0. Its timestamp contains invalid literal `3N`; retain it as malformed, do not invent precise timing. This establishes a recorded config write, NOT effective deployment or successful proof.
- Enable-deploy stdout/stderr exist in that directory and may still be growing. Reconcile in-flight operation and fresh state before retry. Mainnet enable has no evidence here; last known mainnet flag absent/off.
- Last full physical Moksha proof was PREP/w3-rollback-finalproof-2004/summary.json at 20:04:01Z: W1/W2 healthy admitted zero-active; W3 stopped after guarded rollback; W4 untouched stopped; controller unpaused. It is historical after re-enable.
- First capacity cycle proved 8 distinct placements (4+4) and automatic W3 provider start. W3 became controller-admitted but Gateway stayed draining because of the hex mismatch now fixed by PR150. Ninth request was NOT issued in that cycle. No completed D lifecycle proof yet.

## A–E ledger

- A: PS PR329 replaced/repaired PR270; merged release de881ee, subsequently included in runtime84d below. Local/release tests and ordinary write/MCP evidence exist. Live internal-session replay is separately unproven; do not mark it PASS.
- B: Gateway PR112 merged/deployed (`196674a7...`); ordinary production smoke passed under explicit user waiver of the special Moksha replay gate. Replay/lifecycle verification remains unproven; do not retry the previously blocked security proof or treat waiver as evidence. See steps60–61 for retained orphan registration and attribution/test limitations.
- C: accepted independently in BASE/out/step64-guarded-drain-recovery/mainnet/c-completion-matrix-luna.md. Guarded recovery, genuine MCP fixture, and 688.691-second final soak passed. Historical cold/capacity evidence is release-labeled; 115.669-second pacing deviation and provider-only memory attribution remain disclosed. Do not reopen completed C gates.
- D: both fleets have signed four-worker directories, W1/W2 pinned and W3/W4 unpinned spares. Manifests merged PR336/337. Approved config prepared, dev competing loop isolated. Remaining critical path is fixed-code Moksha lifecycle E2E, then mainnet enable and bounded lifecycle E2E.
- E: PR113 remains draft; assessment and executable remediation path at BASE/briefs/step58-private-inference-assessment/RESULT.md and BASE/out/step58-private-inference-assessment/remediation-plan-a.md. Five spend/metering gaps remain; paid/private inference stays BLOCKED. Assessment complete does not mean safe to enable.

## Approvals already granted and hard limits

- Kahtaf approved production membership/provider token/enable rollout in `dp-rpc/prd_moksha` then `prd`, dev_moksha disable/refresh, and the exact obsolete Preview removal/branch-alias move. Do not ask again for these same prepared changes.
- Additional non-protected test owners, including new mainnet test owners and Gmail, are authorized. Original prohibition on new owners is superseded. Never touch `0xabae1ae71b5a299e3a3ac50d4a3f844ee5ea4766`.
- No escrow, fees, on-chain money, CVM deletion, paid inference, GO LANES/PR136/config changes, verifier relaxation, digest disablement, or instance override. Do not manually settle pending test registrations.
- No unrelated app/account/mobile aliases. Mobile remains pinned `dpl_35RPcRKq2N3WBHUjmJtyC4yZ4Qn8`; historical one-off dev Preview exception is completed, not general alias permission.
- Author Kahtaf Alam <kahtaf@gmail.com>; no attribution/coauthors. Exact-head independent review and green required CI before merges. Record rollback deployment ID before every deploy; state no migration or reviewed additive nullable shape.
- Operator/canonical requests spaced at least121 seconds from prior target completion. One bounded capture→guard→action phase must not insert another121 seconds between guard and dependent action. Provider-only bounded async settle may use30 seconds. Normal Vercel cron is the sole pool action loop; no manual normal cron POST or manual starts/admissions to manufacture proof.
- Create receipt directories BEFORE operations; save raw response/status/timestamps/hash BEFORE assertions. A local ENOENT/curl23 can occur AFTER mutation: reconcile fresh state; never blindly retry. Never print/store secret values or secret digests.

## Runtime, credentials and preserved configuration

- PS runtime `84d19ffc3f4059c5a5d034c8f7e987f0c07bcfd9`; images.env SHA `fe866457e7068cf6d0c4e78c8e6cfa607d3b646f40a42ed6ca607c041bc112fc`. Gateway fix requires no CVM restage/sign/roll.
- Moksha manifest SHA `69a09aa8efe87fe59e7beb86dc23d0a4c1d629248ffc0ed3c6558f685b0c5842`, PR336 merge `daf4677944fdf943335b6d3694d3df0620a7a2d7`; worker compose `8a0f4ab7722b278ff9b1d5055e53b6219f0a4b208b355b44fccdf2ae7d43f050`.
- Mainnet manifest SHA `53bf05f07a1ae20f9c7b1d7093147c3c417907c93838b3a42220ed16741ac3fb`, PR337 merge `c1b2426568cba0fe6cee59fd27fb9bc7052e5b90`; worker compose `b830734d63f3b4dd818cecf3ef1aa2e04454a810de8f76f14712e2a59026bba3`.
- Obtain exact UUID/instance/URL/admin refs from frozen five-node manifests/receipts. Moksha W3 UUID `eb5e1d4d-18c1-4ac2-8e59-fb8f53004fa5`, instance `bcf10e49759e17bfb3e0bdf460b9b7e071722d00`; never select by app ID alone.
- Both production configs contain four cap4 member declarations, pinned W1/2 and unpinned W3/4, with all8 per-member agentSecret values privately verified; approved PHALA_API_TOKEN exists. Use explicit Doppler project/config, never implicit cwd. Once seeded, DB membership is authoritative.
- W3/4 Keychain refs use `vana-step65-{moksha|mainnet}-worker-{3|4}-{agent|node}-secret-v2`, account `spike-agent`; old unsuffixed refs are empty. Read W1/2 refs from manifest.
- dev_moksha flag0; disabled Preview `dpl_CKpK7Ubv3iv1v7zY36RnA7zHjv7F` has branch alias; old enabled `dpl_AwMGqBiX4jdEX5UQ9Apd1B2GE8YS` deleted. Generic dev/dev_personal have no fleet config. No need repeat these operations.
- Last rollback OFF Moksha deployment `dpl_GNxab32GV79zv62CyzahZ4rWwQ5z` is pre-PR150; capture CURRENT fixed-code rollback before next deploy, rather than assuming this older artifact is preferred.

## Remaining execution sequence

1. Exclusive handover; reconcile latest local artifacts, running commands, actual deployment/flags/DB/provider/controller/Gateway state. The enable command may already have succeeded. Do not overwrite active operational handoff files from a stale snapshot.
2. Confirm PR150 fix deployed and normal cron reconciled W3 after rollback. Cold adoption demotes unavailable zero-lease starting member only after previous tick gap≥10min. Ordinary admit-wait can otherwise reach8min restart/quarantine. Verify actual last_tick_at and phases; no fake clock or DB reset. This may already have happened after recorded enable.
3. Establish fresh 2running/2stopped, W1/2 healthy admitted cap4, idle0 placement baseline. Capacity8 BEFORE is idle/free8; the action CREATES8 demand. Execute reviewed existing8 owner prewarms once, then require8 distinct live placements, ≤4 per worker.
4. Capture persisted saturation/action timing. Normal60-second cron, debounce60s, max4/min2. First cycle did not retain exact saturated_since before it cleared; use existing cron decision logs/read-only history without violating121-second operator pacing. Never fabricate a live no-early-start claim from source alone.
5. Require one automatically started spare, health200, controller admitted/available/non-draining, Gateway admitted, exact app/compose/instance and fresh heartbeat. Only then count capacity12. Capture guard→ninth action in one bounded phase before existing leases expire. 202 means accepted, not assigned; prove actual ninth placement and no overcommit, W4 remains stopped.
6. Stop renewing workload. TTL600 seconds first, then persisted zero-live idleSince≥15min; normal loop drains then later stops the unpinned member, cooldown5min. Capture real timestamps/provider terminal state; W1/2 pinned never stop. Prove idempotence and failure visibility/reconciliation; no forced/manual stop as proof.
7. Independent Moksha evidence review; resolve actual scoped failures. Then mainnet source re-review, fresh ninth mainnet identity derivation/enrollment, approved enable/deploy with rollback, and bounded repeat. Mainnet source fixes are author-verified, NOT independently accepted yet.
8. Close durable results/receipt≤100lines/INDEX, accepted limits, rollback identifiers, final flags/placements/provider state and exclusive-owner release. Report D complete only with actual evidence. E remains held as above.

## Harness and identity traps

- Moksha bundle STEP65/moksha-pool-live-proof; mainnet bundle STEP65/mainnet-pool-live-proof. Never copy Moksha chain14800/signing/config/contracts/admin secrets into mainnet chain1480. Mainnet runner policy and typed chainId fixes are in corrected source; independent-review-luna.json preserves findings and AUTHOR_VERIFIED_PENDING_INDEPENDENT_REVIEW.
- Snapshot JSON records actual file hashes; refresh phase leases/config timestamps using real clock and validated source fences. Templates are NOT executable configs. Existing offline mainnet import failure is not a passed behavioral test.
- All9 Moksha EOAs enrolled/sealed. Ninth EOA `0x5f25a48a0e168c72a1260d565bd53ff6088908b9`, Keychain `vana-step65-moksha-capacity-owner-9-v2` / `spike-agent`; Moksha userPsId `0xbcffd885596324e1dc5930370926a0a027f07786d7cee4244a8c7d2f3c8539a7`.
- Same EOA/key across chains is authorized; mainnet userPsId must be freshly derived on1480 and ordinarily enrolled/sealed. Do not reuse Moksha userPsId or regenerate key because service name contains moksha.
- Strict key adapter accepts bare64hex or0x64 then derives matching ledger address. Pending server registration with sealed identity is expected and supported ONLY for reviewed pool prewarm phases; do not weaken confirmed/finalized requirements for data writes or force settlement.
- Local PostgreSQL regression runtime is under `/tmp/data-gateway-pool-resume-fix-20260919` (.dev-pg,127.0.0.1:5433), but tests MUST execute the new checked-out source. Never run regression mutations against production NEON.
- No browser work is currently on D critical path. If needed, honor user preference for an independently controllable in-app browser; do not require foreground Chrome while they use their machine.
