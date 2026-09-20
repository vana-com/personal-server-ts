> Archive note (2026-09-08): Initial targeted Codex review snapshot. Later reconciliation qualifies the scope of the PS Lite ingestion blocker. References to a pending migration-direction question are historical: the user subsequently requested planning only.
>
> Current index and plan: [Review response and PS Lite decommission plan](../260908-review-and-ps-lite-decommission-plan.md).

# Enclave stack review and PS Lite migration map — 2026-09-08

Follow-up: `CLAUDE-REVIEW-RECONCILIATION-2026-09-08.md` qualifies the decommission blocker: global Lite retirement needs owner-ingestion work, but enclave DCR completion can independently drop its obsolete Lite URL requirement. It also records additional version-enforcement and result-destination findings and corrections to Claude's feedback.

Read-only, targeted review of the six parent PRs and the dated handoff. This is a source review and dependency assessment, not an exhaustive audit or fresh runtime certification. No tests, deployments, merges, secret reads, or production operations were performed.

## Pinned stack

| Repository / PR         | Target | Base SHA     | Head SHA     | Changed files |
| ----------------------- | ------ | ------------ | ------------ | ------------: |
| personal-server-ts #245 | main   | 7167045030ab | 2f1915b076ab |           132 |
| vana-sdk #211           | main   | 8127729571ac | fa0152075367 |            19 |
| data-gateway #100       | main   | 3d0d754db3f7 | 30d13db97a74 |            94 |
| vana-storage #24        | dev    | 1961dcfb2ce8 | f442653f5bf6 |            14 |
| unity-surfaces #987     | dev    | fd32b1e5b49d | bd8f2fe6226c |            65 |
| lorebook #1             | main   | 05c43c12872c | ff49c73ec7b3 |            21 |

All six are open. Review agents verified current remote head/base, matching local worktrees, nonempty three-dot diffs, and commit histories. Earlier Opus reviews were consulted to exclude resolved findings. Coverage emphasized ownership boundaries, signed artifacts, sealed delivery, result storage, prewarm, lifecycle, and consent/ingestion dependencies.

## Standards

1. **P2, non-blocking: grantee disclosure policy is duplicated across core and server.** `personal-server-ts-enclave/packages/server/src/jobs/raw-envelope-stream.ts:360` repeats core-owned `$writtenBy`/lineage redaction. The repository AGENTS.md assigns protocol behavior to core. Current parity coverage mitigates drift; no present disclosure leak was established. Share the policy or move the streaming policy into core in a separate change.
2. **P3, non-blocking: public streaming authentication semantics need documentation.** `vana-sdk/packages/vana-sdk/src/crypto/envelope/job.ts:840` documents `openJobResultStream` with a one-line summary. The SDK DOCS_GUIDE requires return/error semantics. Its promise validates metadata; subsequent corrupt/truncated frames fail while consuming the body. Document per-chunk authentication, full-consumption requirements, and deferred failures.

No further consequential standards findings were established in the targeted Gateway, Storage, Unity, or Lorebook inspection. Standards total: two; most significant is duplicated core-owned disclosure policy.

## Spec

These are gaps against the architecture's target guarantees, not claims that the raw-read preview was intended to deliver every future inference feature.

1. **P1: own registration is not verified as an owner-signed artifact.** Architecture decision 9 requires "its own owner-signed registration." `personal-server-ts-enclave/packages/server/src/jobs/worker.ts:215` checks unsigned Gateway registration fields. With a previously sealed secret and valid builder grant, stale or fabricated registration state can still authorize execution. Relatedly, `packages/core/src/policy/signed-artifacts.ts:53` explicitly leaves grant-revocation verification on chain as a TODO. The complete refuse-only Gateway guarantee is therefore not implemented.
2. **P1: retired epochs are not independently enforced by the agent.** Identity contract section 1 requires "Agent refuses to derive/seal for epoch < current." `personal-server-ts-enclave/packages/enclave/src/agent/evidence.ts:20` derives the requested epoch. `agent/seal.ts:34` uses an optional minimum supplied by the Gateway, with an explicit comment that v1 has no store. Honest Gateway retirement works; independent protection against rolled-back Gateway state does not.
3. **P2: fresh result-handle retrieval does not recheck revocation.** Architecture invariants say revocation reaches result fetch. `data-gateway-fold/api/v1/jobs/[id].ts:41` checks builder ownership; the result view checks TTL. A builder can complete a job, have its grant/server revoked, and still obtain its handle by polling until expiry. This is separate from the accepted inability to revoke ciphertext URLs a builder already possesses.

Spec total: three; most significant are incomplete independent authorization and retirement boundaries. Immutable-key retries after an ambiguous PUT can also fail on conflict, but the result-delivery plan expressly accepts orphan-result failure; reconcile that with the architecture's stronger idempotency wording before classifying it as a violation.

## PS Lite decommission: missing prerequisite

The selected priority is decommissioning on a branch stacked on #987. A clean local worktree exists at `unity-surfaces-retire-lite`, branch `feat/retire-ps-lite`, starting at exact parent `bd8f2fe6226c9ecc8295416549734c021d1c8ec0`. It contains no implementation changes and has not been pushed.

Removing registration alone breaks current ingestion:

- Web `web-personal-server-session.ts:849` still prepares/signs/submits Lite registration. `prepareWebPersonalServerSession` calls this before initial sync. The provider unconditionally boots the runtime. DCR approval retains a Lite fallback when enclave delivery is disabled or unavailable.
- Mobile `apps/mobile-shell/lib/ps/ps_service.dart:368` registers during boot. `ps_bundle/src/harness.js:2972` refuses unregistered sync. `mobile_native_login_orchestrator.dart:254` requires registration and then relay readiness before successful login.
- Upstream `personal-server-ts-enclave/packages/lite/src/sync.ts:290` gates sync on the Lite server's registration. Its storage, AddData, deletion, and lineage requests use the Lite server account. Bypassing only the gate cannot repair authorization.

The existing infrastructure supports direct-owner authorization: Gateway `/v1/data` accepts an owner-signed AddData, and Storage accepts an owner Web3Signed request. SDK #211 contains the crypto/storage/registration primitives, but no complete owner-ingestion adapter. Account and native Mobile lack constrained AddData/storage signing intents. An enclave public identity cannot replace an unavailable private signer.

Recommended dependency order:

1. Define and implement owner-authorized ingestion using existing wire formats, exact version commitments, and appropriate retry/deletion behavior. First public regression: an owner with no registered Lite server encrypts, uploads, and registers a data point successfully.
2. Add constrained Account/native signing adapters and external-wallet behavior for that ingestion path. Live policy changes remain separate from implementation and tests.
3. Replace Web source-write and Mobile connector upload adapters. Preserve local data access and existing encryption keys while changing readiness.
4. Remove automatic Lite registration and DCR server fallback; prove Web preparation makes zero registration prepare/sign/submit calls while ingestion remains usable. Remove Mobile's registration/relay login gate only after replacement readiness works.
5. Retain `packages/lite` and compatibility exports until enclave adoption and remaining consumers permit deletion.

Do not remove `vana-master-key-v1`: active Web, Mobile, and Account already use it for existing data keys and enclave delivery. The SDK's separate legacy message is `vana.account.v1:ps-lite-owner:<address>` in `protocol/personal-server-lite-owner-binding.ts`. No literal `personal-server-lite/` message remains in the active Unity code inspected. Inventory consumers before retiring that legacy export.

Validation after implementation: package-local Vitest/TypeScript, changed-file lint, Mobile shell Node/Flutter checks, and the real Web sources/DCR flow plus native Mobile onboarding. The new worktree lacks dependencies; existing package-local binaries are available in sibling worktrees. No installation or environment mutation was attempted for this review.

## Rollout constraints and conflicts

The September 8 handoff takes precedence over older runbook advice:

- No merge to main/dev without Kahtaf's explicit go; no production operations.
- Exactly one running CVM per Phala app id. The older runbook recommendation for two nodes must not be executed as written.
- Several nominally Moksha runbook steps touch production Web/Account or the production Storage bucket. They remain excluded by the no-production rule.
- SDK release #1, re-pins, migrations, fleet provisioning, and SDK release #2 with trust anchors are dependencies, not actions completed by this review.
- Every Personal Server change requires a passing root `npm run build`. Never roll a CVM to an unverified ref.

Migration direction is pending: expand to owner-authorized ingestion prerequisites, or keep this pass at review and a concrete decommission plan. Existing upload/login paths were left intact pending that choice.
