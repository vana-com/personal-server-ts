# Production launch plan — September 14, 2026

**Deploy the shared stack first, prove controlled rollout, then retire Lite.** This supersedes September 9's preview-hardening hold and mainnet exclusion, and September 13's review-first ordering. Architecture review is complete; its larger findings are follow-up work unless a concrete launch failure makes one necessary.

Execution: [Claude Fable handoff](260914-claude-fable-launch-handoff.md). Target prerequisites and evidence: [launch detail](../../e2e-proof-2026-09-09/fleet-overnight/launch-handoff-260914/launch-plan-detail.md). Current source/PR authority: [source inventory](../../e2e-proof-2026-09-09/fleet-overnight/launch-handoff-260914/source-inventory.md); older refs below are review snapshots, not live status.

## 1. Implement the rollout contract

Use **one server-owned, chain-aware TEE rollout policy**; Account is the recommended home, not an implemented service. Start with Lite as mainnet's default and TEE on Moksha. Resolve authenticated owner eligibility centrally; Web, Account, mobile and Gateway must enforce the same decision. Environment/anchor configuration is a prerequisite, not another rollout switch.

Restore the real Lite consumer adapters before exposing this mixed deployment. Reviewed PS `919932f` still contains `packages/lite`; Unity `df5618f3` removed/rerouted its owner-data, consent and MCP adapters. Package retention alone cannot make flag-off work.

Rollout-off stops **new TEE admission**. Existing registered/sealed identities, grants and MCP routes keep their recorded TEE binding and authorization checks; preserve status/revoke/resume controls. Never silently fall back to Lite, infer Lite from an unknown status, or revoke through the rollout policy. Emergency execution pause is a separate incident action with an explicit outage. Smoke access needs explicit disable/revoke and a next-request denial proof.

## 2. Prepare and deploy in dependency order

1. Publish the usable **SDK**, with verified Moksha anchors for the chosen fleet; pin consumers. Integrate release branches and pass each repository's required checks against exact candidates.
2. Inventory/apply target **Gateway DB** prerequisites before Gateway deployment; include required identity/jobs/fleet migrations and preserve fencing. Deploy Gateway and Storage with matching chain, audience and endpoints. Prove scheduled settle/jobs-sweep/pool-loop execution from durable cron.
3. Deploy **Personal Server** controller/workers with pinned artifacts, signed config/anchors, persistent state and restart-safe config lifetime. Bootstrap `MCP_STATE_REQUIRED=0` → admit workers/activate controller → create a real MCP connection → re-sign with state required `1`.
4. Resolve **Account** DB 008/010 ledger before required 026/027; configure required signing/Privy rules, origins and OAuth. Deploy Account + Unity with released SDK and the shared rollout policy; preserve primary mainnet Lite and selected-network routing. Deploy Lorebook/reference app to the same endpoints.

Canonical host mapping remains Moksha `app-dev.vana.org` / `account-dev.vana.org`, mainnet `app.vana.org` / `account.vana.org`; confirm actual hosting branch/environment before promotion. A preview migration or passing cron endpoint is not target deployment proof.

## 3. Prove rollout, then expand

1. On the shared deployment, prove mainnet Lite import/read/consent/MCP and selected Moksha TEE ingestion → consent → SDK result/decrypt/ACK plus real Claude MCP read. Reject unauthorized and wrong-chain requests.
2. Prove **enable → disable → re-enable**: new admission follows policy, existing TEE routes keep working, and no cross-network/implicit fallback occurs. Exercise explicit smoke-access revoke separately.
3. Add actual-mainnet capability as a separate slice: fleet and Account have hard Moksha guards. Supply real mainnet chain/contracts/endpoints, signed fleet/KMS configuration and published trust anchors; changing a Boolean is insufficient. Then smoke selected wallet-allowlisted accounts while other mainnet users stay on Lite.
4. Expand the mainnet cohort after successful proof, then all eligible users. Fix small failures affecting switching, networks, shared production or smoke now; record larger review hardening for later.

## 4. Retire only after successful rollout

Stop new Lite use, safely resolve remaining Lite routes/connections and retire the rollout flag. **Only then** remove Lite adapters, package/dependencies/release artifacts and Lite-specific infrastructure, followed by genuinely obsolete Git branches. Keep local full-server support and unrelated relay services/data intact. See [retirement gates](260908-lite-retirement-launch-gates.md).

## Authority and scope

Prepare reviewable release work now. Main/dev merges, canonical host/DB changes, shared Privy or verifier/peer-policy changes require targeted user go. No external messages, secret exposure, project creation or autoreview egress is authorized. Preview disposability does not authorize unrelated deletion. Broad HA, reconciler, audit or quota platforms are not prerequisites.
