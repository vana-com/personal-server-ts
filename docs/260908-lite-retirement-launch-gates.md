# Lite rollout and retirement gates — September 14, 2026

**Launch with Lite retained; delete it only after successful TEE rollout.** This replaces the earlier productionize-then-delete ordering. [Production plan](260906-production-plan.md) and [Claude Fable handoff](260914-claude-fable-launch-handoff.md) govern execution. [Source inventory](../../e2e-proof-2026-09-09/fleet-overnight/launch-handoff-260914/source-inventory.md) governs refs; [launch detail](../../e2e-proof-2026-09-09/fleet-overnight/launch-handoff-260914/launch-plan-detail.md) holds prerequisites and proof requirements.

The reviewed PS `919932f` retains `packages/lite`; reviewed Unity `df5618f3` removed/rerouted Lite adapters. Restore a working default mainnet Lite path before mixed deployment. Preview proofs do not establish canonical/mainnet readiness.

## Ordered gates

| Order                        | Required outcome                                                                                                                         | Minimum proof                                                                                                                                                              |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Shared deployment         | SDK → migrated Gateway/Storage → PS → migrated/configured Account + Unity; one server-owned chain-aware policy, Account recommended home | Exact refs/artifacts, target migration ledger, signed anchors/config, durable cron execution and real MCP state bootstrap.                                                 |
| 2. Lite default / Moksha TEE | Mainnet non-selected owners retain functional Lite; selected Moksha owners use TEE                                                       | Real source import/read, DCR/consent and MCP on Lite; TEE ingestion, SDK result/decrypt/ACK and Claude read; wrong-chain and unauthorized denial.                          |
| 3. Rollout reversibility     | Enable → disable → re-enable governs new admission; persisted TEE routes remain authoritative                                            | New admission denied when off; enrolled owners retain status/revoke/resume and existing authorized reads; same-owner re-enable without silent Lite fallback.               |
| 4. Actual-mainnet smoke      | Separate mainnet capability plus selected-wallet allowlist, others remain Lite                                                           | Mainnet contracts/URLs/anchors/signed config and registry evidence; cold/warm read; unlisted/wrong-chain denial; explicit smoke-access disable/revoke denies next request. |
| 5. Expand                    | Successful selected smoke → wider mainnet cohort → all eligible users                                                                    | Exact cohort/chain, real ingestion/consent/SDK/MCP receipts, known failures fixed or explicitly bounded; retained Lite users remain functional.                            |
| 6. End Lite routing          | After successful rollout, stop new Lite use, resolve remaining recorded routes/connections safely, then retire policy flag               | Inventory demonstrates remaining Lite consumers are migrated, deliberately disconnected or otherwise safely resolved; TEE routes remain correct without policy.            |
| 7. Remove Lite               | Only after gate 6: adapters, package, CLI/server dependencies, publishing/release artifacts, Lite-only infrastructure, obsolete branches | Replacement routes still pass; no Lite consumer/dependency/release reference remains; ownership inventory protects full local server and unrelated relay resources.        |

Rollout-off is **not** revocation or emergency execution pause: existing TEE bindings and credentials continue under durable authorization checks. A security pause is an explicit incident action; the smoke must separately demonstrate removal of its access. Unknown identity status must not select Lite, and a TEE failure must never trigger implicit Lite fallback.

PS #299 / Unity #1043 are historical removal candidates, not approvals. Package deletion is not rollback. Mainnet needs coherent fleet/Account capability beyond their reviewed Moksha guards.

## What does not block deployment

Fix small bugs required for rollout switching, network routing, shared deployment or selected smoke now. Broader architecture-review work, HA, reconciler, audit/quotas and exhaustive parity/soak are deferred unless a concrete selected flow is blocked. Existing local full-server support survives retirement.

Preview resources being disposable does not authorize deleting unrelated data, relay infrastructure or Git branches. Main/dev merges and canonical hosts/DBs/shared Privy/verifier-peer-policy mutations require targeted user go. No external messages, secrets, project creation or autoreview egress. Each gate needs exact-target/ref receipts, beyond unit tests.

Historical September 11 gate statuses and their evidence are preserved in [pre-update gates](../../e2e-proof-2026-09-09/fleet-overnight/launch-handoff-260914/260908-lite-retirement-launch-gates-pre-update.md); these are historical evidence.
