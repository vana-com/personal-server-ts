# Claude Fable review of the fleet controller design

Scope: independent review of [the proposed design](../260908-tee-fleet-controller-design.md), with relevant code and current live-demo evidence as context. This was not the autoreview workflow or a general code review. No runtime, dependency, deployment or git-ref changes were made.

Reviewer: Claude Fable through `npx acpx` (acpx 0.15.1), explicitly selected with `--model fable`; read/search permissions. The first exploratory pass ended without final findings; a direct continuation delivered six findings. A focused follow-up checked the document changes.

The prompt supplied current verified refs: PS #245 `ca4c9b1` / deployed runtime `a16fd5b`; Unity #987 `7cb42e0f`; Gateway #100 `30d13db`; Storage #24 `093310df`; SDK `fa015207`. It pointed to the matching worktrees, current MCP/identity/job contracts, fresh-owner and consent proofs, native ingress research and actual Claude demo evidence. Historical docs were identified as historical, and HA/DRK/renewal limits remained explicitly deferred.

## Findings and disposition

| Finding                                                           | Decision                                 | Design change                                                                                                                              |
| ----------------------------------------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| High: missing source for a new worker's sealed wake-up envelope   | Accepted                                 | New private controller→Gateway envelope retrieval, current identity/assignment binding and failures; MCP-only cold-start proof required.   |
| Medium: worker registration/admission/operator interfaces omitted | Accepted                                 | Explicit peer-key-bound registration, separate operator actions and migration of existing admission records as pending candidates.         |
| Medium: execution interface omitted connection/grantee material   | Accepted with factual wording correction | Carry ephemeral grantee **signing** key/connection context through the protected TEE channel; it is not the owner decryption root.         |
| Medium: fleet rollout job-claim exclusion unenforced              | Accepted                                 | Persist owner enrollment; exclude enrolled owners atomically from generic claims and serialize enrollment against in-flight legacy claims. |
| Low: scoped readiness reporting missing                           | Accepted                                 | Scope/version reports tied to current placement, bounded worker refresh when stale, pending/unavailable instead of optimistic readiness.   |
| Low: v1 leadership term and dormant state unclear                 | Accepted                                 | Reserve term 1 for singleton deployment; define dormant/release/reallocation transitions without generation reset.                         |

Final Fable verdict: all six findings adequately addressed; no material contradiction introduced. Its optional wording note was also applied: worker B **receives** wake-up material through controller preparation, rather than ambiguously fetching it itself.

No architecture reversal or new demo release blocker was introduced. Full RPC schema details, timing measurements, shared state/leadership for HA, broader attestation audits and fleet deployment remain their existing future work.

## Evidence and checks

- [Review and code-path evidence](../../../e2e-proof-2026-09-08/fleet-design-review/claude-fable-review.md).
- [Focused verification](../../../e2e-proof-2026-09-08/fleet-design-review/claude-fable-verification.md).
- Prompt and raw acpx logs are stored alongside those artifacts.
- Prettier checks pass; all 15 links in the design were checked and local targets resolve; `git diff --check` passes.
- No runtime tests were run for these documentation-only changes.
