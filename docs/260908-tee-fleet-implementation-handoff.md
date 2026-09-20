# TEE fleet implementation and E2E handoff

Status: implementation dispatched on 2026-09-09 after user approval of the live Moksha envelope: at most one controller and two workers, reusing compatible existing resources. Temporary screenshots, sanitized logs and timings are required. Mainnet remains excluded.  
Architecture: [fleet controller design](260908-tee-fleet-controller-design.md). Review: [Claude Fable findings and resolutions](reviews/260908-claude-fable-fleet-design-review.md).

## Success means existing workflows still work

Implement owner-affine fleet execution, then prove the existing owner ingestion, SDK read, consent and ordinary Claude workflows against the actual deployed artifacts. Passing new unit tests or `/health` is not sufficient. Preserve stable MCP connections, owner keys/ciphertext, grants and all explicitly retained legacy paths. No new DRK, general autoscaling, mainnet rollout or global Lite removal.

## Baseline and source of truth

Reverify remote refs and live deployed versions before changing anything; these are known starting points, not permission to overwrite newer work:

| Repo            | Feature base                         | Known head / local evidence                                                        |
| --------------- | ------------------------------------ | ---------------------------------------------------------------------------------- |
| Personal Server | #245 `feat/enclave-primitives`       | `ca4c9b1`; deployed MCP runtime `a16fd5b`; `personal-server-mcp-tee-demo` worktree |
| Unity           | #987 `feat/account-enclave-delivery` | `7cb42e0f`; `unity-enclave-mcp-consent` worktree                                   |
| Gateway         | #100 `feat/identity-schema`          | `30d13db`; `data-gateway-fold` worktree                                            |
| Storage         | #24 `feat/job-result-objects`        | `093310df`; `vana-storage-revocation` worktree                                     |
| SDK             | Current job/identity feature state   | `fa015207`; `vana-sdk` worktree; verify actual published consumer pins             |

Proofs to preserve and repeat:

- [Fresh-owner onboarding, owner-signed Spotify v1 and SDK readback](../../e2e-proof-2026-09-08/fresh-owner/proof.md).
- [Existing-owner ingestion and version update](../../e2e-proof-2026-09-08/owner-ingestion/proof.md).
- [Consent without Lite](../../e2e-proof-2026-09-08/consent-no-lite/proof.md).
- [Ordinary Claude MCP and restart proof](../../personal-server-mcp-tee-demo/docs/260908-mcp-tee-demo-results.md).
- [Web MCP consent proof](../../e2e-proof-2026-09-08/mcp-consent/proof.md).
- [Storage delegation revocation controls](../../e2e-proof-2026-09-08/storage-revocation/proof.md).

The real baseline uses isolated preview Gateway/Storage and callback-compatible Web/Account/Lorebook aliases documented in those proofs. Do not infer environments from `dev` labels. Account preview OTP origin is not allowed; the prior fresh signup used ordinary Account dev before preview OAuth. Existing browser/Claude sessions may expire; verify access before unattended deployment.

## Preflight before dispatch and before infrastructure changes

1. Record exact repos, child/base refs, image digests, SDK pins, alias targets, DNS/TXT/CAA, CVM/app identities, node admission/drain state and recovery references. Never export secrets into the record.
2. Confirm usable Phala, DNS and preview-deployment access plus actual browser/Claude test sessions. Missing interactive authentication is a blocker for its E2E step, not a reason to claim a pass.
3. Run the current deployed happy paths below and capture baseline evidence before replacing anything. Existing failures are reported as baseline defects and bounded separately.
4. Enforce the authorized resource envelope: at most one Moksha controller plus two Moksha workers, reusing existing compatible resources where possible. The user's overnight approval supersedes the prior one-demo-CVM limit for this scoped run.
5. Record worker/controller sizes, maximum concurrent CVMs, test window and final keep/stop plan before provisioning. Mainnet stays untouched. Name resources per design §17; preserve worker app/key identity.

## Astra ownership and integration sequence

Root remains coordinator and serializes shared infrastructure/parent folds. Use Astra implementation agents with independent worktrees and explicit path ownership. Do not let multiple agents edit the same file or alias concurrently.

| Lane                  | Owns                                                                                                                           | First deliverable                                            |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------ |
| Controller/router     | PS central bootstrap, placement/capacity, protected state, router/peer adapter and state migration                             | Private contracts and placement state machine                |
| Gateway integration   | Assignment/enrollment transactions, private envelope retrieval, prewarm/admission delegation; necessary SDK compatibility only | Transaction boundaries and Gateway interfaces                |
| Worker and regression | PS local agent/registry/claim changes, peer execution/readiness; repeatable existing-flow test driver                          | Existing workflow baseline plus local assignment enforcement |

Before implementation diverges, agree a small checked-in interface contract for peer identities, assignment/enrollment transactions, sealed-envelope retrieval, execution connection material and readiness reports. Agents may resolve routine schemas within this architecture; no new user decision is needed for every field. A change to the agreed trust boundary, key contract or resource scope requires coordination before dependent changes.

Use the nearest owning repo's instructions and scripts. Personal Server uses npm; Unity follows its own package-manager instructions. Red/green one focused public-contract behavior at a time. Review against actual dependencies. Full applicable checks must pass before deployment. Parallelize local work; integrate shared contracts and deploy serially. After a lane completes, an available fresh Astra reviewer can independently challenge the integrated change and E2E evidence; its report cannot substitute for runtime proof.

## Existing-workflow regression matrix

Run before deployment and repeat after fleet integration unless a row explicitly describes a new fleet test. Record source/deployed refs, owner/grant/version/job IDs, expected result and observed result. Use public test data and authorized test owners. Do not log private keys, OAuth codes/tokens or raw unlock signatures.

| Flow                                   | Required oracle                                                                                                                                                                                        |
| -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| New owner onboarding                   | Normal signup/auth, explicit enclave enablement, correct stable owner identity, no accidental Lite registration. If a fresh login needs user action, mark pending.                                     |
| Owner ingestion without active sandbox | Public Spotify collection encrypts/uploads/registers successfully; independently recover persisted AddData owner signature; distinguish exactly one enclave registration from zero Lite registrations. |
| Existing owner update                  | Advance a controlled test version; prior ciphertext remains readable and new committed version is readable under requested policy. Failed upload/registration is not reported as synced.               |
| Web consent                            | Stored data approval and return from collection use durable metadata; no Lite boot/relay dependency. Unsealed/error path stays explicit, no silent legacy fallback.                                    |
| Builder/SDK read via Lorebook          | Complete actual consent and existing SDK job flow, direct encrypted result download, correct decoded data and consumer acknowledgment. Exercise warm and cold owner.                                   |
| Existing Claude connection             | Use the already-authorized connector after migration: same grant, no forced OAuth, all seven tools discovered, actual approved read.                                                                   |
| New Claude connection                  | Ordinary DCR/PKCE, Web owner approval, exact allowed scope, successful real tool call. Do not substitute hand-minted tokens.                                                                           |
| Browser-closed MCP                     | Close owner Web/Account/consent pages; evict sandbox; same connection wakes and reads without browser prewarm.                                                                                         |
| Controller restart                     | Same connection restored and worker affinity preserved; no OAuth replay, generation reset or duplicate sandbox.                                                                                        |
| Scope and tenant denial                | Ungranted scope rejected; second controlled owner cannot read first owner's data via routing/connection substitution.                                                                                  |
| Revocation                             | Preserve Storage owner/delegate controls and bounded revocation behavior; no stale placement bypasses grant/epoch checks. Use test identities only.                                                    |
| Retained legacy paths                  | Existing full-PS/Lite MCP and legacy direct-read routes retain applicable integration tests; run live smoke where prerequisites exist and label unavailable live coverage.                             |

Seven-tool discovery is not proof of all tool behaviors. Run deterministic granted fixtures for search, list blocks, selected-block read, access-request guidance and file/resource handling through the MCP transport; keep the ordinary Claude live read as the compatibility oracle. Do not expand public Spotify pilot source support solely to manufacture these fixtures. Use local/integration fixtures where live supported data is unavailable and label the level of proof.

Existing pending chain settlement, prior cold-prewarm retry, missing local QVL/CT audit and untested renewal are known limits. Do not relabel them as newly introduced regressions or silently claim they passed.

## Additional fleet E2E matrix

- Prewarm on A, then simultaneous MCP and SDK work: same placement/generation/container on A, none on B.
- Concurrent first MCP/prewarm/job: one startup and no generic-claim theft during fleet enrollment.
- New scope or new committed data while A is warm: scoped hydration/readiness, no duplicate owner on B.
- MCP-only cold wake on B with empty local envelope cache, no queued job and no browser.
- Drain A normally; next call cold-starts B on the same Claude connection.
- Fail/partition A: B starts only under a newer valid generation; obsolete responses/commits rejected. Use a safe controllable fault, not unrelated network/service changes.
- Restart worker agent: incarnation changes and stale local authorization cannot reclaim work.
- Router/controller state migration to separate app: owner identities unchanged, connections preserved, no secret export to operator host.
- Rollback rehearsal: restore an approved working deployment without dual writers, duplicate placement or Lite re-registration; then return to the selected tested candidate.

A local two-agent simulation is required but does not count as live multi-TEE proof. Do not rename one CVM and present it as two workers. Use correlation metadata and real node/container identities to demonstrate affinity.

## Deployment, stop conditions and completion

Keep the working baseline available until reviewed artifacts and the migration/rollback plan are concrete. Stage the controller and workers without cutting over existing connections; verify admission/channel identity, then serialize the authorized alias/DNS/state cutover. Do not run two writers against the ingress connection store. Do not replace resources merely to satisfy naming: rename labels safely where supported and keep immutable identities recorded.

On a regression, stop further rollout, preserve evidence and restore the last verified service where safe. Continue local diagnosis/review independently. Stop the dependent step on credential/interactive-login failure, unexpected production backing resource, unapproved spend, KMS identity drift, peer validation failure or inability to restore protected state. Missing E2E is pending, never passed. No main/dev merges or production release are included.

Completion requires: exact tested refs/artifacts, applicable checks and review, before/after matrix with no unexplained regressions, new fleet proof, migration/rollback evidence, appropriately named CVMs and final resource inventory. Record nonfatal known limitations separately. Only then fold children into their immediate feature-base PRs with root-serialized exact-ref checks and resulting parent verification. A draft PR or successful unit suite alone is not completion.

Progress reports should cover code/check milestones, baseline results, infrastructure/cutover, actual browser/MCP results, failures and recovery, final proof and cost/resource state. Do not wait until morning to surface a blocker that needs the user. No indefinite monitoring or unattended paid provisioning is implied by this document.
