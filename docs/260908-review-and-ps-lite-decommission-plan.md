# Enclave review response and PS Lite decommission plan

Date: 2026-09-08  
Status: scoped Web ingestion/Spotify consent folded; single-TEE Claude MCP demo proven; DRK redesign deferred and migration gate open  
Documentation branch: `codex/personal-server-architecture`

## Start here

This is the continuation entry point for the six-repository Personal Server enclave effort. It records the reviewed state, review corrections, proposed work, dependencies, and user constraints. Read it before resuming implementation or rollout.

The user authorized documentation of the review and **PS Lite decommissioning plan on a stack based on Unity #987**, then separately authorized narrow implementation slices. Enclave DCR completion is implemented in [Unity #1029](https://github.com/vana-com/unity-surfaces/pull/1029), with a fresh Spotify browser happy path now passing alongside the URL-less return fix in [Lorebook #2](https://github.com/vana-com/lorebook/pull/2), stacked on #1. Following preview E2E verification, Unity #1029 and malformed signing-body validation in [Unity #1030](https://github.com/vana-com/unity-surfaces/pull/1030) were folded into #987; Lorebook #2 was folded into #1. Unity #987 was verified at `095b2cb160676c513b95c88b6e9eb55d2ae08de4`; #1030 passed 16/16 malformed-body cases and the happy flow. These are base-PR folds only, not merges to main/dev or rollout/retirement certification. MCP migration remains a retirement gate. The user has deferred the random DRK/wrapping/rotation redesign (Claude A1); this decision supersedes the historical open proposal. Other architecture decisions remain open; this document does not authorize additional implementation.

The [Lite retirement launch checklist](260908-lite-retirement-launch-gates.md) tracks owners, status, evidence and exit criteria. The scoped owner-authorized public Spotify ingestion and fresh-owner readback are proven, including normal explicit enclave enablement; [Gate 1 evidence](../../e2e-proof-2026-09-08/fresh-owner/proof.md) records the exact deployments and limits. Selected enclave consent without Lite boot, relay readiness or Lite-backed grant-version lookup is also proven in [Unity #1032](https://github.com/vana-com/unity-surfaces/pull/1032), folded into #987 at `7861e740ff2c8e280e64c888a91a4505da7a7b45`; [Gate 2 proof](../../e2e-proof-2026-09-08/consent-no-lite/proof.md) records live fresh-owner Spotify consent/readback and component-only unsealed/source-return negatives. Derivative questions are explicitly unsupported on this enclave path. These narrow slices do not certify global Lite retirement, MCP migration, native parity or production release. The separately authorized single-TEE MCP demo now proves real Claude OAuth, seven-tool discovery and Spotify reads after closing owner pages, sandbox eviction and a full CVM restart. Unity #1033 folded into #987 at exact tested `7cb42e0f0b4af29c60c7c11170a3da2501a2d1a1`, with all eight resulting parent checks passing. PS #272 retains deployed runtime `a16fd5b`; its owning agent tracks the PS fold. [MCP server/TLS report](../../personal-server-mcp-tee-demo/docs/260908-mcp-tee-demo-results.md) and [Web approval proof](../../e2e-proof-2026-09-08/mcp-consent/proof.md) record exact artifacts and limits; full migration remains open.

### Review archive

- [Claude's complete supplied review](reviews/260908-claude-enclave-review.md): A1–A6 and B1–B14 are the identifiers used below. Preserve the distinction between its findings and new design proposals.
- [Initial Codex review](reviews/260908-codex-enclave-review.md): targeted Standards and Spec findings, repository baselines, and initial ingestion dependency map.
- [Reconciliation and corrections](reviews/260908-enclave-review-reconciliation.md): source-checked agreement, qualifications, and the smaller independent DCR fix.
- [Architecture](260901-personal-server-gateway-enclave-architecture.md), [identity contract](260902-identity-contract.md), [result delivery](260904-result-delivery-plan.md), [production plan](260906-production-plan.md), [cold-start results](260906-cold-start-results.md), [spike results](260902-enclave-spike-results.md).
- [September 7 Slack status](https://vana-org.slack.com/archives/C07JYF0U8BY/p1788756922229679) and [earlier architecture review](https://vana-org.slack.com/archives/C07JYF0U8BY/p1788320370525709).

Original operational handoff: `/Users/kahtaf/Documents/workspace_vana/personal-server-ts-enclave/HANDOFF-CODEX-2026-09-08.md`. Its backup, earlier Opus reviews, measurement reports, screenshots, and videos are under `/Users/kahtaf/Documents/workspace_vana/e2e-proof-2026-09-04/`. The dated handoff is authoritative over the older untracked `HANDOFF.md`; the old file was not removed.

## Current state and constraints

### Reviewed stack

All six PRs were rechecked on September 8 at the following review baselines; subsequent base-PR folds are recorded above. Review was targeted source inspection, not an exhaustive audit or fresh runtime certification.

| Repository / PR                                                                    | Target | Reviewed head                              | Scope                                                        |
| ---------------------------------------------------------------------------------- | ------ | ------------------------------------------ | ------------------------------------------------------------ |
| [personal-server-ts #245](https://github.com/vana-com/personal-server-ts/pull/245) | main   | `2f1915b076abda9931189e4d3aa6127e32f42986` | Agent, sandbox, jobs, streaming results, prewarm, deployment |
| [vana-sdk #211](https://github.com/vana-com/vana-sdk/pull/211)                     | main   | `fa0152075367d87680d4803af36fafb460c6802a` | Jobs protocol/client and result encryption                   |
| [data-gateway #100](https://github.com/vana-com/data-gateway/pull/100)             | main   | `30d13db97a742325305d98ea32b05305b6555362` | Identity, jobs, nodes, prewarm, migrations                   |
| [vana-storage #24](https://github.com/vana-com/vana-storage/pull/24)               | dev    | `f442653f5bf6d99e063fa6af358f35cc628af2d3` | Create-only job-result objects                               |
| [unity-surfaces #987](https://github.com/vana-com/unity-surfaces/pull/987)         | dev    | `bd8f2fe6226c9ecc8295416549734c021d1c8ec0` | Account signing, consent, enclave delivery, prewarm          |
| [lorebook #1](https://github.com/vana-com/lorebook/pull/1)                         | main   | `ff49c73ec7b3cfb51c9252f57954d0ab3ef9531f` | Builder demo and resumable enclave reads                     |

Children PS #265–#268, Gateway #111, and Unity #1005 were folded into the parents. Parent PR bodies do not all describe their final scope. Verify the current head and actual base before future work; do not assume every PR targets main.

The implementation worktree `/Users/kahtaf/Documents/workspace_vana/unity-surfaces-retire-lite`, branch `feat/retire-ps-lite`, started from Unity head `bd8f2fe6`; the separately authorized DCR slice now lives on that stack. The six heads above remain the review baseline, not a claim that subsequent implementation and verification have not occurred. The MCP addition here changes documentation only.

Three persistent Astra agents explored Standards, Spec/runtime contracts, and Unity/consent flows. Their recoverable findings are archived here; continuation must not depend on agent memory.

### Operational baseline — reported, not freshly probed

The dated handoff reports a working testnet preview on the spike Gateway, Lorebook/Web/Account previews, and one admitted enclave node `spike-b3-f1` at `2f1915b` (CVM prefix `87c32ca4`, Phala app prefix `ec9a39de`). Another CVM was stopped. Do not infer current health from this record.

Reported performance: approval-to-portrait about 60 → 32 seconds; sandbox boot 10–14 → 5–6 seconds; cold job with a 15-second prewarm lead 22.5 → 3.5 seconds; CVM deployment about 10–15 → 3 minutes. These are different scenarios, with contention and warm-cache caveats. The cold-start document contains the measurements.

### Hard constraints

- Keep implementation within separately authorized slices. Documentation, including the MCP gate, does not authorize additional code changes.
- No merge to main/dev without Kahtaf's explicit go. Never touch production, including production Web/Account deployments, the production Storage bucket, mainnet databases, Gateway, or CVMs.
- Secrets must come from the macOS keychain inline per command; never export them or write them to files. No secret values belong in this documentation.
- Every Personal Server change must pass root `npm run build`; never roll a CVM to a ref whose build was not verified locally.
- Keep exactly **one running CVM per Phala app ID**. The older runbook recommendation for two simultaneous nodes conflicts with the newer handoff and must not be executed as written.
- Nominally Moksha runbook steps that touch production services remain forbidden under the no-production rule.
- Keep `packages/lite` until the enclave serves real users and its remaining consumers have migrated. The MCP gate below applies before disabling registration, onboarding, relay, or runtime behavior needed by existing MCP clients—not only before package deletion.

## Review conclusions to carry forward

Implemented primitives include owner/builder signature recovery in the raw-read worker, sealing, sandbox isolation, object-before-completion delivery, and create-only results. This does **not** establish the complete refuse-only Gateway or revocation guarantee.

1. **Lite retirement blocker is scoped.** Removing all Lite registration breaks uploads and native login today. However, enclave DCR completion can independently stop requiring a Lite URL. At the reviewed #987 head it waits for routing, requires `ps_url`, and then discards that URL; #1029 addresses this independent coupling. The enclave completion branch already skips reachability probing.
2. **Version enforcement is a concrete defect.** Gateway pins version N at admission, but execution does not enforce that pin. A subsequent N+1 upload can be returned while job status advertises N. Historical-version hydration is also missing.
3. **Result fetching needs destination controls.** Arbitrary HTTP(S) handles, redirects, and buffering occur before integrity checks. Encryption does not prevent unintended backend network access or resource exhaustion.
4. **Registration, retirement, and liveness remain Gateway-dependent.** The worker trusts its own unsigned registration row; grant revocation uses Gateway state; the agent trusts an optional caller-provided minimum epoch. Fresh job-handle retrieval also does not recheck revocation.
5. **Delegate minting has a narrower consequence than the review suggests.** Gateway accepts registered-server-signed grants, but this enclave raw-read verifier rejects grants not signed by the owner. Do not describe delegate minting alone as a bypass of that verifier.
6. **Account sees the plaintext master signature.** This is explicitly described in the identity contract, not a newly discovered implementation departure. Browser ciphertext-only delivery is not an Account confidentiality guarantee.
7. **Random DRK/wrapping/rotation redesign is deferred by user decision.** It is not a controlled-pilot or first-production-release gate, or a prerequisite for owner ingestion under the current exact-signature-derived key contract. V1 retains its no-data-key-rotation limitation. Two-factor wrapping, strict RPC failure closure and KMS-mode changes remain proposals; Phala off-chain KMS was already a recorded choice.
8. **Other corrections matter.** Ready means sealed plus confirmed/finalized, not hydrated. Signature counts vary by operation/cache. Some identity requests short-circuit. Agent control authority is already trusted authority. Mixed SDK versions need compatibility proof, not an assumption of failure.

The reconciliation contains exact source references and additional qualifications. Section B's "code-only" classification is a cost classification: several B items can still block mainnet.

## Dependency-ordered work plan

### Phase 1 — Ratify the release contract

Record the chosen threat model and separate implemented, launch-required, and deferred guarantees. Keep malicious Gateway, compromised operator credentials, compromised trusted agent, and ordinary crashes distinct.

| Decision                                   | Required outcome                                                                                                                                                                                   | Review IDs  |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| Data root and recovery — deferred redesign | Retain the exact-signature-derived v1 key contract and its no-data-key-rotation limitation. Random DRK/wrapping/rotation redesign is deferred, not a pilot, first-release or owner-ingestion gate. | A1          |
| Account authority and consent              | Accept or change server-side signing authority; accurate plaintext/revocation claims; permission for later prewarm signing; product sign-off on the June reversal.                                 | A4, A6, B12 |
| Identity lifecycle                         | KMS mode; V3 timing or explicit V2 bridge; revoke/re-enable; fleet-wide retirement authority, freshness, ordering, backup rollback, and partition behavior.                                        | A2, A5, B4  |
| Authorization timing                       | Checks before hydration versus before release; in-flight revocation behavior; RPC failure and bounded fallback policy.                                                                             | B2, B3      |
| Builder contract                           | Signed pricing consent; routing metadata; evidence verifier; claim types; version selection, retention, and unavailable-version behavior.                                                          | A3, B8, B13 |
| Fleet provenance                           | Executable/image/configuration inputs covered by evidence, authorized measurement-policy signer, upgrades and rollback rules.                                                                      | B6, B7      |

The deferral does not approve a cryptographic migration or reject DRK permanently. Revisit the proposal when planning broad adoption or when product requirements call for key rotation; no new deadline is imposed. Current signing/key authority limitations remain explicit: v1 offers neither cryptographic erasure of copied roots nor recovery from a compromised root through rewrapping. Owner-ingestion work can use the current contract without resolving the deferred redesign.

Future DRK proposal guardrails: rewrapping preserves an uncompromised DRK; it cannot revoke copied roots or old wrappers paired with old keys. Backup retention does not bound attacker-held copies. Changing the signed message is not protection against a compromised wallet signer. Two independent wraps mean either-key access; both-factor access needs an explicit construction and independent authorization. Existing ciphertext derives from exact 65-byte signature material; a new 32-byte DRK requires versioned formats and migration. Separate owner authentication from key material. Browser-side code placement alone does not make signing authority independent.

### Phase 2 — Independent fixes and review hygiene

The first two slices have separate implementation authorization and PRs as recorded above. Remaining slices are proposed; listing them here does not authorize implementation.

| Slice                               | Owner / stack                         | Acceptance proof                                                                                                                                                                                                               |
| ----------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Enclave completion without Lite URL | Unity Web, child of #987              | Route succeeds without `ps_url`; client skips routing calls/retries after an enclave grant. Preserve owner/session, grant, builder, scope, sealed-identity checks and legacy URL requirements.                                 |
| Malformed signing request bodies    | Unity Account, separate child of #987 | Authenticated null/array/primitive bodies return structured 400; valid signing is unchanged.                                                                                                                                   |
| Result fetch containment            | SDK #211, then consumers              | Trusted origins independent of handle contents; constrained redirects; HTTPS outside explicit local development; bounded bytes/time before full buffering; integrity/binding checks afterward. Test injected fetch middleware. |
| Claim type alignment                | SDK → Gateway → enclave               | Consistent chain ID contract, cross-chain rejection and shared wire fixtures.                                                                                                                                                  |
| Public API/ownership cleanup        | SDK and PS                            | Document streaming deferred errors and full consumption; share core-owned disclosure policy without changing redaction behavior; retain parity proof.                                                                          |
| Review hygiene                      | All six repos and docs                | PR descriptions cover final diffs; actual SDK compatibility matrix; accurate provenance/readiness claims; reconcile historical docs and checked-in reports.                                                                    |

Coverage: B5, B8, B14, parts of A3, and earlier Standards findings.

### Phase 3 — Trust, lifecycle, and execution

| Package                            | Owners                                    | Required proof                                                                                                                                                                                                                                                                                                                                           |
| ---------------------------------- | ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Registration and retirement        | Gateway/enclave, SDK/contracts as needed  | Verify owner registration; reject registration/delivery replay; enforce retired epochs across derivation, seal, unseal, prewarm and execution. Test restarts, concurrent revoke/re-enable, stale state and backup restoration against the approved retirement authority. A local counter or Gateway-supplied floor alone is insufficient.                |
| Grant authorization and revocation | Gateway/core/server                       | Refuse enclave-delegate grants at admission; preserve owner-only worker verification. Test revoke during hydration/execution/upload; prevent fresh result-handle release after the agreed boundary. State limitations for already-disclosed public URLs and plaintext.                                                                                   |
| Prewarm authorization              | Gateway/enclave                           | Verify the selected evidence before the approved plaintext boundary; cover owner-triggered and grant-triggered paths, replay, expiry, and wrong-owner inputs.                                                                                                                                                                                            |
| Version enforcement                | Gateway/enclave/server/SDK                | Admit N, ingest N+1, execute/retry: return N or the specified error, never silently N+1 under N metadata. Resolve request/admission disagreement without rewriting signed payloads. Cover tombstones, cold/warm execution and missing versions.                                                                                                          |
| Builder read contract              | SDK/Gateway, Unity DCR/Lorebook consumers | Apply approved evidence verification before request encryption/submission; reject wrong owner/key/chain/anchor/measurement. Implement agreed signed pricing and routing metadata, preserve free-only legacy compatibility, and expose the intended single SDK read entry point. Test mixed clients and routing fallback; reduce demo-only protocol glue. |
| Storage delegation                 | Storage/Gateway                           | Revoke blocks ordinary and result writes under the agreed freshness policy, including fresh lookups after cache expiry. Preserve direct-owner writes, cross-chain boundaries and create-only results.                                                                                                                                                    |
| Provenance and admission           | Deployment/enclave/Gateway                | Validate challenge and evidence against approved executable/configuration policy; reject wrong app, code, digest, stale challenge or policy rollback. Align update defaults, debug modes and logs with the policy.                                                                                                                                       |
| Rate limits and receipts           | Gateway                                   | Bound expensive fresh-identity, invalid-secret, prewarm and builder-job work. Exactly one successful receipt per committed result; no successful receipt for failed/orphan work and no duplicates on retry.                                                                                                                                              |

Coverage: A2, A5, B1–B4, B6–B11, B13, and post-revocation result-handle retrieval. Signed price/payer decisions precede paid-job implementation; missing signed terms never authorize charging an old free client.

**Deferred future key-migration package (A1):** excluded from the current pilot, first-production-release and owner-ingestion prerequisites. Only if separately revisited and approved, implement it in SDK/key contracts first, then Personal Server readers/writers, Account authority, and ingestion clients. Separate owner authentication from root material; define authenticated owner/epoch/wrapper context, downgrade protection, legacy epoch handling, resumable migration and offline-writer behavior. Test wrong-owner/wrong-epoch wrappers, interruption at each migration stage, wrapping-key rotation, DRK-compromise rotation, and the selected recovery path. Never present legacy epoch-zero wrapping as revocation of the old signature. This package remains deferred, with no implementation authorization. Reflect the retained v1 limitations in launch claims and consent; deferral does not provide data-key rotation, cryptographic erasure or compromised-root recovery.

### Phase 4 — Replace Lite's ingestion dependency

Baseline blockers identified before the authorized slices: Web registered before sync, and Lite sync used its registered identity for Storage/AddData/deletion/lineage signing. The scoped public Spotify owner-ingestion path and selected enclave consent dependency removal now pass Gates 1 and 2. Broader scopes, Mobile registration/sync and native relay readiness remain separate work.

Gateway already accepts owner-signed AddData; Storage already accepts direct-owner Web3Signed requests. The scoped Web/Account owner-ingestion adapters are implemented; broader ingestion and native adapters remain incomplete. The enclave public identity is not a substitute for a private signer.

1. Define owner-authorized ingestion using existing protocol primitives and the current exact-signature-derived v1 key contract. Preserve encryption compatibility, upload-before-registration, version commitments, retries, deletion and interrupted uploads. Avoid copying protocol logic into surfaces.
2. Add narrow Account and native authorization transports. Specify external-wallet prompts, cancellation, wallet mismatch, expiry and policy compatibility. Do not silently broaden signing privileges.
3. Replace Web source-write and Mobile connector upload adapters while preserving local inspection/deletion. Prove a fresh owner with **no registered Lite server** can collect, encrypt, upload, register a data point, and read it back through the enclave.
4. Replace remaining DCR dependencies: durable scope/source readiness, grant-version lookup and derivative-question registration. Prove approval of already-stored data without a browser runtime or relay. Unsupported derivative behavior needs an explicit scope decision, not a silent fallback.

SDK/core own reusable protocol behavior; Account owns signing authority; Unity owns surface/native integration. Keep these in distinct owning stacks rather than hiding them inside a nominal Web cleanup. The deferred DRK redesign does not block this ingestion layer. Preserve current ciphertext/key compatibility; a future separately approved migration would require its own versioned contract and compatibility plan.

### Phase 4B — Migrate MCP before removing its Lite dependencies

The proposed [TEE fleet controller design](260908-tee-fleet-controller-design.md) defines central routing/controller ownership, local worker-agent changes, placement and the existing read/write/MCP workflows. It is documentation only and does not claim fleet implementation or authorize multi-CVM deployment.

**Hard retirement gate:** do not disable automatic Lite registration or relay-dependent onboarding for MCP users, retire their registrations, remove relay/runtime adapters, or delete `packages/lite` until the replacement MCP path and legacy-client migration pass the acceptance checks below. DCR completion without a Lite URL and owner-ingestion parity do not satisfy this gate. Preserve a deliberately gated legacy MCP path while migration is incomplete.

**Reviewed legacy baseline:** Web obtains its MCP endpoint from the booted Lite server's public relay URL and performs connection/authorization management through its local handle ([Web authorization hook](<../../unity-surfaces-retire-lite/apps/web/src/app/(app-shell)/(with-nav)/(main)/mcp/hooks/use-mcp-authorization.ts>), [Web PS session](../../unity-surfaces-retire-lite/apps/web/src/features/personal-server/web-personal-server-session.ts)). MCP itself is not Lite-specific: [full PS mounts MCP/OAuth routes](../../personal-server-ts-enclave/packages/server/src/app.ts), and Desktop supplies an MCP approval callback. Existing MCP tools use per-connection grantee keys and bounded block/search reads ([read client](../../personal-server-ts-enclave/packages/core/src/mcp/read-client.ts), [tool catalog](../../personal-server-ts-enclave/packages/core/src/mcp/tools.ts)). The reviewed enclave worker supports only `raw_read`; it is not a replacement for this MCP protocol and tool surface. No hosted MCP router was found in Gateway #100. Existing MCP code inside the PS image does not make a durable, publicly reachable enclave MCP service available.

**Current scoped demo:** the authorized fixed endpoint `https://mcp-dev.vana.org/mcp` terminates TLS and MCP inside the existing TEE, reuses existing MCP tools, and persists per-connection authorization state encrypted inside the CVM. Unity's explicit demo selector performs owner-approved grant creation and direct TEE approval without Lite boot. Actual Claude OAuth, discovery, browser-closed reads, sandbox recreation and a repeated read after full CVM restart passed. This bounded demo preserves the legacy MCP route; it does not complete the migration matrix below. [Exact runtime and TLS evidence](../../personal-server-mcp-tee-demo/docs/260908-mcp-tee-demo-results.md). CT history lookup failed, local QVL and accelerated renewal were not exercised, and fleet failover, rollback-resistant state and resumable streams remain outside scope.

**Decisions before broader migration:** choose a stable endpoint and routing topology, ownership of OAuth clients/authorizations/sessions/tokens and per-connection grantee keys, and their protected persistence across idle teardown, sandbox replacement and restarts. Keep owner consent, owner-signed grants, revocation and per-client/owner isolation explicit. Preserve Gateway blindness: terminate MCP plaintext inside the TEE or an explicitly approved trusted client bridge; do not quietly decrypt tool results at the Gateway. Specify cold-start behavior, streaming transport, timeouts, cancellation/reconnect and session continuity. Extending the enclave job protocol versus forwarding MCP to an enclave handler is an open design choice, not an approved architecture.

Proposed delivery sequence:

1. Inventory clients, URLs, OAuth flows, grants and tools; reuse existing MCP tool/authentication code where compatible. Assign reusable behavior to PS/core, protected lifecycle to the enclave/control plane, and consent/endpoint presentation to Unity/Account.
2. Establish the stable transport and durable connection state; prove grant-scoped discovery and bounded scope/block reads without a browser runtime. Do not substitute full raw-scope downloads for bounded tool semantics.
3. Add access-request/approval, search and file-tool parity. Any omitted tool or derivative behavior requires an explicit supported-scope decision and a visible unsupported response.
4. Switch Web's MCP endpoint and connection/consent UI to the replacement. Exercise new-client setup and existing-client migration before removing the legacy endpoint.
5. Migrate or explicitly retire old relay URLs, tokens and clients under the approved compatibility policy. Only then remove the corresponding registration, onboarding, relay and runtime dependencies in Phase 5.

Acceptance proof:

- With the Vana Web tab closed, a fresh MCP session can connect and read; a new client can complete owner consent and OAuth setup, then operate after that consent surface closes. OAuth refresh must work without a resident browser PS.
- Cold start, idle teardown and sandbox replacement preserve approved connection/session behavior; streaming, timeout, cancellation and reconnect follow the selected contract.
- Clients and owners cannot read one another's scopes, keys or sessions. Revocation blocks active/in-flight reads, future calls and token refresh at the agreed boundary; retained credentials cannot revive a revoked grant.
- Discovery, bounded scope/block reads, search, files and access requests meet the approved tool matrix, including any explicit unsupported capabilities.
- Old endpoint/client migration is demonstrated, including stale clients and rollback. No removal silently strands existing clients or re-registers a retired Lite server.

The bounded single-TEE demo is implemented and proven for the cases above. The remaining matrix is a release gate; it does not authorize broader deployment or certify old-client migration.

### Phase 5 — Complete Lite retirement and product flows

After replacement ingestion, DCR proof, and the Phase 4B MCP gate for every affected caller:

1. Remove automatic Web/mobile Lite registration and relay-dependent onboarding only after ingestion and affected MCP clients no longer depend on them. Never fake a successful registration to bypass sync checks.
2. Retire existing Lite registrations through the approved owner-authorized migration. Test users who never reopen the old client and stale-client attempts to re-register.
3. Implement revoke/re-enable controls only after lifecycle proof; include failure/retry and consent states.
4. Complete external-wallet support and separate registration/sealing from data readiness. Consolidate the duplicate Personal Server presentation.
5. Remove unused relay/runtime adapters after caller inventory and MCP migration proof. Lite may temporarily remain local storage only if upload authorization, readiness and MCP serving no longer depend on its server identity.
6. Retire the legacy SDK `vana.account.v1:ps-lite-owner:<address>` binding with its last consumer. Preserve active `vana-master-key-v1` while existing encryption/delivery relies on it; no literal `personal-server-lite/` message was found in active Unity code.
7. Delete `packages/lite` only after the enclave serves real users and compatibility consumers are migrated.

During transition, legacy behavior stays explicitly gated. Once enclave delivery is selected, an error stays on that path instead of silently changing delivery. After migration, rollback must not silently re-register Lite or rewrite stored data. Preserve compatible ciphertext and identifiers; disable unsupported actions explicitly where necessary.

Coverage: A2, A4, A6, B5, B12 and the handoff's decommission scope.

### Phase 6 — Validation and rollout preparation

For each authorized slice: write one focused public-contract regression, observe the expected failure, implement the smallest change, then run relevant checks. Use actual package scripts and local binaries. Personal Server uses npm and requires root build; Unity uses its pnpm/package-local workflow and owning AGENTS.md instructions.

Cross-repo gates:

- Fresh-owner ingestion and enclave readback with no Lite registration.
- Enclave DCR completion without a relay, while legacy paths retain required checks during transition.
- The Phase 4B MCP matrix: browser-closed operation, new-client consent/OAuth and refresh, cold start/replacement, isolation, revocation, tool parity and legacy endpoint migration before any change that would break existing MCP clients.
- Cold/warm reads, admission-version races, tombstones and interrupted jobs.
- Revocation during active work, no fresh post-revoke handle, and revoke/re-enable.
- External-wallet consent and native Mobile onboarding; inspect actual affected Web/Account routes and Mobile at 390×844.
- Interrupted key migration/rotation and old-client compatibility only for a future separately approved DRK migration; these are not current pilot, first-release or owner-ingestion gates.
- Independent review of changed trust boundaries, final PR descriptions and cross-package release-artifact compatibility.

### Authorized subagent closeout

A draft PR is an intermediate checkpoint, not completion. For each authorized item, the owning subagent carries the work through a preview deployment and meaningful end-to-end verification as prerequisites allow, then records the exact tested ref, checks/review results, proof and limitations. Missing or unavailable E2E is not a pass: report the concrete blocker and continue independent work that remains possible.

Only after E2E is proven and the required checks and review pass should the subagent fold the change into its **immediate base PR branch**. Verify the current child head, parent PR/base branch and current parent ref before folding; serialize updates to a shared parent branch so parallel subagents cannot overwrite or absorb each other's work. Recheck the resulting parent state. A fold into an intermediate feature branch never authorizes a merge to `main` or `dev`, or any production action.

Current application: Unity **#1029 → #987** and **#1030 → #987**; the related Lorebook change follows the same rule, **#2 → #1**. These folds are complete following the verified preview E2E closeout recorded above; they did not merge either base PR to main/dev. Preserve the evidence for each child when reporting the resulting parent ref.

The root agent remains orchestration-only and available for user questions; subagents own implementation, preview deployment and browser verification within their authorized scope. This workflow does not authorize new features or override the production and runtime constraints above.

For broader rollout, prepare—not execute—the SDK releases and re-pins, trust anchors, migration inventory, policies and isolated testnet verification unless separately authorized. The preview closeout rule above applies to already authorized slices. Preserve the production-plan dependencies: SDK release #1 → consumers/image → provisioned fleet anchors → SDK release #2. Reconcile Gateway backlog 0048–0051 with actual ledgers before later migrations; resolve Account manifest/026–027 ordering, Storage Moksha URL configuration and job-result retention, and the unconditional Mobile Privy policy requirement. Mainnet remains gated on the selected launch contract and user approvals.

No deployment may use an unverified ref. No live multi-node experiment may violate the one-running-CVM-per-app rule. No testnet label overrides the ban on production resources.

## State after autoscale (2026-09-11)

Preview only; nothing merged to dev/main. The single-CVM demo is now a fleet: 1 controller + 4 signed workers (2 pinned tdx.small, 2 stopped tdx.medium) with an external start/stop loop, digest-pinned images and no daily re-signing. Results and receipts: [autoscale closeout](260910-autoscale-closeout.md).

| Phase                           | Movement                                                                                                                                                                                                                                                         |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 3 — Trust, lifecycle, execution | Signed bundles no longer expire; worker kill mid-job, two-owner isolation and enclave revoke/re-enable are proven. Storage revoked-delegation fix is draft #26, unmerged.                                                                                        |
| 4B — MCP                        | Browser-closed reads, cold wake, controller restart under a live connection and a 24 h token TTL are proven. Per-connection revoke, OAuth refresh, streaming/reconnect, tool parity and old-client migration remain open — the hard retirement gate still holds. |
| 5 — Lite retirement             | Existing-user migration is descoped (Kahtaf 09-10: no users, no data). Functional removal still precedes `packages/lite` deletion and relay teardown.                                                                                                            |
| 6 — Validation and rollout      | Not proven on any canonical target; no monitoring or rollback evidence.                                                                                                                                                                                          |

Gate-by-gate status, evidence paths and the numbered start order for the next task ("productionize the TEE path, remove PS Lite") are in the [launch gates](260908-lite-retirement-launch-gates.md#state-after-autoscale-2026-09-11).

## Next continuation

The separately authorized #1029, #1030, owner-ingestion #1031/PS #271, consent #1032 and Lorebook #2 slices completed their scoped preview E2E closeout and were folded into their immediate base PRs. Preserve their proof and verify current parent refs before new work; those completed slices do not certify broader metadata behavior, tool parity or rollout. Keep the random DRK/wrapping/rotation redesign deferred: use the current exact-signature-derived v1 contract for any separately authorized owner-ingestion work, retain its stated limitations, and do not reopen A1 as a pilot or first-production-release prerequisite. MCP migration remains a separate retirement gate. The single-TEE demo now proves real Claude OAuth and reads across closed owner pages, sandbox replacement and a full CVM restart; close its serialized child-to-parent folds with exact proof before expanding scope. Resolve remaining refresh, streaming, fleet and old-client compatibility checks alongside mainnet trust decisions before scheduling retirement. Keep optimizations such as earlier prewarm, approve-to-submit latency, caching and additional boot work as separate measured follow-ups; they must not obscure correctness and lifecycle gates.
