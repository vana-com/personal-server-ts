> Archive note (2026-09-08): Source-based reconciliation of the Claude review. Implementation suggestions remain proposals. The user subsequently requested planning only; no implementation is authorized by this document.
>
> Current index and plan: [Review response and PS Lite decommission plan](../260908-review-and-ps-lite-decommission-plan.md).

# Reconciliation of Claude's six-PR feedback — 2026-09-08

All six current GitHub heads still match the supplied review: PS `2f1915b`, SDK `fa01520`, Gateway `30d13db`, Storage `f442653`, Unity `bd8f2fe6`, Lorebook `ff49c73`. All remain open. This reconciliation combines direct source inspection with the three persistent Astra reviewers. It does not represent a fresh runtime test, exhaustive audit, approval to merge, or approval of proposed architecture changes. No source implementation or deployment was changed.

## Overall assessment

The notes are a useful inventory of launch gaps. Their introductory trust-core statement needs a qualification: grant/builder signature recovery, sealing, and sandbox isolation primitives are present, but independent registration liveness, retirement, code-provenance enforcement, and several user-facing requirements remain incomplete. Cost of change and release criticality are separate axes: several section B items can block a mainnet release even though their fixes are code-only.

## New concrete findings to prioritize

### B5: remove the unnecessary Lite URL gate from enclave completion

The Web DCR flow calls `waitForRequiredCompletionRouting` after an enclave grant (`unity-surfaces-fold/apps/web/src/app/(app-shell)/(with-nav)/(main)/data-connection-requests/[id]/use-data-connection-request-flow.ts:1340`). The completion route requires `ps_url` at line 127 and then discards it in the enclave branch at line 583. That branch already skips reachability probing, so "requires a relay-reachable server" overstates its server-side validation.

This is a safe narrower slice on #987:

1. Prove the authenticated completion route accepts enclave delivery without `ps_url`, retaining grant, builder, scope, owner, session, and sealed-identity validation.
2. Keep the existing URL requirement for legacy delivery only.
3. Prove a successful enclave grant completes without calling or retrying Lite routing, using the already-resolved owner address.
4. Retain legacy/fallback tests and the existing URL-less durable enclave response.

**Correction to the earlier decommission assessment:** the missing owner-ingestion adapters block global Lite registration/runtime removal, not this completion-tail fix. It does not yet make the entire DCR flow independent of Lite: the provider, reconnect, source readiness, grant-version lookup, and derivative question registration still use it. Full retirement remains a separate migration.

### B13: admission's pinned version is not enforced at execution

Claude's explanation that Gateway does not pin is incorrect. `data-gateway-fold/api/v1/jobs.ts:125` stores `admission.pinnedVersion`. However, `personal-server-ts-enclave/packages/enclave/src/jobs/run.ts:821` does not bind it to the decrypted request, and the worker enforces only the request's `pinnedVersion`, normally null.

Concrete case: admission records N; a new upload creates N+1 before execution; the job can return N+1 while status still advertises N. Historical-version hydration is also missing. Decide whether a raced job should serve N or fail/retry under an explicitly revised contract, then test that behavior through the job path.

### B8: result URL validation has a network-destination risk

`vana-sdk/packages/vana-sdk/src/protocol/jobs-client.ts:454` accepts arbitrary HTTP(S) result URLs. At line 799, `openResult` fetches that destination and buffers the response before checking the claimed size and hash. Default fetch behavior follows redirects. Encryption does not prevent unintended backend network access or resource exhaustion from this fetch. Define trusted origin/redirect policy, HTTPS requirements, and response bounds; test them before relying on a refuse-only Gateway claim.

## Confirmed trust and product gaps

- **B2/B4:** own registration and revocation still rely on Gateway state; the agent has no independent retired-epoch floor. These confirm the earlier review. Requiring strict RPC failure closure also changes the draft's permitted five-minute Gateway fallback, so record that choice.
- **A2/A4:** the revoke button is disabled with a no-op action. Revoke/re-enable needs an actual end-to-end flow, not just improved copy.
- **A6:** Account receives the raw master signature before encrypting it. Ciphertext-only browser delivery does not mean Account lacks plaintext access. This is already explicit in identity-contract section 1 step 7 and section 4; reconcile broader product claims with that documented implementation. Compromised signing authority may affect existing eligible wallets as well as future enablements; exact blast radius depends on credentials, wallet access, and policy.
- **B6/B7:** source-at-boot and operator-asserted node admission are real. Say that runtime code provenance is not fully bound to compose evidence, rather than that nothing is measured. Identity KMS-chain and app-id checks still exist independently of admission.
- **B9:** Storage's delegation predicate ignores revocation. The problem is broader than its 60-second cache: revoked records can pass after a fresh lookup too. Create-only result objects do not make all ordinary blob writes safe.
- **B12:** external-wallet support is incomplete; mobile's five-rule policy requirement is unconditional; "ready" means sealed plus confirmed/finalized, not hydrated. Four signatures is not a universal flow count: enablement, grant signing, optional prewarm, and cached legacy boot are distinct operations.
- **B14:** JSON null reaches `signEnclaveIntent` and is dereferenced at `personal-server-intent-service.ts:715`. A focused authenticated route regression should require a structured 400. Stale PR bodies and mixed SDK pins merit cleanup/compatibility proof, but mixed versions alone do not establish a runtime defect.

## Claims that need narrower wording

- **B1:** Gateway accepts registered-server-signed grants, contrary to the owner-only policy. This enclave's `signed-artifacts.ts:74` rejects signatures not recovered to the owner. Do not claim delegate minting alone bypasses this raw-read verifier.
- **B3:** prewarm unseals and startup sync decrypts before builder authorization, inside the explicitly trusted TEE. `/prewarm` does not return plaintext. Owner-signature verification at the agent must account for both explicit owner prewarm and grant-triggered prewarm.
- **A5:** V2 signatures lack contract nonce/deadline. The existing Gateway does reject retired enclave addresses, so a captured enclave signature does not automatically reactivate through that honest Gateway. Legacy replay and the absence of contract replay protection remain.
- **B10:** the agent's broad bearer/Docker access is part of its existing trusted authority, not a new privilege escalation. `WORK_DELAY_MS` and `SANDBOX_DEBUG` are not sandbox environment allowlist entries. Operational debug/log/default hardening remains worth assessing without alleging demonstrated secret disclosure.
- **B11:** missing rate limits and receipts are real target gaps. Existing identity and sealed-secret requests can short-circuit; not every request reaches the agent. A nonexistent data point causes later read failure, not unauthorized data access.
- **A3:** the verifier option is absent and the claim chain-id definitions disagree. Optional verifier/routing fields can be additive. Old builders require upgrades to benefit; an unavoidable wire-breaking migration is not established for every item. Paid jobs need signed pricing consent, while old clients could remain free-only.

## A1 and A2 require architecture decisions

The random DRK proposal is technically consequential and should be evaluated before broad adoption. It revises the current explicit no-data-key-rotation-v1 decision and moves the suggested deadline from the architecture's pre-GA work to the first mainnet user. It has not been accepted as an implementation requirement.

Corrections to make before adopting A1:

- Wrapping-key rotation can avoid re-encrypting data only while retaining the same uncompromised DRK. A leaked DRK requires a new epoch and data re-encryption to protect affected data going forward.
- Rewrapping or deleting server copies cannot revoke an attacker's saved DRK, or an old key plus an old wrapper. Backup retention does not bound attacker-held copies.
- Changing the wallet-signed message is not password rotation. If the wallet private key or signing authority is compromised, the attacker may produce signatures for the new message too.
- Two independently decryptable wrappers provide either-key access. A scheme requiring both factors needs an explicit AND construction, authenticated context, independent authorization, and tested destroyable-key semantics. Moving signing code to a browser alone does not establish independent signing authority.
- Existing data uses the exact 65-byte signature as HKDF input. Calling it epoch zero can preserve legacy compatibility but does not revoke that signature. A new 32-byte DRK needs versioned readers/writers and a migration ledger. Owner authentication must be separated from root-key material because current code also recovers the owner from that signature.
- Recovery wrapping adds another authority path; it is not a free consequence of envelope encryption.

KMS mode is already recorded as Phala off-chain in decision 26. Reopening that choice for future measurement governance is reasonable, but it is a new decision rather than an unmade choice. The dual-factor proposal also changes availability, recovery, and the no-second-wrap position and needs explicit review on those terms.

## Working sequence

1. Keep the current preview isolated; preserve no-production/no-merge constraints.
2. Take the narrow enclave-completion/Lite-URL fix on the prepared #987 stack, with red/green route and client tests, if continuing the selected decommission lane.
3. Track version enforcement, destination policy, authorization/retirement, revocation flow, admission/provenance, and release gates as separately owned changes with concrete tests.
4. Resolve DRK/KMS/signing-authority and builder-contract decisions explicitly before treating them as approved code scope.
5. Complete owner-authorized ingestion before globally removing Lite registration and native login's registration/relay dependency. Retain `packages/lite` until real-user adoption and consumer migration permit deletion.

The earlier pending choice about expanding into owner-authorized ingestion remains unanswered. The supplied review notes add evidence; they do not constitute acceptance of the DRK proposal or permission to merge/deploy.
