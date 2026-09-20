# 2026-09-10 hardening closeout → autoscale session handoff

Preview only. Nothing merged to dev/main. No canonical host, shared Privy signer, or attestation policy touched.

## Heads (all pushed, all CI green)

| Repo               | Branch                       | Head     | PR state                                                                                   |
| ------------------ | ---------------------------- | -------- | ------------------------------------------------------------------------------------------ |
| unity-surfaces     | feat/owner-data-client       | 355e703d | folded into #987 (feat/account-enclave-delivery, base dev, 18/18, MERGEABLE); #1039 closed |
| data-gateway       | feat/owner-access-feed       | 971bc34  | folded into #100 (feat/identity-schema, base main, green); #125 closed                     |
| personal-server-ts | feat/mcp-access-records      | 123bf40  | #276 open, diverged from #245; merge PREPARED, not pushed (below)                          |
| vana-storage       | fix/revoked-delegation-check | 9e2323b  | draft #26 (base dev, green), not merged                                                    |

## Previews (aliases)

| Surface   | Alias → deployment                                                                                  | Rollback        |
| --------- | --------------------------------------------------------------------------------------------------- | --------------- |
| Web       | vana-web-enclave-preview → dpl_9jKXugCa42R1N4bFdPktYToqcB7p (355e703d)                              | dpl_CEbDAbk8    |
| Account   | vana-account-enclave-preview → dpl_7zGHRNQ15k6C6P6AFyu2rQRFbkU8                                     | dpl_AYyW9yL9    |
| Mobile UI | vana-mobile-aqdm39x28 (62d5d117; sim Runner 62d5d117)                                               | q3cwff5nr       |
| Gateway   | dp-rpc-moksha-spike-b3 → dpl_HnpQAv9z21VKteeAJzcnjkp8vZ3A (971bc34), private config                 | dpl_4dGtpxds    |
| Storage   | spikeb3 alias version c937c512 (fix branch)                                                         | 3fe95da5        |
| Fleet     | controller ae2a9c3d, W1 87c32ca4, W2 1a5acf08; GIT_REF 123bf40; bundles expire 2026-09-11T11:36:32Z | re-sign runbook |

Local loops: settle PID 59402, jobs-sweep PID 33507 (preview gets no Vercel cron).

## Proven today (e2e-proof-2026-09-09/)

- Mobile live Spotify write, all 3 scopes (owner-data-client/mobile-proof.md Attempts 9–11).
- Owner auth on GET /v1/access, Web + Mobile (owner-data-client/proof.md).
- Step 3 worker kill mid-job: bounded retry, no stale result, idempotent ACK (hardening/step3-worker-kill.md).
- Step 4 two-owner isolation/revocation matrix (hardening/step4-revocation-isolation.md); Storage D1/D2 fixed and re-measured, revocation window 61 s (step4-storage-fix.md); submit-time denials in the access feed, registered builders only (step4-denied-rows-live.md).
- Enclave Revoke wired and proven, re-enable at new epoch (hardening/enclave-revoke.md); final 15/15 golden journey on the alias (hardening/final-preview-proof.md).

## Open, deferred (not blockers)

- Hardening steps 5 (fleet cold wake, reconnect, controller restart with live MCP connection), concurrent first-call race, mixed soak.
- UX: post-revoke consent failure page hides the computed reason; prewarm 429 bursts (fan-out not de-duplicated); revoked owner's MCP request surfaces as generic 503; Mobile builder names need a name source; #276 `lookupSandbox` lacks the current-generation guard.
- Unity repo tracks root `.vercel/project.json` (app dirs now linked locally); consider untracking.
- Lite package/relay teardown after prod is smooth (inventory in memory).

## Autoscale session — start here

Memo: docs/260910-tee-fleet-autoscaling-research.md (uncommitted). Decisions taken: stopped-CVM warm pool accepted; start→healthy reduction in scope; tdx.medium, capacity 4→6; idle TTL 600 s kept, fix preview overrides (TTL 30 s, capacity 2), enable prewarm at consent render.

Slice 1: push the prepared merge 0e35a083 (worktree scratchpad/ps-fold of session 58478976, branch fold/276-into-245, parents 40e69ec + 123bf40, build + 2064 tests pass) to feat/enclave-primitives, point feat/mcp-access-records at it, roll the fleet (replicate, never update in place; SANDBOX_CPUS=1 on tdx.small), re-sign once with expiresAt: null.
Slice 2: prebuilt enclave + sandbox-runtime images in docker.yml, composes on digests (target ≤90 s start→admitted).
Slice 3: raise worker cap, tolerate stopped members, admit {resume:true}, restart-once on double mr-kms; pre-create 2 stopped workers; external start/stop loop on controller signals.

Rules: never create Vercel projects (all exist; `vercel link` first); Gateway preview deploys need the private config; stop for Kahtaf on shared Privy signer, canonical dev/prod, attestation policy.

## Superseded — autoscale session ran 2026-09-10

The "Autoscale session — start here" section above is history: all three slices landed, plus two more.
Current fleet state, measured numbers, heads and the ranked open list: [autoscale closeout](260910-autoscale-closeout.md).
PS head is now `b693a0e` on `feat/enclave-primitives` (#245); the pool is 4 signed members with a loop in `scripts/tee/`.
The research memo's §9 decisions are taken — see [autoscaling research](260910-tee-fleet-autoscaling-research.md).
Production requirements that came out of it are in [production plan §7.1](260906-production-plan.md).
