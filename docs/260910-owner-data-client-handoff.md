---
name: handoff-2026-09-10-owner-data-client
description: "START HERE — state at 2026-09-10 03:25Z: Web fully Lite-free and proven on preview; Mobile C1–C4 landed, C5 (Lite removal) in flight; access logs from Gateway (jobs + MCP); fleet re-signed; blockers, running loops, next steps"
metadata:
  node_type: memory
  type: project
  originSessionId: 429b9c78-3df5-430f-9af0-caf7247f91b2
  modified: 2026-09-10T03:22:37.358Z
---

# Handoff 2026-09-10 (overnight complete ~05:45Z; Kahtaf asleep since ~03:25Z)

Direction (see [[mobile-tee-path-2026-09-09]]): retire PS Lite; owner surfaces sign only; one PS runtime (packages/server) hosted locally (Desktop) or in the TEE fleet; owner data plane = client-side crypto via `packages/owner-data-client` (Unity). No flags; commits are the revert unit. Preview only; never dev/main/canonical hosts.

## Branches / heads (none pushed except fleet + gateway)

- Unity `unity-surfaces-moksha-integration` branch `feat/owner-data-client` @ **cd498e91** (30 commits off f740d042). NOT pushed to origin. Web fully Lite-free (0bb785b4); revoke/delete (574fd222/b8278ed6/9240d061/6533b711); access history from Gateway (1a4e977b); Mobile C1 c70ae55c/0f414d58, C2 873d4173/e02d5393/17abdcad, C3 9d68ad6d/36637ff6/35cd5a3a/e89c22e2, C4 cd498e91; shell origin overrides 88270aea. Checkout node_modules are hand-wired symlinks — never plain `pnpm install`; `--lockfile-only` + hand symlinks. `next build` is broken locally by a bad `node_modules/next` symlink (pre-existing); Vercel builds fine.
- Gateway `data-gateway-fleet` branch `feat/owner-access-feed` @ ba978fe (rebased; was 68d8511) (d0f2ec3 `GET /v1/access?user=`, 866ab54 `POST /v1/access-records` + migration 0060, 68d8511 union + 180-day purge). Deployed to alias spike-b3 as dpl_AE3xSLao3gGkGXRYq4wyq4DJvYn1 (rollback dpl_Us98BBz2, older dpl_KueZgMtG). Migrations 0059/0060 applied to spike-b3 Neon only. Preview env NEON_URL is WRONG — deploy with private config from keychain `spike-b3-neon-url` (see [[phala-cloud-and-codex-ops]]).
- PS fleet `personal-server-fleet-controller` branch `feat/mcp-access-records` (pushed) @ 123bf40 (a37c259 reporter+relay, 13723f4 nested envelope, dff863e denied records from tool envelope, 123bf40 tests). Deployed to workers: GIT_REF 13723f4, PS_IMAGE sha256:46d820dd…; dff863e/123bf40 NOT yet rolled (worker window 3): root cause was denials filed under grantId "none" → Gateway rejected the batch; fix files under the covering/connection grant and adds `tool`. PS_IMAGE for 123bf40 = sha256:8c67a524425536a516e82b7d156a8af55fd669b41868a22ad54800809cca4176 (fleet-overnight/ci-docker-123bf40/images.env).

## Preview deployments (aliases)

- Web https://vana-web-enclave-preview.vercel.app → dpl_9AprzWaZWZ2uTeDUnq41w7G77W59 (6533b711). Recipe: isolated worktree, patch environments.json dev.gatewayUrl→spike-b3, env from scratch deploy-web-candidate.sh + NEXT_PUBLIC_VANA_STORAGE_API_URL=spikeb3 worker + NEXT_PUBLIC_VANA_STORAGE_AUDIENCE=https://storage-dev.vana.org.
- Account https://vana-account-enclave-preview.vercel.app → vana-account-coydbdwei (mobile attestation vars + DID allowlist; Kahtaf's 4 signer vars in ../unity-surfaces/apps/account/.env.account; a redeploy with them was in flight at 03:25Z). Must pass ACCOUNT_OWNER_INGESTION_ENABLED=true + STORAGE_AUD + SCOPES + INTENT_SIGNING_ORIGINS + anchor override.
- Mobile UI preview https://vana-mobile-73l6x3r9y-opendatalabs.vercel.app (17abdcad; needs --build-env NEXT_PUBLIC_MOBILE_UI_BUILD_ID=<sha>, NEXT_PUBLIC_VANA_ACCOUNT_ORIGIN=<account preview>, gatewayUrl patch).
- Gateway spike-b3 (above); Storage https://spikeb3-vana-storage.vana.workers.dev (claim aud = https://storage-dev.vana.org; owner self-signed PUT OK; last-write-wins).

## Fleet (preview, prod5)

Controller ae2a9c3d… compose 8b6a1e5c (frozen), W1 87c32ca4… compose e0d5a12d…, W2 1a5acf08… compose 30839aa6…; all bundles expire **2026-09-11T03:35:23Z** (window 4: W1 compose b3a922f0…, W2 ef77e477…, GIT_REF 123bf40, PS_IMAGE 8c67a524…) (fail-closed on restart only; re-sign daily). Both workers admitted; MCP live. Re-admission = drain→remove→re-register→heartbeat→admit (`fleet-overnight/access-records-rollout/readmit-gateway-worker.cjs`); controller FLEET_WORKERS_JSON must carry new worker hashes before peer admission. Double `mr-kms` in RTMR3 after a reboot = KMS failover → restart the CVM (do NOT relax verifier). Receipts: fleet-overnight/access-records-rollout{,-2,-3}/.
Settle cron: preview never gets Vercel cron ticks → local loop `scratchpad/settle_bg_loop.sh` (PID 40376, ends ~08:05Z) chained to `settle_bg_loop_36h.sh` (starts ~08:05Z). If both die, tick `POST /v1/cron/settle` with keychain `spike-b3-cron`.

## Proven (preview)

- Web fresh owner 10/10 (owner 0xdfdb…5d99): signup, write v1/v2 (client encrypt ~90 ms, put 2–3 s, register 0.2–0.4 s), read (get 0.3–0.6 s + decrypt ~80 ms; cached 0 network), enclave enable → ready 71 s, MCP endpoint, consent→portrait 16 s, close/reopen, sign-out/in. Zero [ps-lite]; no personal-server-ts in bundle. Revoke/delete/revive 8/8. Access history shows job + MCP rows (served). Proof: e2e-proof-2026-09-09/owner-data-client/proof.md + evidence/.
- Access logs PROVEN end to end (04:50Z): `/v1/access` shows job reads + MCP served (tool read_scope) + MCP denied (scope_not_granted); Web Access History renders Served/Denied rows (screenshot fleet-overnight/access-records-rollout-4/access-history-Access_logs.png). Lorebook job 25.5 s.

## Blocked / open

- **pnpm-lock.yaml stale on feat/owner-data-client** (zod added in C3) → Vercel/CI builds fail ERR_PNPM_OUTDATED_LOCKFILE until `pnpm install --lockfile-only` is committed (asked C5 agent to include it).
- **Simulator sign-in blocked #2 (03:24Z):** Account iOS session bootstrap `validatePolicy` (apps/account/src/lib/mobile-attestation/mobile-signer-bootstrap.ts:253) requires 5 Privy policy rules (owner binding + ServerRegistration + PrewarmRequest per chain 1480/14800); shared dev policy `oucrb8tj6jjhz1186w667aa9` has only 3 (no PrewarmRequest) → 503 mobile_signer_bootstrap_unavailable. DECISION for Kahtaf: add two PrewarmRequest ALLOW rules to that shared Privy policy (verifyingContract 0xCae2CE0e9caa6643ed28186cF57bd40Bd9E17Eab, chainId eq) or create a preview-only policy and point the Account preview at it (ACCOUNT_MOBILE_PRIVY_POLICY_IDS). Account preview now dpl_BpTtMWzb9cQyZMYjKa7f8BZE1jK4 (with all mobile vars); Mobile UI preview vana-mobile-khmjtf4k7 (e89c22e2); evidence e2e-proof-2026-09-09/owner-data-client/mobile-proof.md.
- Simulator proof: owner 0x57ef…dca4 (DID did:privy:cmtuwzsh200xk0cjuit2ilawm, inbox vanaproofmtuwz9vg@uberip.com on mail.tm) has Spotify v1 from Web; sign-in previously 503 (mobile signer vars) — vars now supplied; proof agent was running at 03:25Z. Mobile write proof needs a third-party login (no test creds) — ask Kahtaf for a throwaway Spotify/GitHub login or accept the reverse-bridge unit tests.
- Mobile C5 (delete Lite from shell + hosted UI, login phases → `ready`) in flight at 03:25Z; then rebuild shell/UI previews and rerun the sim proof.
- Owner auth on `/v1/access` listing (exposes MCP tool names) — follow-up.
- Gateway grant settlement waits on paymentStatus (grants stay `pending`); grant revocation on-chain submit is a stub; Gateway lacks latest-version timestamp (sources "Updated" label = first write).
- Legacy MCP `?mcp_authorization=` deep link not classified by the shell's native link dispatcher; DCR consent grant in hosted UI still via native controller (fine).
- Desktop untouched (keeps full-PS sidecar by design).

## Kahtaf decisions 03:40Z

- Owner auth on `/v1/access` listing: LATER, first follow-up after the Mobile proof (Web3Signed owner claim; needs Account claim audience for Gateway).
- Mobile live write proof: use Kahtaf's own Spotify (username kahtaf, email-code login). Claude does NOT enter the login code (credential entry); plan = Claude drives the connector to the Spotify login screen on the simulator, Kahtaf types the code, Claude continues (collect→encrypt→upload→register→read-back, timings). Gated on decision 3 (Privy policy PrewarmRequest rules).

## 03:50Z in flight

Kahtaf asked for the simulator to be set up for the Spotify login now → agent creating a preview-only Privy policy (5 rules incl. PrewarmRequest; shared dev policy/signer untouched; stop if the shared signer must change), redeploying Account preview with ACCOUNT_MOBILE_PRIVY_POLICY_IDS=<new>, signing in on the sim, driving to the Spotify login screen. Also running: Mobile C5, worker window 3 (123bf40), Web hygiene.

## 04:15Z sim status

Preview-only Privy policy d5e3dlkq8rcr85agxbw4zcs8 (5 rules) created; Account preview dpl_22X8tdKj2ptn5PamT6SrDLxj6RAX uses it (ACCOUNT_MOBILE_PRIVY_POLICY_IDS). Policy 503 gone. NEW BUG: Web-first owner (0x57ef…) → mobile session POST 409 `mobile_wallet_state_conflict` (wallet already has the Web signer; unlogged shape check ~mobile-signer-bootstrap.ts:404). Workaround in flight: mobile-first fresh owner → allowlist DID → Spotify login screen for Kahtaf. Fix Web→Mobile wallet attach later (product bug). Web hygiene 087e7ad4 landed; C5 shell removal 96479407 landed (hosted UI + protocol commits pending).

## 04:30Z

Mobile C5 LANDED: 96479407 (shell −14236), 1f804103 (hosted UI + protocol; capabilities now connectors,continuation,enclave-signing,external-url,native-auth,owner-binding,owner-signing; login phases account_session→owner_binding→ready), e5d39722 (CI/docs + pnpm-lock fix). Preview via readScope + native shareTextAsFile; "view on-chain" dropped; Home connected-app count null (wire to enclave grants later). Pushing Unity + Gateway branches to origin for CI (agent). Unity head after this: e5d39722 (+ 087e7ad4 web hygiene before it).

## 04:15Z sim attempt 4

Mobile-first owner 0x4934…d000 (DID did:privy:cmtuzr78k015o0cjeiwo26y4l, inbox vanaproofmtuzoeih@uberip.com) → Account preview dpl_GvwHXAqS5LoT9Z343xeXFjvVgCyM (allowlist incl. that DID, policy d5e3…): wallet conflict gone; first POST 409 attached the mobile signer; then every POST 502 FUNCTION_INVOCATION_FAILED (no logs) → agent root-causing (post-attachment path; key format of ACCOUNT_MOBILE_PRIVY_WALLET_AUTHORIZATION_PRIVATE_KEY suspected). Privy session survives simctl uninstall → `xcrun simctl keychain <udid> reset`. Kahtaf told to sleep; Spotify hand-off in the morning. Also running: Web soak; Account web-first wallet-conflict fix.

## Web-first wallet "conflict" root cause (04:40Z, commit 8c0e6b78 test only)

Account returns 409 `mobile_signer_attachment_required` (correct). Shell `mobile_account_session.dart:569-573` maps it AND its own attach precheck failure (:473-478) to `walletStateConflict`; the on-device `addSigner` never lands for Web-created wallets — suspect `readExisting()` (`privy_flutter_auth_port.dart:148-157`) returns ≠1 embedded wallet (wallet_client_type "privy", recovery privy-v2, delegated). Next sim build: `--dart-define=VANA_PRIVY_DIAGNOSTICS=true` to capture the SDK error; fix in the shell, not Account.

## 05:00Z overnight plan (Kahtaf 05:05Z: YES draft PRs — open, watch CI, make green (no merges); STOP if the shared Privy signer must change)

Running: Account 502 root cause (invocation failure before handler on resume POST) + sim retry → Spotify screen; Web soak; shell fix (select wallet by bound address, refresh before create, split attachment_required); fixture-export harness `FIXTURE_EXPORT_AUTORUN=<sourceId>` (writes spotify.savedTracks fixture through ExportSink → owner-data ingest; markers ===FIXTURE-EXPORT-BEGIN/END===) for a Mobile write proof without Spotify login. Then: rebuild Lite-free shell (head) + Mobile UI preview, sim proof (sign-in, fixture write, read, enable, DCR, close/reopen), timings → mobile-proof.md.

## Soak 03:59–04:08Z (owner 0xdfdb): CLEAN

3 writes (v4→7; client encrypt ~86 ms, put 1.2–2.1 s, register 0.3–0.4 s; click→connected median 33 s = Spotify scrape), 6 consents (approve→portrait median 17 s; 1 stalled: approve click before hydration never started the handler, no timeout/error state → fix in progress), 10 reads (9 cache hits), 2 revokes. One job per DCR, zero pending, zero 5xx, 4×429 on Gateway `/v1/prewarm` under burst (adding backoff). Fleet: all placements released, no leaks. UX nit: unnamed grant shows "Technical grantee 0xd49e…" in Active tab.

## 05:30Z landed

ba862e9a fixture-export harness (`--dart-define=FIXTURE_EXPORT_AUTORUN=spotify`, writes spotify.savedTracks fixture via ExportSink; markers ===FIXTURE-EXPORT-BEGIN/END=== with JSON). 1362a50f shell signer attach fix (refresh before create; select wallet by bound address; `signer_attachment_required` distinct from conflict; diagnostics) — boundOwner wiring in shell_page follow-up in flight. Running: Account 502 root cause + sim retry; draft PRs/CI; prewarm backoff + approve-stall fixes.

## 04:30Z Account 502 ROOT CAUSE + FIX (commit e4e0a479)

Not a crash: `mobile_session_issue_failed` — Account DEV DATABASE lacked migrations 026/027 (mobile_sessions scope check still legacy 3 scopes; ledger stopped at 025), so the post-attachment mint failed; simulator path had no failureStage → no logs. Agent APPLIED 026+027 to the shared Account dev DB (additive; TELL KAHTAF) and added stage logging. Account preview now dpl_6HkkpBVvuA6GV4cGP6ispk4pWg8K; mobile session POST 200; owner 0x4934…d000 signed in on sim. Old Runner (e89c22e2) then failed PS-Lite boot → Attempt 6 (Lite-free build at HEAD + fixture write + read + enable) running. cdd2ced4 bound-owner wiring landed.

## 05:50Z PRs

Draft PRs: unity-surfaces#1039 (base dev, stacks on #987) GREEN at cdd2ced4 (+ later e466111e prewarm backoff, d2902234 approval stall watchdog — repush needed); personal-server-ts#276 (base main, stacks on #245) GREEN at 123bf40; data-gateway#125 (base main) GREEN at ba978fe after rebase onto origin/feat/identity-schema (Gateway branch head now ba978fe; deployed preview alias still dpl_AE3xSLao from 68d8511 — same code plus parent settlement work; redeploy from ba978fe when convenient). Never merge.

## 05:05Z Mobile Attempt 6 (Lite-free build cdd2ced4)

Mobile UI preview vana-mobile-q3cwff5nr (dpl_AkgNPQhYxkyxVHuduT6wtPw79JG8); Account preview dpl_9Psv644iSou472VLWp5zFjoT1ZAr (ACCOUNT_INTENT_SIGNING_ORIGINS must include the current Mobile UI preview origin!). Sign-in PASS (mobile session 200; zero [ps-lite]/PS boot lines; launch→ui 5.7 s). Always-on enable PASS 131.6 s (device-signed ServerRegistration + enclave-delivery 200 → sealed → serverStatus confirmed; server 0xf18d66…, enclave 0x09d6E64F…). Fixture write FAIL: harness fired on first onLoadStop (`/`) and the post-login redirect to /home/ dropped the bridge reply → commit hung 10 min (product weakness: no timeout on lost bridge reply). Fix + Attempt 7 in flight. No Mobile permissions/access-history screen exists yet. Consent via /continue not exercised for the mobile-first owner.

## 05:20Z running

Attempt 7 (ingest bridge timeout/reject + harness re-arm on settled document, then sim write/read/reopen proof); Mobile permissions + access-history screen LANDED 9e2dc8bc (`/account/access`; builder names by grantee id deferred). PRs green: unity#1039 d2902234, gateway#125 ba978fe, ps#276 123bf40 — repush Unity after new commits.

## 05:20Z MOBILE WRITE PROVEN (Lite-free shell 2e238911; fixes 96bd31fd ingest timeout/reject, 4074f7ae + 2e238911 harness re-arm after settled document/login resume)

Fixture export spotify.savedTracks: ok, 787 B plaintext, 3 records, version 1, 2860 ms client; launch→ok 9.6 s. Gateway DP 0xe41422ae… v1 active (05:19:59Z); Storage blob v1 984 B. Lost-reply case now fails in 270 ms with a clear error. Attempt 7 FULL PASS (build 2e238911): launch→UI 3.3 s; write 2.86 s; READ tap→visible ≤0.5 s, preview plaintext 3 records byte-equal; reopen ok (wrote v2 via harness). Gaps: Memory screen doesn't refetch in place after a same-document write (fix in flight); blob-cache-on-reopen unmeasured (no request lines in os_log). PR unity#1039 GREEN at 9e2dc8bc. Attempt 8 (Web-first owner 0x57ef sign-in with wallet fix + cross-surface read) running.

## 05:45Z OVERNIGHT RESULT — all planned items done

- Mobile Attempt 8 PASS: Web-first owner 0x57ef signs in on iOS (409 attachment_required → device addSigner 2.1 s → 200; OTP→signed in 4.7 s); cross-surface read of Web-written spotify.profile decrypted on device (display_name kahtaf, following 19) → same master key on both surfaces. Privy wallet now has both signers.
- 1e0f9115 memory screen refetch after write. Unity head 1e0f9115 pushed; PR #1039 was green at 9e2dc8bc (re-check after push).
- Mobile proof file: e2e-proof-2026-09-09/owner-data-client/mobile-proof.md (Attempts 1–8, shots, os_logs).
- Remaining for Kahtaf: (a) Spotify live connector run on the sim (Claude drives to login screen; Kahtaf types code) — build has FIXTURE_EXPORT_AUTORUN, fine; (b) owner auth on /v1/access (first follow-up); (c) Account dev DB migrations 026/027 were applied overnight (additive); (d) Privy preview policy d5e3dlkq… and preview deployments to tear down eventually; (e) fleet bundles expire 2026-09-11T03:35:23Z — re-sign or accept fail-closed-on-restart.

## Overnight-safe work (no supervision)

1. (DONE) worker window 4 rolled 123bf40; denied rows proven.
2. After C5: build shell + Mobile UI previews at head, run sim proof (sign-in, read, enable, DCR link); record timings.
3. (DONE push) both branches pushed; CI only runs on PRs → ask Kahtaf about a draft PR to dev.
4. (DONE) Web hygiene 087e7ad4.
5. (DONE) soak clean; follow-ups in flight (prewarm backoff, approve stall).
