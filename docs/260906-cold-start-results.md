# Cold-start results (2026-09-05/06)

## Before → after (spike CVM tdx.small, 512m sandbox)

| path                                                  | before               | after                                                   | lever                                                                                       |
| ----------------------------------------------------- | -------------------- | ------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Lorebook deep cut, 12-scope owner, approve → portrait | ~60 s                | ~50 s (B1+systrap) → ~33 s (+bundle) → ~32 s (+prewarm) | #266, #265, #268, prewarm trio                                                              |
| same, job complete after approve                      | —                    | 27.6–29.1 s                                             | agent log: click→prewarm at node 5–6 s, lead 4 s; boot 5–10 s; hydrate 6–7 s; execute 6–8 s |
| second chapter on the warm sandbox, other scope       | n/a                  | ≤14 s                                                   | lazy hydrate on read (#266)                                                                 |
| sandbox acquire → healthy                             | 10–13.8 s            | 9.2 s → 5.5 s                                           | systrap (#265) → + bundled entrypoint (#268)                                                |
| e2e small / 5 MB / 48 MB, single-scope owner          | 22.5 / 21.8 / 54.3 s | 25.1 / 23.9 / 54.3 s (±3 s noise)                       | none expected                                                                               |
| e2e cold job with grant-side prewarm a few s ahead    | 22.5 s               | 11.4 s                                                  | prewarm D2 (#111, #267)                                                                     |
| e2e cold job with a 15 s prewarm lead                 | 22.5 s               | 3.5 s (= warm)                                          | prewarm D1 (#1005 + #111 + #267)                                                            |
| CVM deploy → agent healthy                            | 10–15 min            | 195 s                                                   | CI digest image + pre-pull (#265)                                                           |

## Ordered plan

1. DONE #266 scope-first + lazy hydration (MERGE READY). Saves the wasted per-scope downloads; grows with owner size.
2. DONE #265 CI digest-pinned PS image + boot pre-pull + systrap (MERGE READY). Operator-side; 3 min boots.
3. LIVE ON PREVIEWS prewarm on approve: #267 (agent route), data-gateway #111 (typed-data route + prewarm on grant), unity-surfaces #1005 (Account intent + Web call). MEASURED: approve → job complete 27.6 s, portrait ~30–36 s (from ~50 s). Attribution from the agent log: the prewarm reached the node 5.8 s after the click and led the job by only 4.4 s, so prewarm itself bought ≈4 s; the approve→submit plumbing is the next target (report D §1, E §2). Harness: cold job 13.6 s (from 20–25 s) with the grant-side prewarm alone.
4. DONE boot itself: esbuild-bundle the PS entrypoint — CVM acquire→healthy 9.2 → 5.5 s, e2e 5 MB 23.9 → 17.0 s, 48 MB 54.3 → 43.6 s, image 88.7 → 65.7 MB; PR #268 stacked on #266, MERGE READY after the native secp256k1 fix. — local gVisor breakdown (report-A2) shows module loading is the whole tax and bundling halves it (systrap 2.95→1.46 s locally). Codex on perf/bundle-entrypoint. Expected 2–4 s on the CVM. runsc flags: no gain.
5. NEXT builder side: Lorebook wait=8 + immediate poll, cache getIdentity (report D §8): 1.5–4 s.
6. LATER prebuilt agent image (2–3 min CVM boot); literal digests in compose YAML (attestation gain); per-owner cache volume (deferred: attestation cost).

## Not done / caveats

- e2e harness step 9s PASSES (7.0 s warm lazy cross-scope, log verified) once only one CVM serves the app URL.
- systrap and prebuilt image not yet rolled on a fresh CVM (cache-cold boot number is an estimate).
- Prewarm previews: Mobile sign-in on the Account preview is failed-closed until the Privy policy gets the 5-rule shape (manual, Privy dashboard) and migration 027 runs; browser flow unaffected.

## Raw measurements

```
# Before (spike-b3-h10, ab07d8c, 512m, cold, 19:31Z 2026-09-05) — before.log
small 421 B: submit_ms 22488 complete 22488 ttfb 25285; warm 2919
5 MB: submit 21789 complete 21789 ttfb 22260; execute 7024 ms
48 MB: submit 25066 complete 54345 ttfb 54752; acquire healthy 13783 ms, synced 29641 ms; execute 23030 ms
oomKilled false on all 3 sandboxes (before-sandboxes-1.json)

# systrap (spike-b3-s2 = CVM 87c32ca4, compose 743eb171 = 73a1175 systrap, ref ab07d8c, 20:16Z) — roll-s2.log
small 421 B: submit 25489 complete 25489 ttfb 27956; warm 2164
5 MB: submit 18392 complete 18392 ttfb 18831; acquire healthy 9421 ms / synced 12849 ms; execute 4998 ms
48 MB: submit 25064 complete 51232 ttfb 51600; acquire healthy 9162 ms / synced 27275 ms; execute 22900 ms
=> healthy 9.2–9.4 s vs 10–13.8 s ptrace (−1 to −4 s). All PASS, no OOM. In-place update.sh took 3.7 min (docker cache warm).
PS_IMAGE=vanaorg/personal-server@sha256:076ecfcc8bab4cb9f79d67d8eb74a1853db5a111f874c1eace7ba91014f65c53 PS_IMAGE_REF=08c819d82a640042c75f377761c680be1038a404 (run 33990646837, 20:39Z)
BASELINE s3 (B1 f514ed2 + systrap 743eb171): small 25.1 s, 5 MB 23.9 s, 48 MB 54.3 s (single-scope owner: no per-job change expected); 9d decoy seed 400 → harness fix

# Chrome manual gate on spike-b3-s3 (B1 f514ed2 + systrap), h10 drained, 20:49Z
ChatGPT "The deep cut": approve click 20:49:01.5 → portrait visible by 20:49:54 (still writing at 20:49:40) = ~50 s (baseline ~60 s). Proof 42-chatgpt-portrait-scope-hydration-systrap-s3.jpg.
Spotify "quick read" on the same warm sandbox (different scope → lazy hydrate): approve 20:51:31 → portrait by 20:51:45 = ≤14 s. Proof 43.
C boot on h10 CVM 0bfecb0c (prod compose + digest 076ecfcc, ref 08c819d, node spike-b3-c1, compose 0c899e89): phala deploy → agent healthy 195 s (3.3 min; disk cache warm) vs 10–15 min in-CVM build

# Prewarm live (node p1 = CVM 87c32ca4 @ 29be489 agent-prewarm, gateway qjktoq6dh #111 PREWARM_ENABLED, web 3ing154o8 + account dkb2lunwf from #1005 with NEXT_PUBLIC_ENCLAVE_PREWARM), 00:34Z 09-06
ChatGPT deep cut, cold owner sandbox: approve 00:34:26.7 → still writing 00:34:52 → portrait by ~00:35:02 = ~30–36 s (was ~50 s with B1+systrap, ~60 s baseline). Proof 44.
Harness p1-prewarm2: cold job (step 9) 13.6 s submit→complete with the grant-side prewarm (D2) already firing; explicit 9p got 429 (cooldown) → harness fix codex-p4.
Prewarm attribution (p1 agent log, Chrome run): approve 00:34:26.7 → prewarm hits agent 00:34:32.5 (+5.8 s: web→account→gateway→node) → job claimed 00:34:36.9 (lead 4.4 s, joined the in-flight start) → healthy 00:34:41.1 (8.6 s) → synced 00:34:48.4 (hydrate 7.3 s for the 4.7 MB scope) → execute 6.0 s → complete 00:34:54.3 (27.6 s after approve) → portrait ~00:35:02 (Lorebook poll). Prewarm itself saved ≈4 s here; the rest of the 50→~34 s drop is plumbing variance.
Harness p1-prewarm3 (86cbdf8): step 9 cold w/ D2 lead 11.4 s; 9p with 15 s lead 3.5 s (warm); baseline 22.5 s.

# Bundle (spike-b3-e1 = CVM 87c32ca4 @ 4837a18 bundle on #266+#267 lineage? no: perf/bundle-entrypoint from perf/scope-hydration; systrap compose 743eb171), 00:56Z 09-06
small 19.6 s (warm 2.2 s); 5 MB 15.6 s, acquire healthy 4822 ms / synced 8615 ms, execute 5.7 s; 48 MB 45.8 s (healthy ~?; execute 7.4 s→ see log). All PASS. Image 65.7 MB (was 88.7).
e2 (bundle fixed 85def04, native secp256k1): small 20.0 s (warm 2.7), 5 MB 17.0 s (healthy 5.5 s / synced 9.5 s, execute 6.7 s), 48 MB 43.6 s. All PASS.
Chrome on e2 (bundle+B1+systrap, NO prewarm route on this branch → 404): approve 01:26:48.8 → job claimed 01:26:59.4 → healthy +5.0 s → synced +9.8 s → execute 7.5 s → complete 01:27:16.7 (27.9 s) → portrait ~01:27:22 (≈33 s). Proof 45.
a1 (all levers 6042098): small 17.8 s cold, warm 5.0 s.
# ALL LEVERS (node spike-b3-a1 = CVM 87c32ca4 @ perf/all-levers 6042098 = agent-prewarm + bundle, systrap; gateway #111 + previews #1005 flags on), 01:37Z 09-06
approve 01:37:03.2 → prewarm at node +5.1 s → job claimed 01:37:12.3 (lead 4.0 s) → prewarm healthy 9.8 s / synced 16.4 s → execute 7.7 s → complete 01:37:32.3 (29.1 s) → portrait ~01:37:35 (≈32 s). Proof 46.
Boot was 9.8 s this run vs 5.0–5.5 s in the e2 runs (1 vCPU contention right after the harness warm cycles; variance). Approve→portrait summary: 60 (baseline) → 50 (B1+systrap) → ~33 (bundle, no prewarm) → ~32 (all levers).
f1 (folded #245 head 2f1915b, systrap compose): small cold 12.6 s (grant-side prewarm), warm 2.4 s, PASS. 02:47Z
```
