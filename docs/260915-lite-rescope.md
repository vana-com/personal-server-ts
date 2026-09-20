# Lite rescope — 2026-09-15

Mainnet-off (2026-09-14) made PS Lite the LEGACY path for chain 1480, `defaultMode: legacy` — live
product for every mainnet owner until the [mainnet TEE slice](260914-mainnet-tee-plan.md) reaches a
full cohort. This rescopes the two removal PRs against that fact, replacing
`260908-lite-retirement-launch-gates.md`.

## 1. What Lite must keep working now

| Capability                     | Where                                                                  | Proof / anchor                                                      |
| ------------------------------ | ---------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Mainnet register/import        | `dp-rpc.vana.org`, `app.vana.org`                                      | 260914-mainnet-off.md smoke, owner `0x2133…d9c0`                    |
| MCP over Lite                  | Web MCP page                                                           | mainnet-off smoke, endpoint published                               |
| Owner-binding localStorage key | `vana.ps-lite.owner-binding.v2.{namespace}`                            | unity `apps/web/src/features/personal-server/owner-signature.ts:37` |
| Desktop bundle                 | `personal-server-ts-lite@1.12.0` (transitive)                          | unity `apps/desktop/package.json:53` (still pinned 1.12.0 on `dev`) |
| Relay infra                    | `personal-server-relay` repo, `*.psrelay/relay.vana.org` DNS, GCP MIGs | tee-path-state Lite footprint (2026-09-10 sweep)                    |

## 2. #288 / #1043 status

**#288 is closed**, not open — its branch `chore/remove-ps-lite` was renamed to `feat/remove-ps-lite`
so `prerelease.yml` could publish a Lite-free canary; the rename closed #288 irrecoverably.
**personal-server-ts #299** (open, `main`) is its replacement and carries the same deletion scope.

**Unity #1043** (open, base `dev`) has two commits: drop the Lite owner-binding key + dead Lite
config (original scope), plus a later re-pin of Desktop to `#299`'s Lite-free canary. Both PR diffs
show 100+ files/commits — noise from squash-merge drift (`#987` squashed into `dev`, these branches
never rebased), not new scope. Confirmed on live `dev`: `apps/web/.../owner-signature.ts` still
writes the Lite key, `apps/desktop/package.json` still pins `1.12.0` — neither PR has landed.
Mobile's own Lite runtime (`lib/ps/*.dart`) is already gone from `dev` via `#987` — unrelated to
these two PRs.

| File group                                                | PR                      | Merge now?                                                      | Gate |
| --------------------------------------------------------- | ----------------------- | --------------------------------------------------------------- | ---- |
| `packages/lite` + relay client                            | #299                    | No — deletes the running mainnet runtime                        | E    |
| Workspace/build wiring (root + cli/server tsconfig, deps) | #299                    | No — same dependency Desktop still needs                        | E    |
| Release/CI (prerelease.yml, .releaserc.yaml, Dockerfile*) | #299                    | No — drops the Lite canary publish Desktop's re-pin needs first | E    |
| Server dev UI (`ps-lite-debug.ts`, `/ui` browser mode)    | #299                    | No — no mainnet dependency, but ships with the same PR          | E    |
| Owner-binding key + dead config                           | #1043 (c1)              | No — breaks live mainnet sessions                               | D    |
| Desktop re-pin off 1.12.0                                 | #1043 (c2)              | No — also blocked on #299's canary existing                     | E    |
| Mobile-shell Lite runtime removal                         | already in `dev` (#987) | done                                                            | —    |

**Verdict: nothing in #299 or #1043 is safe to merge now.** Mainnet TEE cohort is empty (all three
mainnet hosts on legacy); merging either breaks live Lite register/import/MCP or the Desktop bundle.

## 3. Proposed gates (replaces 260908 gates 4–7; keyed to 260914-mainnet-tee-plan.md §4)

| Gate                     | Outcome                                                                              | Plan step(s) | Minimum proof                                                                                                      |
| ------------------------ | ------------------------------------------------------------------------------------ | ------------ | ------------------------------------------------------------------------------------------------------------------ |
| A. Mainnet TEE staged    | Guards widened, ingestion chain-keyed, SDK anchors real, mainnet CVMs signed+applied | 1–4          | Code merged, fleet live, `dp-rpc` gateway-rotated                                                                  |
| B. Selected-cohort smoke | ≥1 mainnet wallet routes to TEE via rollout-policy override                          | 5, §3 matrix | §3 proof rows 1–5 pass against real `dp-rpc.vana.org`                                                              |
| C. Cohort expansion      | Wider mainnet cohort; Lite retained for the rest                                     | 9 (repeated) | Per-expansion receipt; retained Lite owners stay functional                                                        |
| D. Cohort = 100%         | Every mainnet owner resolves TEE (or explicit non-owner); no new Lite enrolments     | 9, terminal  | Rollout-policy allowlist covers all owners (or `defaultMode: tee`); zero new Lite registrations over a soak window |
| E. Remove Lite           | #299 + #1043 merge                                                                   | after D      | Inventory: no live Lite session, Desktop re-pinned and released, relay infra decommissioned                        |

## 4. Decisions for Kahtaf

1. #288 is dead (closed, unrecoverable). Should #299 become the tracked "remove PS Lite" PR — and
   worth rebasing to shed the squash-drift diff before its next review pass?
2. #1043 now bundles two waiting changes (owner-binding key removal, Desktop re-pin) under one PR
   with 100+ commits of inherited diff. Rebase/split it now for hygiene, or leave it dormant until
   gate D/E actually unblocks it?
3. Gate D needs a concrete "cohort = 100%" definition. Is that the rollout-policy allowlist
   literally listing every mainnet owner, a `defaultMode: tee` flip, or an owner-count threshold
   plus soak window before flipping?
