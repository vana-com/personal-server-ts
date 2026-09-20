# Controller HA and directory resize

Detail: [../../e2e-proof-2026-09-09/fleet-overnight/reviews/controller-ha-design-detail.md](../../e2e-proof-2026-09-09/fleet-overnight/reviews/controller-ha-design-detail.md)

Design only, 2026-09-11. No code, no deploys; code read at `f5febb3`. Baseline: ingress and allocator share one CVM and one compose hash, so every controller restart or roll costs **150–180 s** of MCP — host stop/start, KMS keys and data disk, not our code. Six decisions, all about what is frozen in the signed bundle and what may change while the fleet runs.

## Fact: why worker bundles pin the controller compose hash

`composeHash` is the only measurement that pins the controller's code and wiring (`peer-verifier.ts:102-152` selects a policy by full equality over `{role,nodeId,appId,instanceId,composeHash}`, then replays it into RTMR3); `mrTd`/RTMR0-2 pin firmware, `appId` the KMS namespace, `instanceId` the CVM.
It cannot move to the controller's key: the dstack app key derives from `appId` alone (`dstack/client.ts:18`), so a key-based pin would admit any compose the Phala account deploys — strictly weaker. Consequence: one controller roll re-signs and restarts every worker.

## Decisions

**1. Split the MCP ingress into its own CVM before production?** Recommend **yes, but not first** — only option that removes the user-visible outage, and a prerequisite for any HA. Gate it behind a peer-session cache, or a third mutual-DCAP handshake per JSON-RPC message makes `initialize`/`tools_list` (already 18–20 s) worse.

| Option                | Outage per roll                                | Trust change                                                                          | Size                   |
| --------------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------- | ---------------------- |
| (a) split ingress CVM | ~0 controller; 150–180 s on rare ingress rolls | new `role:"ingress"`, MCP keys leave the controller bundle, reciprocal pins both ways | ~400–450 LOC + compose |
| (b) active/standby    | ~0 (failover)                                  | (a) + monotonic `controllerTerm` + shared transactional MCP state                     | ~700+ LOC, needs (a)   |
| (c) accept, shorten   | 150–180 s                                      | none                                                                                  | ~0                     |

**2. Active/standby controllers for v1?** Recommend **no.** The leader lease has no trustworthy home (dstack exposes `info`/`deriveKey`/`quote` only); a Gateway advisory lock puts a non-TEE Postgres in charge of the allocator, which is safe only once `controllerTerm` is a real fencing epoch (literal `1` in 7 sites). Standby also cannot inherit MCP state — per-CVM volume, no shared volume.

| Option        | Outage         | Trust change                                              | Size                |
| ------------- | -------------- | --------------------------------------------------------- | ------------------- |
| Standby now   | ~0 on failover | fencing epoch + shared OAuth state + non-TEE lease holder | ~700+ LOC after (a) |
| Defer past v1 | unchanged      | none                                                      | 0                   |

**3. Adopt staged reciprocal pins (two controller policies per worker bundle) now?** Recommend **yes** — cheapest availability win on the list: turns a controller roll from 5 restarts into 1, with zero code.

| Option                     | Outage                          | Trust change                                                      | Size                                         |
| -------------------------- | ------------------------------- | ----------------------------------------------------------------- | -------------------------------------------- |
| Ship current + next policy | 1 restart per roll instead of 5 | none — `policies` is already an array (`worker-runtime.ts:54-62`) | 0 LOC, one extra signing round before a roll |
| Keep single pin            | 5 restarts per roll             | none                                                              | 0                                            |

**4. Hot-reloadable signed worker directory, or stay frozen?** Recommend **frozen at N=8 for preview, hot directory for production.** Reject admission tokens outright: no revocation, so an old token re-admits a retired member.

| Option                          | Outage per resize           | Trust change                                                                                                   | Size                                                                                      |
| ------------------------------- | --------------------------- | -------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| (a) signed hot directory doc    | 0                           | membership becomes an authenticated HTTP call; same key, same authority, replay-fenced by persisted `sequence` | ~150–200 LOC + ~80 signer                                                                 |
| (b) per-worker admission tokens | 0                           | **weaker** — no revocation, tokens sit beside the admin bearer                                                 | ~80–120 LOC                                                                               |
| (c) frozen, pre-list N=8        | 150–180 s per resize past N | none                                                                                                           | 1 line (`bootstrap.ts:42`), + 8 CVMs built and signed once (~$2.03/mo each while stopped) |

**5. Accept that a runtime directory document trades audit visibility for uptime?** Recommend **yes**, with the accepted sequence and digest logged and exposed on `/fleet/v1/status`. Today a membership change is a `phala envs update` with a receipt; afterwards it is a quieter trail.

| Option                           | Outage               | Trust change                        | Size             |
| -------------------------------- | -------------------- | ----------------------------------- | ---------------- |
| Accept + log digest              | 0 per resize         | quieter audit trail, same authority | included in 4(a) |
| Require an `envs update` receipt | 150–180 s per resize | none                                | 0                |

**6. Order of work: 3 → 4c (`MAX_FLEET_WORKERS` 8) → peer-session cache → 1 (split ingress) → 4a (hot directory)?** Recommend **yes**; (2) stays open.

| Option              | Outage removed                           | Trust change                             | Size               |
| ------------------- | ---------------------------------------- | ---------------------------------------- | ------------------ |
| This order          | ops wins first, user-visible outage last | staged, one at a time                    | cheapest first     |
| Split ingress first | outage first                             | three handshakes before the cache exists | latency regression |
