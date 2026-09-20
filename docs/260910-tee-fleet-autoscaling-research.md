# TEE fleet autoscaling — research memo (history)

Detail: [../../e2e-proof-2026-09-09/fleet-overnight/reviews/autoscaling-research-full.md](../../e2e-proof-2026-09-09/fleet-overnight/reviews/autoscaling-research-full.md)

Superseded 2026-09-10. The memo asked whether to autoscale the fleet and how; the answer was built and proven on preview the same day. Current numbers, open items and receipts: [autoscale closeout](260910-autoscale-closeout.md) — where the memo disagrees with it, the closeout wins. Known correction: the controller does **not** boot paused after a restart (activation persists on `fleet-state`).

| Decision taken 2026-09-10                                                            | Shipped as                  |
| ------------------------------------------------------------------------------------ | --------------------------- |
| Signed bundles never expire (`expiresAt: null`), stopped members included            | #276, folded into #245      |
| Pool = 2 pinned + 2 stopped members (later all tdx.medium, cap 4)                    | #277/#278                   |
| Start/stop called by a keychain loop on the operator laptop; no `phak_` key in a CVM | `scripts/tee/pool-loop.mjs` |
| Scale down after 15 min idle; cold start for moved owners accepted                   | pool loop                   |
| One controller restart per pool-size change accepted                                 | —                           |

Still open from §10 (frozen directory, loop off the laptop, ingress split): [controller HA memo](260911-controller-ha-and-directory-resize.md).
