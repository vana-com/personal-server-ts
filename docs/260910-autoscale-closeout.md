# 2026-09-10 TEE fleet autoscale — closeout

Detail: [../../e2e-proof-2026-09-09/fleet-overnight/autoscale-slices.md](../../e2e-proof-2026-09-09/fleet-overnight/autoscale-slices.md)

Preview only (prod5). Nothing merged to dev/main. Verifier, attestation policy and the shared Privy signer are untouched.

## Shape

```
 Claude/SDK ──▶ controller (tdx.medium, ingress + allocator, 4 signed entries)
                  ├─ W1 cap 4 ┐ pinned, always on
                  ├─ W2 cap 4 ┘
                  ├─ W3 cap 4 ┐ stopped pool members
                  └─ W4 cap 4 ┘   started by the loop when free = 0, stopped after 15 min idle
 Gateway (Vercel) POST /api/v1/cron/pool-loop: decides + calls Phala start/stop (PHALA_API_TOKEN in Vercel env) — outside the TEE; ticked every 60 s (laptop ticker until GitHub cron runs from main)
```

W1/W2 started as pinned tdx.small cap 2 and were resized to tdx.medium cap 4 in slice 8 (256 MiB sandboxes OOM'd heavy owners).

## Result — fleet at `5bb9599` (2026-09-11 19:23Z)

| Measured                               | Value                                                                                     |
| -------------------------------------- | ----------------------------------------------------------------------------------------- |
| Worker boot → admitted                 | 63–87 s; Gateway-issued start → admitted 70 s, held jobs claimed in 125 s                 |
| Peer handshake                         | 0.1–0.3 s (was 5.8–10 s)                                                                  |
| Warm MCP call, p50                     | 2.5 s (was 12.1 s)                                                                        |
| Controller restart or roll: MCP outage | 150–180 s                                                                                 |
| Overnight soak across a roll           | 20/20 jobs, 0 alerts, 0 409s                                                              |
| Slots                                  | 8 running (W1+W2), 16 with the pool up                                                    |
| Signed bundles                         | `expiresAt: null` — daily re-signing gone                                                 |
| New owner (`POST /v1/identity`)        | 0.7 s (was 502 while the controller pinned a stopped peer / dstack `/Info` 15 s on prod5) |
| From-scratch fleet (prod9 rehearsal)   | 13 min to admitted                                                                        |

Heads: PS #245 @ `919932f` = #277–#303 folded, CI green on a main base; Unity #987 @ `df5618f3` (#1041, #1042, read nonce); Gateway #100 @ `c7c73ba` (#126–#130; alias `spike-b3`, env from Doppler `dev_moksha`). Drafts: PS #299 remove Lite, Unity #1043 Desktop off Lite.

## Open (ranked)

1. **Controller SPOF** — ingress shares a restart unit with the allocator, so every restart or roll costs 150–180 s of MCP. Options and recommendations: [controller HA memo](260911-controller-ha-and-directory-resize.md).
2. **Scaler tick source** — the Gateway loop is live but ticked from a laptop until #100 reaches main (GitHub cron) or prod (Vercel cron); the signed directory is frozen at 4 members. Same memo, §2/§4.
3. **MCP gaps** — per-connection revoke needs an owner-auth port on the ingress (Kahtaf 09-11: production gate). Done: handshake fast path, `MCP_STATE_REQUIRED`, 7 d refresh.
4. **Security review follow-ups** — open: Gateway-attested revocation (trust-model decision), fail-open access log. Closed: read replay fence (#126), access-record binding (#290).
5. **Host** — prod5 guest agent answers dstack `/Info` in 15 s (prod9 0.3 s), cached at boot on our side; after a roll a member may read back `stopped` or stay `PEER_EVENTS_REJECTED` until one `phala cvms restart`. Capacity 4 → 6 after a measured run; Gateway lock is not a ceiling at 226 req/s.

## Receipts

| What                                     | Path (under `../../e2e-proof-2026-09-09/`)                                                                                  |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Slice-by-slice history and facts learned | [fleet-overnight/autoscale-slices.md](../../e2e-proof-2026-09-09/fleet-overnight/autoscale-slices.md)                       |
| Per-slice evidence                       | `fleet-overnight/autoscale-slice{1,3,4,5,6,7,8,9,10,11,12,13,14,15}/`, `rehearsal-prod9/`, `gateway-pool-loop/`, `doppler/` |
| PR and closeout reviews                  | `fleet-overnight/reviews/pr277-278-review.md`, `closeout-review-245.md`, `closeout-review-100-987.md`                       |
| Security, latency, MCP state             | `fleet-overnight/reviews/security-review-245-100.md`, `mcp-call-latency.md`, `mcp-state-across-rolls.md`                    |
