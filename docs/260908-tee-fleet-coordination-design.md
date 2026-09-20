# TEE fleet coordination and owner affinity

> Superseded topology and ownership: see [TEE fleet controller, secure routing and workflows](260908-tee-fleet-controller-design.md). The newer proposal puts routing and scheduling in dedicated central TEE services, retains local agents on workers, and makes Gateway a protocol/queue service rather than a second scheduler. This earlier note is retained for placement and failure-design history.

Status: proposed design; no fleet implementation or multi-CVM deployment authorized by this document.  
Context: the single-TEE MCP demo is proven. The next requirement is that a request uses the owner's existing sandbox even when it enters through another TEE.

## Decision

Maintain one authoritative placement for each `(chainId, userPsId, identityEpoch)`. MCP dispatch, owner prewarm and background job execution must all use that placement. A public TCP balancer chooses an ingress TEE; it does not choose the owner’s execution TEE.

If the owner is running on A and a request arrives at B, B authenticates it inside the TEE, resolves placement A, and forwards it over an authenticated encrypted TEE-to-TEE connection. A reuses its local sandbox. B must not create another sandbox because it has spare capacity or because A is slow to respond.

Start with the existing ingress on one TEE and several eligible worker TEEs. This achieves owner affinity without first building replicated ingress. The ingress is an explicit availability bottleneck until the later HA step; worker failover and ingress failover are separate capabilities.

## What changes from today

- [MCP dispatch](../../personal-server-mcp-tee-demo/packages/enclave/src/mcp/dispatch.ts) always calls its local sandbox registry.
- [Sandbox registry](../../personal-server-mcp-tee-demo/packages/enclave/src/sandbox/registry.ts) deduplicates startup and tracks active requests only inside one process.
- [Gateway agent selection](../../data-gateway-fold/lib/tee/agent-selection.ts) chooses a least-loaded admitted node without owner affinity.
- [Job claim](../../data-gateway-fold/lib/jobs/repository.ts) claims queued work without restricting it to the owner's assigned node. Its per-job attempt fencing remains useful but does not provide per-owner placement.

The September architecture note's statement that v1 needs no per-user lease does not cover this fleet requirement. This proposal adds an owner placement lease; it does not replace the existing job lease.

## Components and authority

| Component                                        | Responsibility                                                                                                                                                       |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Public ingress transport                         | Forward encrypted TLS records to a healthy ingress. No HTTP parsing or owner selection outside a TEE.                                                                |
| TEE MCP ingress                                  | Terminate TLS, authenticate OAuth connection, verify owner/grant binding, resolve placement, dispatch locally or to the assigned TEE.                                |
| Gateway placement directory in existing Postgres | Atomically reserve, renew and release owner placement; publish node health/capacity and lease metadata. No MCP bodies, result plaintext or TLS/grantee private keys. |
| Worker agent inside each TEE                     | Own its placement leases, start/reuse local sandboxes, enforce lease generation and authorization, drain safely.                                                     |
| Existing local sandbox registry                  | Coalesce concurrent starts, hold local request references, enforce local resource limits and evict idle sandboxes.                                                   |

The directory is trusted to serialize placement correctly. It cannot authorize reads or supply an unverified destination for plaintext. Cryptographic grant checks and destination verification remain independent. A malicious/equivocating directory is outside the single-executor guarantee of this design; a metadata signature alone would not solve equivocation. Do not expand the existing refuse-only claim into a Byzantine scheduling guarantee.

## Placement record

One unique record per owner identity:

```text
chainId, userPsId, identityEpoch
nodeId, nodeIncarnation
generation                       # monotonically increasing fencing value
state                            # starting | ready | draining | dormant
leaseExpiresAt                   # database-controlled
lastActivityAt
```

Keep the generation when placement becomes dormant; never reset it by deleting and recreating the row. `identityEpoch` is the owner's key lifecycle; `generation` is a placement lifecycle. They are not interchangeable. A node incarnation changes when its agent restarts, preventing a restarted agent from inheriting old work accidentally.

Node registry records carry independently checked destination identity and health/capacity. Do not copy arbitrary routing URLs into authorization decisions. A `ready` hint improves routing but cannot replace the worker's actual readiness check.

## Request and startup flow

1. Ingress validates the MCP bearer, immutable owner binding and current grant/identity state. It does not route using a caller-supplied owner alone.
2. Resolve a valid owner placement. If A holds it, dispatch to A with owner identity and placement generation. A verifies it and acquires the existing local sandbox.
3. If no valid placement exists, atomically reserve an eligible admitted node and increment the generation. Reserve capacity in the same admission process so concurrent owners cannot all select one apparently empty node.
4. The chosen node acknowledges that generation, establishes its conservative lease deadline and starts the sandbox. Simultaneous requests see the same `starting` record and wait within a bounded deadline; they do not choose additional nodes.
5. The node marks the placement ready after the relevant storage/sync readiness checks. MCP keeps bounded timeout/error behavior. An unfinished startup is not a successful empty read.

Use a short-lived ingress cache only while the placement lease remains valid. On an authenticated stale-placement response, invalidate it and resolve once more. Limit forwarding to one worker hop; workers return a stale-placement response instead of forwarding recursively.

## Integrate every execution entry point

**Prewarm:** resolve/reserve the same placement before sending the authenticated sealed identity to a node. Cache the envelope at that node only after current identity validation. OAuth ingress state and worker wake-up material must not accidentally remain available only on the first demo node. On replacement, use the existing authenticated identity/prewarm delivery mechanism; do not send the raw unlock signature through Gateway.

**Jobs:** claim only jobs for owners assigned to the claiming node. For unassigned owners, job claim may reserve placement atomically with the claim. Preserve per-job attempts, idempotency and result commit checks; also bind the attempt to the owner placement generation. A generic worker must not steal A's owner's job while A's placement is valid.

**MCP:** resolve placement before the current local dispatch operation. Local and remote requests converge on the same worker handler and registry key. Remote dispatch carries the verified owner/connection/grant context over the protected channel; the worker independently checks owner, epoch, grants and placement before execution.

## Idle, draining and node failure

| Situation                                    | Behavior                                                                                                                                                                |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A is healthy and owns an active sandbox      | Every execution path keeps routing there. Load changes do not move an active owner.                                                                                     |
| Concurrent first requests                    | One atomic reservation; one local start; other requests wait or receive a bounded retryable startup error.                                                              |
| A temporarily unreachable with a valid lease | Fail or retry within the request deadline. Do not start on B immediately.                                                                                               |
| A has lost its lease                         | Stop admission and abort/fence ongoing work before the conservative deadline; suppress stale responses/results.                                                         |
| A's lease expires                            | Directory can reserve B with a higher generation; B cold-starts from durable encrypted storage.                                                                         |
| Idle eviction                                | Stop sandbox, then release placement with compare-and-swap on generation. Optional dormant affinity can prefer A later, but cannot block capacity recovery.             |
| Operator drains A                            | Stop assigning new owners; let bounded active requests finish, then stop/release each sandbox. Move on the next request. No live memory migration in the first version. |
| A returns after replacement                  | Its old incarnation/generation cannot renew, release, commit results or serve new work.                                                                                 |

Node heartbeat and owner lease are distinct. An alive node may have lost a particular sandbox. Batch owner lease renewals per node to reduce control-plane traffic; retain per-owner generation checks.

Choose lease/renewal intervals after measuring the control plane. A candidate is 30-second leases renewed every 10 seconds, with an explicit clock/network safety margin; these are initial experiment parameters, not an availability promise. Compute local conservative deadlines with monotonic time and bounded renewal latency. A slow or uncertain renewal cannot extend local authority. Check authority before execution and again before releasing a result. Ingress must reject a late response from an obsolete generation.

This targets one authorized executor, not exactly-once computation or rollback of bytes already delivered. A paused/partitioned old process may physically exist; generation checks prevent accepting its stale work. Streaming responses must be interrupted at lease loss, and already delivered bytes cannot be withdrawn. Do not automatically replay operations with side effects after an ambiguous failure; today's read-only tools allow more limited retries.

## TEE-to-TEE transport

Use an authenticated channel with peer identity bound to admitted, verified application/compose evidence. A URL or Gateway node row alone is insufficient. Keep private keys generated and retained inside TEEs. Any intermediate Phala or public routing hop must carry ciphertext; do not put ordinary Vercel HTTPS or default externally terminated HTTP forwarding between workers.

The worker endpoint is a narrow MCP execution RPC, not a public admin proxy. Bind each request to owner identity, placement generation, deadline and request ID. Revalidate the original grant rather than accepting the ingress's owner claim alone. Respect the existing restricted network policy through a specific reviewed peer channel, not unrestricted sandbox egress.

## OAuth durability and ingress HA

The first worker fleet can keep the proven single ingress and its encrypted durable state. Its connection-to-owner lookup stays authoritative regardless of the chosen execution node. Preserve the existing external URL and consent flow.

Before adding interchangeable ingress replicas, replace the local single-writer file with transactional shared persistence for encrypted connection state. Code redemption, token revocation and record versions require atomic operations; copying files or sharing a decryptable key does not solve concurrent writers or stale revocation. TLS certificate issuance, renewal and failover also need their own proof. Do not claim the demo's instance-bound DNS route already balances ingress replicas.

## Implementation order and acceptance

1. Add placement transactions and two simulated agents; test competing reservation, renewal, release, capacity and stale generations.
2. Route prewarm and jobs through placement, retaining local registry deduplication and existing job fencing.
3. Add authenticated remote MCP dispatch. Test request entering B when A already owns the sandbox: only A executes; B starts none.
4. Test lease loss/partition, stale cache, late result, node restart/incarnation, idle eviction, drain and identity revocation/re-enable. Directory outage must not trigger competing startups.
5. After separate authorization for multiple live CVMs, prove actual A/B routing, peer TLS identity and failover with one ordinary Claude connection. The previous one-CVM limit still applies until then.
6. Add replicated ingress only when its separate availability work is needed; verify OAuth/TLS persistence and renewal under replica failure.

Record owner placement, generation, node incarnation, sandbox ID and request/job correlation in metadata-only diagnostics. The key acceptance assertion is: while A's placement remains valid, MCP, prewarm and jobs for that owner all reuse A, including when the public request arrives elsewhere.
