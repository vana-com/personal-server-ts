# TEE fleet controller, secure routing and workflows

Status: architecture reviewed; scoped implementation and live Moksha E2E authorized on 2026-09-09.  
Baseline: single-TEE MCP runtime `a16fd5b`; PS #272 folded into #245 at `ca4c9b1`; Unity MCP #1033 folded into #987 at `7cb42e0f`.

Related: [original architecture](260901-personal-server-gateway-enclave-architecture.md), [identity contract](260902-identity-contract.md), [earlier placement proposal](260908-tee-fleet-coordination-design.md), [single-TEE demo proof](../../personal-server-mcp-tee-demo/docs/260908-mcp-tee-demo-results.md).

## 1. Decision and scope

Introduce a central TEE deployment containing a public MCP router and a private fleet controller. The controller is the single authority for worker admission policy, health, capacity, owner placement, leases and draining. Each worker TEE keeps a local node agent responsible for its own sandboxes and keys.

If an owner's sandbox is active on worker A, all MCP requests, prewarm and background jobs for that owner use A. An unrelated worker B never receives the public MCP request and does not start another copy. Least-loaded selection happens when allocating an owner, not on every request.

Gateway (`dp-rpc`) retains protocol APIs, grants, identities, settlement, encrypted job requests and result metadata. It asks the controller for placement rather than choosing workers independently. Existing Postgres can persist placement state without making Gateway a second scheduler.

This document supersedes the earlier proposal's Gateway-owned scheduling and interchangeable ingress/worker roles. It also revises the original architecture's “no per-user lease” and pull-only/no-inbound worker assumptions. Per-job leases remain necessary.

The first fleet version uses one central deployment and manually provisioned workers. Replicated ingress, automatic CVM provisioning, live memory migration, new MCP write tools and DRK redesign are outside that first version. The user separately authorized overnight implementation and live proof with at most one Moksha controller and two Moksha workers, reusing compatible existing resources; mainnet is excluded.

## 2. Current baseline versus proposed fleet

The demo has proven ordinary Claude OAuth, seven-tool discovery, approved Spotify reads, scope denial, browser-closed sandbox recreation and recovery of the same connection after a full CVM restart. It combines ingress and execution on one CVM; it has no fleet placement authority or remote worker dispatch.

| Current implementation                                                                                                                             | Proposed change                                                                            |
| -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| [MCP service](../../personal-server-mcp-tee-demo/packages/enclave/src/mcp/service.ts) starts beside the local agent                                | Central role owns public ingress, durable connections and worker dispatch.                 |
| [MCP dispatch](../../personal-server-mcp-tee-demo/packages/enclave/src/mcp/dispatch.ts) always acquires a local sandbox                            | Router resolves placement; selected worker performs local dispatch.                        |
| [Sandbox registry](../../personal-server-mcp-tee-demo/packages/enclave/src/sandbox/registry.ts) deduplicates starts within one process             | Keep local deduplication, associate entries with fleet generation, report start/eviction.  |
| [Agent HTTP](../../personal-server-mcp-tee-demo/packages/enclave/src/agent/http.ts) exposes identity/seal, prewarm, drain and local result signing | Retain local operations, add narrowly authenticated fleet execution and lease enforcement. |
| [Claim loop](../../personal-server-mcp-tee-demo/packages/enclave/src/jobs/claim-loop.ts) polls generic work                                        | Claim only jobs for valid local owner assignments; retain attempt heartbeats/concurrency.  |
| [Gateway prewarm](../../data-gateway-fold/lib/prewarm.ts) independently selects an agent                                                           | Authenticate/rate-limit as today, then ask controller to ensure owner placement.           |
| [Gateway selection](../../data-gateway-fold/lib/tee/agent-selection.ts) chooses a least-loaded admitted node                                       | Remove independent selection from fleet-enabled paths.                                     |
| [Job claims](../../data-gateway-fold/lib/jobs/repository.ts) fence individual attempts                                                             | Preserve attempt fencing and require matching owner placement/node incarnation.            |

## 3. Components and ownership

| Component                             | Responsibilities                                                                                       | Excluded responsibilities                                          |
| ------------------------------------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| DNS and opaque public transport       | Deliver encrypted TCP to central ingress                                                               | Owner selection, MCP parsing, external TLS termination             |
| Public router inside central TEE      | TLS, OAuth, connections, token/grant validation, bounded MCP forwarding                                | Scheduling independently; remote Docker access                     |
| Private controller inside central TEE | Admission, health/capacity, placement, startup coordination, leases, drain/recovery                    | Grant minting, processing ingestion payloads                       |
| Agent on each worker TEE              | Local gVisor lifecycle, derive/unseal, hydration, local tokens, result signing, assignment enforcement | Choosing another placement; public owner/admin access              |
| Owner sandbox                         | Existing PS data/auth/tool engine and permitted jobs                                                   | Fleet scheduling, dstack/Docker sockets, general server-key access |
| Gateway                               | Protocol authorization, identities/sealed envelopes, grants, jobs, metadata, settlement                | Independent scheduling; decrypted MCP proxying                     |
| Storage                               | Encrypted source blobs and result objects                                                              | Plaintext processing or scheduling                                 |
| Web/Account/native surfaces           | Owner authentication, signatures, consent and existing collection flows                                | Keeping remote execution alive after consent                       |

Run router and controller as separate services/listeners even when colocated in one CVM. Public requests must not reach private administration through path forwarding. Central services use a local private interface; workers expose a narrow agent RPC, never a fleet-wide Docker socket.

The controller tells A to prepare an owner's sandbox; A performs and validates the operation. A retains its wallet derivation, owner-envelope unsealing and constrained result-upload signing. Raw owner roots and worker runtime sockets do not move into the controller.

The central router is necessarily trusted with the approved MCP plaintext passing through it. Scheduling does not require it to hold every owner's data-unlock secret. Manual operator tooling initially keeps cloud provisioning credentials; the public router does not need Phala account credentials.

## 4. Public-to-private routing

### MCP path

1. Claude connects to the stable `/mcp` origin. DNS-only records and opaque transport forward its TLS stream into the central TEE.
2. Router terminates TLS, validates the MCP token and resolves its immutable owner/grant binding from protected state.
3. Router asks controller to ensure placement for that owner identity and required scopes.
4. Controller returns worker A and the placement generation, or reserves A and coordinates bounded startup/readiness.
5. Router forwards a bounded execution request to A over mutually authenticated, encrypted TEE-to-TEE transport.
6. A validates owner, epoch, grant, assignment and deadline, then reuses its local sandbox. Result returns A → TEE router → Claude.

No MCP arguments or results pass through a Vercel HTTP handler. Claude's bearer terminates at the MCP resource; internal execution uses a separate service identity and original owner/grant proof, not an unvalidated forwarded bearer.

### Worker channel

Use a dedicated agent RPC listener with peer keys bound to verified TEE identity and admitted code measurements. The first fleet version uses direct RPC; an outbound worker tunnel is an optional later transport adapter. Phala passthrough can provide reachability but must preserve the inner TLS connection to its intended peer.

“Private” means authenticated and restricted, not merely an obscure public URL. Even if Internet-reachable, the worker endpoint admits only authorized peers. Gateway metadata alone cannot turn an arbitrary URL into a trusted plaintext destination. Workers return a stale-placement error rather than forwarding recursively.

Keep the existing sandbox network restrictions. Open only the reviewed agent peer channel; do not give sandboxes unrestricted fleet/network access.

### Gateway and operator channels

Gateway calls controller with authenticated protocol metadata and sealed ciphertext only. Ordinary HTTPS is sufficient for this leg because Gateway already sees that content; it still uses a dedicated service identity with limited operations. It cannot call arbitrary worker administration routes.

Operator admit/drain actions use separate authorization from public MCP, Gateway and worker calls. Controller enforces the approved measurement policy; operators still control which software identities are approved. Running the controller inside a TEE does not itself make an operator assertion into attestation.

## 5. Placement, leases and durable state

One unique placement exists per `(chainId, userPsId, identityEpoch)`:

```text
nodeId, nodeIncarnation
generation, controllerTerm
state: starting | ready | draining | dormant
leaseExpiresAt, lastActivityAt
```

Keep generation history when releasing a placement. Owner epoch, placement generation, controller leadership term and job-attempt number represent different lifecycles. A node incarnation changes when its agent restarts.

For the initial single-controller deployment, `controllerTerm` is reserved at `1`; no leader-election subsystem is required. Operate exactly one active controller and fence/stop its old instance before replacement. Placement generations and node incarnations still enforce stale-work rejection. HA later replaces the constant with elected, monotonically fenced terms.

`dormant` means the retained owner row has no assigned node or live lease. After confirmed teardown or lease expiry, a conditional release clears node/incarnation/expiry but preserves generation. A later allocation transitions `dormant → starting` and increments generation; successful hydration gives `ready`, and planned removal uses `draining → dormant`. An expired assignment may also be atomically replaced by a newer `starting` generation without an observable dormant interval.

`ensurePlacement` returns a valid existing assignment without reconsidering load. Otherwise it transactionally reserves eligible capacity and creates a new generation. Concurrent MCP/prewarm/job requests join the same starting assignment. Worker checks capacity before acknowledging; a failed start releases only the matching reservation.

The worker's local registry still coalesces starts, holds references while requests run and handles idle eviction. The controller does not replace those mechanisms. Scope/version readiness is more specific than owner readiness: reuse A while hydrating an additional authorized scope rather than starting B or assuming every scope is ready.

Workers report readiness on hydration changes, optionally batched with heartbeats: owner/epoch, node incarnation, placement generation, scope, observed data version, hydration state and observation time. Controller discards reports from obsolete assignments. `getReadiness` answers only for matching requested scopes/version policy and fresh observations; stale or missing status triggers a bounded `getOwnerReadiness` RPC to the assigned worker or returns pending/unavailable, never optimistic readiness. Worker execution still checks required data at call time.

| State                                              | Persistence and authority                                                                             |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| Identities, grants, current epoch, sealed envelope | Existing Gateway protocol records; independently checked at execution under the selected trust policy |
| Worker policy, capacity, placement                 | Controller-owned transactional records; Gateway may expose a read-only projection                     |
| Jobs/result metadata                               | Existing Gateway store, extended with controller assignment                                           |
| OAuth connections, grantee keys, tokens/codes      | Protected central state, ciphertext outside TEE, atomic authorization operations                      |
| Local containers/tokens/request references         | Worker agent/registry, reconciled or discarded against current assignment after restart               |
| TLS keys and certificates                          | Protected ingress persistence; private keys generated/retained inside TEE                             |

Existing Postgres can hold controller records with a dedicated least-privilege controller role. Gateway may validate assignments during claims/completion, but cannot independently allocate owners. For HA, code redemption and token revocation need shared transactional state: copying encrypted files or sharing a decryption key does not solve concurrent writers or stale revocation.

Initial lease experiment: 30 seconds, renewed every 10 seconds, with a measured network/clock safety margin. These are proposed test parameters, not an SLA. Workers use conservative monotonic deadlines and reject late renewals. Batch renewals per node while checking each owner generation. Ingress caches cannot outlive lease validity.

Directory transactions are trusted to serialize assignments correctly. This is not Byzantine consensus against an equivocating controller/database. Data authorization and peer verification remain independent; a placement row never substitutes for an owner grant. Signed/encrypted rows alone do not prove freshness.

## 6. Workflow: onboarding, identity and sealing

1. Web uses existing Gateway identity APIs. Gateway asks controller to select an eligible worker with the existing worker KMS/app identity.
2. Worker derives and returns public identity/evidence. Preparing identity does not require a sandbox or permanent compute placement.
3. Existing owner evidence verification, registration signature and Account delivery proceed. Registered server URL remains Gateway for SDK reads.
4. Account's existing signing path encrypts the master signature to the enclave identity. Gateway relays ciphertext via controller to an eligible worker's sealing operation. Worker returns a sealed envelope to the existing durable store.
5. Explicit enablement/prewarm obtains placement and hydrates the selected worker. Later authorized jobs/MCP calls can also wake it without the owner browser.

Preserve the current Account trust boundary: Account sees the master signature while producing encrypted delivery. Fleet coordination does not change that signing-service contract. Controller needs public metadata and encrypted envelopes, not the raw signature.

## 7. Workflow: owner writes and synchronization

1. Web, Desktop or Mobile collects data through its existing authorized collector. The proven Web pilot covers public Spotify; this design does not certify broader source/native parity.
2. Existing client/core pipeline encrypts with unchanged owner-derived keys.
3. Ciphertext uploads directly to Storage under applicable owner authorization. Client then registers the data-point/version with owner-signed AddData at Gateway. Keep upload-before-registration, retries and version-conflict handling in that pipeline.
4. Gateway publishes committed metadata for normal sync. It may notify controller that an active owner has new data; this is an optimization, not the sole correctness signal.
5. If A is active, A refreshes its sandbox. If there is no active placement, an upload need not start one; the next authorized read hydrates durable data.

Ingestion bytes do not route through the new controller. Existing hosted collectors retain their existing plaintext boundary; this document does not claim every collection happens locally. Reading fresh data must verify the requested version/read policy, even if an update notification was lost.

MCP remains read-only. Builder writes and additional owner-ingestion sources are separate capabilities, not enabled by adding fleet routing.

## 8. Workflow: builder/SDK reads

1. SDK submits the existing signed/encrypted job request to Gateway. Gateway performs current protocol admission and queues owner/grant/scope/version/deadline metadata.
2. Controller observes queued owners through a restricted metadata interface/view, resolves placement and records assignment. It need not decrypt the request.
3. A claims only jobs assigned to its valid placement. Claim transaction verifies node/incarnation, placement generation and job state, then creates the existing fenced job attempt.
4. Gateway delivers existing signed request and sealed identity material. A validates current identity/grants, derives/unseals locally, and starts/reuses the sandbox.
5. Sandbox reads authorized data, encrypts the result to the builder's key, obtains the existing local agent's constrained upload signature, and uploads ciphertext directly to Storage.
6. Gateway accepts completion metadata only from a valid attempt and placement. SDK fetches the result object and decrypts at the builder backend.

Neither central router nor controller carries the SDK result body. Controller reservation and job claim may be two steps, but the claim must transactionally reject obsolete assignment. Preserve job idempotency/attempt fencing; routing alone does not establish stronger historical-version guarantees than the current reader implements.

A generic worker cannot claim A's owner's job just because it is idle. Persist fleet enrollment per owner identity in Gateway's transactional store. Generic claim SQL must atomically exclude jobs belonging to enrolled owners; fleet claim SQL requires enrollment plus a valid matching assignment. Enrollment and claims serialize on the same owner record (or an equivalent transactional exclusion), and enrollment waits for or fences any already-claimed legacy work. A deployment flag or application-side precheck alone cannot enforce this during a mixed rollout.

## 9. Workflow: consent and prewarm

Web creates owner-signed grants through the existing Account contract and reads durable source/grant metadata without requiring Lite. Authenticated prewarm now uses Gateway → controller → assigned worker, so consent cannot warm B while MCP/jobs use A.

Acceptance of prewarm is asynchronous, not proof of hydration. UI checks bounded readiness for required scopes and shows retryable failure without falling back to Lite. Existing MCP connections and authorized jobs can independently trigger wake-up. Controller obtains the current sealed envelope through a new private Gateway `getSealedEnvelope(userPsId, epoch)` operation and delivers it to the assigned worker. This is a new interface: today envelopes are delivered only through job claims and Gateway-initiated prewarm, while public identity reads expose only sealed status. Authenticate the controller with a dedicated scoped service credential; bind the request to chain/owner identity, epoch and current assignment. Gateway checks live registered/sealed identity and returns the matching ciphertext envelope plus identity metadata, or a typed missing/retired/epoch-mismatch failure. Rate-limit and audit metadata only. Workers recheck current identity and grant state before unseal; possessing an envelope is not read authorization. Wake-up must not depend on a browser, a queued job or a cache on the first demo node.

## 10. Workflow: MCP setup, calls and recovery

### Connection and OAuth

1. Claude discovers the stable MCP resource and starts the ordinary OAuth/PKCE flow at TEE ingress.
2. Router creates pending authorization and per-connection grantee in protected state. Web loads metadata directly from that origin.
3. Owner approves exact scopes with existing signing. Prewarm establishes placement/readiness; Web posts grant references to the TEE approval endpoint.
4. Router validates signed owner/grantee/scopes and current grant state before binding the connection. Code redemption is atomic/single-use.
5. Claude receives a token for the stable MCP resource. The connection identifies an owner, not a worker, so changing workers requires no new consent.

Web/Account can see their existing consent metadata and signatures. Tool payloads do not traverse those Vercel surfaces. Preserve the tested client-compatible protocol; this design neither upgrades MCP automatically nor claims untested refresh features are implemented.

### Tool execution

Router authenticates, resolves owner placement and sends A an execution envelope: owner/epoch, original grant proofs and connection context, generation/term, request ID, deadline and bounded MCP payload. A independently validates authorization and executes existing tools through the local handler.

The current engine requires the connection record, including its grantee signing private key, to sign authorized data reads. The remote `executeMcp` contract explicitly carries that connection/grantee material inside the protected TEE channel; it remains ephemeral in worker/sandbox memory and is never logged or persisted outside protected central state. This preserves the existing sandbox signing contract while adding a verified remote hop; it is not the owner data-decryption root. General server keys/unlock roots stay local. A returns raw approved blocks/snippets/files through the TEE router to Claude. Both network hops must preserve their intended TEE TLS boundary.

A stale-placement error invalidates the router cache and permits a bounded re-resolution. Workers never recursively forward. Read-only retries recheck authorization and placement; do not generalize this to future side-effecting tools or exactly-once execution.

### Moving or restarting

After A's valid lease ends, controller can assign B with a new generation. Router retains the same connection/grantee and public URL. B receives current sealed identity material through controller preparation and cold-starts. No browser prewarm, new OAuth or data-key change is required.

An ingress restart restores protected connections and reconciles existing placements. It must not reset generations or blanket-reassign owners. Connection recovery and worker recovery are separate mechanisms.

## 11. Workflow: revocation, deletion and derived work

Owner revocation stays authenticated at Gateway. Controller invalidates the retired epoch's placement and tells worker to stop admission, destroy the sandbox and discard its cached envelope. Router invalidates/denies affected connections under current grant/identity state. Missed events are caught by current-state checks; placement freshness alone cannot authorize a revoked read.

Re-enable uses the existing next-epoch identity contract and a new placement. Old generations/cached envelopes cannot reactivate the retired epoch. Existing tombstone/deletion checks remain in sync/storage and must also apply to warm reads. Already delivered plaintext/ciphertext cannot be recalled; this is not cryptographic erasure or a new root-key rotation design.

Supported derivative/inference operations would use the same owner placement and existing authorized execution/encrypted inference path. The scoped Web enclave pilot excludes derivative questions. Fleet coordination does not implement or enable that missing workflow.

## 12. Failure and lifecycle rules

| Event                          | Behavior                                                                                                       |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| Concurrent first requests      | One placement and local start; bounded join/retry.                                                             |
| A unreachable with valid lease | Do not start B; wait or fail within request deadline.                                                          |
| Renewal failure                | A stops admission and aborts/fences work before conservative expiry.                                           |
| Expired lease                  | Controller advances generation; B cold-starts from durable data.                                               |
| Old A returns                  | Old incarnation/generation cannot renew, release new placement, commit or return accepted work.                |
| Idle eviction                  | Stop sandbox, then compare-and-swap release; race with new request resolves through local registry/controller. |
| Planned drain                  | No new owners; finish bounded active calls, stop/release, cold-start elsewhere on demand.                      |
| New scope/version on warm A    | Hydrate within A; preserve explicit read-version semantics.                                                    |
| Gateway/DB outage              | No new authority from stale state; existing work bounded by both auth freshness and placement lease.           |
| Agent restart                  | New incarnation; reconcile/fence old containers before accepting assignment.                                   |
| Controller restart             | Restore/reconcile leases, avoid duplicate allocation; later HA uses fenced leadership term.                    |

Fencing is checked before execution and before accepting a result/commit, not only at startup. Leases target one authorized executor, not exactly-once computation: a paused old process may physically remain. Terminate streams at lease loss; delivered bytes cannot be withdrawn.

One central CVM is initially an availability dependency. Replicated routers later require shared transactional OAuth state and proven TLS renewal/failover. Controller replicas need one elected leader with a monotonically fenced term. Neither capability is established by the current instance-bound demo DNS.

## 13. Private interfaces

These are proposed names, not existing routes or finalized wire schemas:

| Interface                                         | Caller → callee                           | Required binding                                                                                                                            |
| ------------------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `registerWorker`                                  | Worker → controller                       | Fresh attestation bound to peer public key/proof of possession, app/compose identity, node/incarnation and capacity; pending until admitted |
| `admitWorker`, `drainWorker`, `removeWorker`      | Operator → controller                     | Separate operator credential; node/incarnation and approved policy/evidence identity; generation-safe lifecycle                             |
| `ensurePlacement`, `getReadiness`                 | Router/authenticated Gateway → controller | Authorized owner/epoch, requested scopes/version policy, deadline/idempotency                                                               |
| `getSealedEnvelope` (new Gateway operation)       | Controller → Gateway                      | Dedicated service credential; chain/owner/epoch and valid assignment; matching live identity metadata plus ciphertext only                  |
| `heartbeat`, `renewPlacements`, `reportReadiness` | Worker → controller                       | Peer identity, incarnation, term/generations; scoped observed version, hydration state and observation time                                 |
| `getOwnerReadiness`                               | Controller → assigned worker              | Owner/epoch/generation, requested scopes/version policy and bounded deadline                                                                |
| `prepareOwner`, `drainOwner`                      | Controller → worker                       | Owner/epoch/generation, deadline, sealed envelope; no arbitrary commands                                                                    |
| `executeMcp`                                      | Router → worker                           | Owner/grant proofs, connection record with ephemeral grantee signing key, placement/term, request ID/deadline, bounded payload              |
| `assignJob`, assignment-aware claim               | Controller → store; worker → Gateway      | Persisted owner enrollment, job/node/incarnation, placement and independent attempt fencing                                                 |
| `prepareIdentity`, `sealDelivery`                 | Gateway via controller → worker           | Existing identity contract/ciphertext; worker recomputes owner binding                                                                      |

Scope public client, Gateway, router, controller, worker and operator credentials separately. Expose distinguishable errors for stale placement, expired authorization, unavailable readiness and capacity; never put payloads/tokens/root material in public logs.

## 14. Packaging, KMS identity and migration

Migrate existing Gateway `teeNodes` records as pending controller candidates, not automatically trusted peers. Each worker must register fresh peer-key-bound evidence and pass admission before receiving fleet work. Gateway retains only the needed read-only admission projection for protocol/claim checks; its old admit/drain endpoints must delegate to controller or be disabled for migrated nodes. The old shared bearer alone cannot authenticate the new plaintext-bearing worker RPC.

Keep code in `personal-server-ts/packages/enclave`: add controller/placement and peer-transport modules and central bootstrap/compose; retain agent/sandbox modules. `server` owns HTTP/MCP composition, `core` reusable protocol/auth/tools, Gateway assignment-aware APIs, Unity stable-origin consent. Preserve dependency direction and update public exports where seams change.

For the physical split, retain existing worker `app_id`, KMS paths and owner identities. Recommend a separate app identity for the dedicated central deployment so its scheduler/router cannot directly derive worker roots. The combined demo does not provide that separation; modules or containers under one app do not create KMS isolation.

Moving OAuth state to a new central app requires a deliberate service-state migration. Transfer connection/grantee/token records through a verified TEE-to-TEE channel, re-encrypt under the controller key, preserve identifiers/bindings and fence the old writer. Copying ciphertext under a different app key cannot work. Do not dump secrets onto an operator machine or require reauthorization merely to avoid migration work.

TLS can be reissued inside the new ingress for the same hostname with coordinated DNS/CAA. Avoid private-key export. The demo uses TLS-ALPN and instance-bound routing; a new central instance needs a deliberate route update, and HA certificate/ACME coordination remains separate work. No owner DRK redesign is required.

Use an explicit per-environment rollout mode. For selected owners, switch prewarm, MCP and job placement together. Reconcile/drain existing local sandboxes before reservation; do not run legacy generic claimants alongside controller assignment for those owners. Rollback stops dispatch, drains/fences assignments and restores a verified compatible deployment without resetting generations, losing connection state or silently registering Lite.

## 15. Implementation order and acceptance

1. Placement/capacity transactions and simulated workers: concurrent reservation, renewal, stale generation, incarnation and capacity tests.
2. Worker registration/admission, private peer RPC and local-agent refactor: wrong peer/owner/epoch/grant rejects before unseal/execution; single-node behavior retained. Add private envelope retrieval and scoped readiness reporting; prove MCP-only cold wake without cached envelope, browser prewarm or a queued job.
3. Controller-owned prewarm and job assignment: generic claim cannot steal another node's owner.
4. MCP remote dispatch: request for A's owner executes on A, B starts nothing.
5. Simulated faults plus write/read freshness, extra-scope hydration, late results, drain, deletion/revocation and restart.
6. Separately authorized live A/B proof with real Claude plus SDK jobs and owner ingestion; validate peer TLS and unchanged client connection across replacement.
7. Central state/DNS migration and rollback proof; then consider replicated central services and automatic provisioning.

| Acceptance case              | Evidence                                                                                |
| ---------------------------- | --------------------------------------------------------------------------------------- |
| Existing sandbox on A        | MCP reuses A's container; B starts none.                                                |
| MCP + job + prewarm together | One placement/generation and one startup.                                               |
| Upload with no sandbox       | Owner write succeeds; next read hydrates committed data.                                |
| Upload while A warm          | A refreshes under requested version policy without duplicate placement.                 |
| A partition → B replacement  | No accepted obsolete response/commit; same Claude connection works.                     |
| Router restart               | Connections persist and existing placement reused.                                      |
| Worker restart               | Incarnation reconciled; no competing executor or stale local token.                     |
| Revocation                   | No wake/read authorized solely by stale placement.                                      |
| Public/private boundary      | Client works; wrong peer/admin denied; external paths contain ciphertext/metadata only. |

Record request/job correlation, pseudonymous owner identity, generation, node/incarnation, sandbox ID, startup/hydration time, renewal failures, queue age and routing errors. Monitor central availability/capacity. Do not log raw MCP bodies as routine diagnostics.

## 16. Standards and remaining decisions

This combines [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization), [remote attestation architecture](https://www.rfc-editor.org/rfc/rfc9334.html) and [Phala TLS passthrough](https://docs.phala.com/phala-cloud/networking/tls-passthrough). MCP does not specify a confidential fleet topology. Claude uses normal HTTPS; operator-verified attestation is not proof that Claude independently checks hardware evidence on every connection.

Finalize private RPC schemas, peer admission/refresh policy and Postgres role/transaction boundaries before implementation. Measure lease/retry budgets. Before HA, decide transactional protected state, leader election and certificate coordination. Existing v1 key contracts and controlled-pilot trust assumptions remain; this proposal does not turn broader security redesign into a new release prerequisite.

## 17. Phala naming and future autoscaling

Use network-qualified service names in Phala, logs, manifests and operator tooling:

| Role                       | Moksha                              | Mainnet example only                 |
| -------------------------- | ----------------------------------- | ------------------------------------ |
| Initial central deployment | `moksha-personal-server-controller` | `mainnet-personal-server-controller` |
| First worker               | `moksha-personal-server-worker-1`   | `mainnet-personal-server-worker-1`   |
| Additional worker          | `moksha-personal-server-worker-2`   | `mainnet-personal-server-worker-2`   |

The controller name covers its colocated router/controller services. Name is a human label, not KMS identity or authorization: do not change a worker `app_id`, derivation path, owner identity or registration merely to rename it. Preserve provider UUID and app/instance references in the deployment inventory. Logical node name is stable across restarts; node incarnation still changes. Allocate worker ordinals monotonically per network and do not recycle retired names for a different CVM. Record network, role, source SHA, image digest, app ID and instance ID alongside each name. Mainnet examples do not authorize mainnet provisioning.

The controller is the natural future autoscaling decision-maker because it knows reserved/available slots, pending owner startups, queue age, saturation and drain state. Keep a capacity-policy seam now, but use manual desired worker count initially. No autoscaling implementation is required for first fleet E2E.

Later, separate policy from cloud provisioning:

1. Controller computes a desired worker count within configured minimum/maximum and spend limits, using sustained queue/startup pressure and reserved capacity. Count provisioning workers to avoid repeated scale-out while boots are pending.
2. A restricted provisioning reconciler applies that desired count through Phala APIs. It may run outside the TEE because it handles deployment metadata, not user payloads or unlock keys. Keep its provider credentials out of the public router.
3. New workers register with peer-key-bound attestation and pass admission before receiving placements. Scale-out must preserve the approved worker app identity/key compatibility.
4. Scale-in selects a worker, stops new allocations, drains placements and verifies no active leases/jobs/streams before termination. Never kill a busy worker merely because average CPU is low.
5. Cooldowns, hysteresis, a spare-capacity target and idempotent provisioning prevent oscillation and duplicate resources. Scaling is disabled if controller leadership/desired state is uncertain.

An active owner stays on its current worker during scale-out. No live memory migration is needed. Central ingress/controller capacity is monitored separately; adding workers does not fix a saturated or unavailable router. Minimum workers of zero requires an always-on central service and a separately tested cold-start/user-timeout policy. Leave that policy disabled initially.

## 18. Implementation handoff and overnight regression gates

The [implementation and E2E handoff](260908-tee-fleet-implementation-handoff.md) supplies agent ownership, exact baseline references, preflight requirements, existing-workflow regression checks, rollout limits and stop conditions. This design supplies architecture; the handoff supplies the execution contract. Three Astra implementation lanes were dispatched following the user's overnight approval.
