# Fleet v1 private contract

Controller term is 1 and only one controller may write. Owner key is
(chainId,userPsId,identityEpoch). Dates are ISO UTC; generations are positive safe
integers retained after release. Wire types live in contracts.ts.

Gateway controller API: POST /v1/fleet?action=enroll|assignment|release|pending,
authenticated by the dedicated FLEET_CONTROLLER_GATEWAY_TOKEN. Enrollment fences
legacy claims before acknowledgment. Assignment publication is CAS: newer
generation or renewal of precisely the same node/incarnation/generation/term.
Worker envelope retrieval uses /v1/fleet?action=envelope, existing node auth,
and the exact live assignment. Response is FleetEnvelopeResponse. No envelope
cache is required for MCP-only wake. Jobs carry that same assignment on every
claim/heartbeat/fail/complete. Owner/grant validation remains independent.

Controller Gateway listener: POST /fleet/v1/ensure {owner,scopes}; POST
/fleet/v1/readiness {owner,scopes}; POST /fleet/v1/identity and /fleet/v1/seal
relay existing identity/seal payloads to an admitted worker. Dedicated Gateway
credential permits these operations only. Separate admin listener/credential
permits /fleet/v1/admit and /fleet/v1/drain. Public ingress mounts neither.

Admin POST /fleet/v1/status returns {controllerTerm,paused,config,nodes,
placements}. Each entry of `nodes` carries `live`, the number of placement rows
holding an unexpired lease on that member — the only count of occupied slots;
`placements` rows are raw and may include an expired lease the next renew tick
has yet to reap. Each entry also carries `lastAdmission`, either null or
{code,since,attempts}. `code` comes from a closed allow-list of reviewed
verifier and identity refusals — PEER_EVENTS_REJECTED (a second mr-kms event),
PEER_MEASUREMENTS_REJECTED, PEER_TCB_REJECTED, PEER_NOT_ADMITTED,
PEER_BINDING_REJECTED, PEER_DEBUG_TDX, IDENTITY_MISMATCH, ADMITTED, and
UNAVAILABLE for anything else — so no remote-influenced error text is exposed.
`config` is {issuedAt,expiresAt,composeHash,appId,instanceId} for
the controller's own verified bundle and identity; it never contains bundle
environment values. A signed deployment-lifetime bundle serializes `expiresAt`
as literal null, which is not the same as an absent field. Worker GET
/agent/v1/health carries the same window as `configIssuedAt`/`configExpiresAt`;
a null `configIssuedAt` means the agent runs unsigned.

Worker adapter owns fleet/worker*.ts and agent/jobs/sandbox changes. Controller
owns contracts.ts, fleet/peer*.ts, placement/controller/router/migration and
central/. Peer transport invokes adapter methods prepare, renew, readiness,
execute, release. Its dispatcher receives an already authenticated peer identity;
worker requires admitted controller role. Transport uses fresh challenge-bound
TDX evidence binding ephemeral encryption key, peer identity and both challenges;
all RPC contents and responses are encrypted and integrity protected. No bearer
credential authorizes peer RPC. Request deadline, generation, incarnation and
local monotonic lease guard execution and response acceptance. The transport
verifier must validate quote signature/TCB, report data and admitted measurements.

Protected MCP migration uses that same verified channel; old writer is fenced
before a snapshot is released, target reencrypts with its own dstack key, and
operator tooling receives only counts/digests. No secrets leave either TEE.

## Authenticated boot configuration

`FLEET_SIGNED_CONFIG` must contain `base64:` followed by canonical standard
base64 of the complete UTF-8 JSON `{payload, signature}` document (including
padding). The whole wire value is bounded to 128 KiB. Raw JSON is rejected:
dstack 0.5.x environment-file escaping damages backslashes in nested JSON
strings. Encoding changes only transport; the decoded document still passes
all signature, schema, lifetime and TEE identity checks. Signers must verify
this exact wire value locally before submitting encrypted environment values.

Worker bundles may set `SANDBOX_DATA_SIZE` to resize each sandbox's `/data`
tmpfs; unset keeps the previous 256m mount exactly. It trades scratch space for
agent headroom when a signed bundle raises per-instance capacity. Adding a key
to the allow-list needs no compose or attestation change.

Dstack encrypted environment values are not measured or authenticated. Every
fleet application boot verifies an operator Ed25519 signature before deriving
protected state keys or opening admin, migration, or peer listeners. The complete
runtime configuration is returned as a new environment map; unsigned values are
never merged. The signed payload binds role, node, current app and instance and
accepts an explicit signed `expiresAt: null` for deployment-lifetime configuration,
so ordinary future restarts need no periodic re-signing. Existing timestamp-valued
`expiresAt` bundles retain their maximum 24-hour validity window and startup expiry
checks; `issuedAt` is always validated, including future-issued rejection. Null is
part of the authenticated payload, never an unsigned environment override. To
migrate an existing deployment, re-sign its reviewed complete configuration once
with `expiresAt: null` and verify it locally before replacing its encrypted bundle.

A non-expiring bundle can be replayed indefinitely on its bound app/instance;
finite bundles only within their signed window. Neither claims hardware monotonic
rollback defense or terminates an already-running process when its boot window
ends. Changes to configuration still require a newly signed complete bundle.

Render the reviewed source commit, base image digest and operator SPKI public key
as literal measured compose text. Templates use explicit REPLACE_WITH markers;
no marker may remain at deployment. Only the signed bundle is passed through
from the provider environment. Do not forward NODE_OPTIONS, alternate source
refs, or policy/admin credentials outside the bundle. App and instance binding
uses public dstack info after signature validation; all private state remains
unopened until that comparison passes. This applies on every process restart.

The paused central role permits an empty signed worker directory for initial
attestation. Stage exact worker policies through a new operator-signed bundle,
restart and verify fresh measurements before admitting peers or moving state.
For a net-new deployment with an empty MCP state, sign
`MCP_MIGRATION_REQUIRED=0`; it starts paused and may be activated after worker
admission without an import. Set it to `1` only when returning to an existing
protected MCP state, which must be imported before activation.

## Explicit KMS CA rotation policy

The default `measurementMode: "exact"` (or omitted mode) still pins MRTD and all
four RTMRs. The optional `measurementMode: "dstack-0.5.9-events"` changes the KMS
trust boundary: the operator trusts the exact approved KMS CA to rotate its
instances. It does **not** assert that the KMS VM measurement remains unchanged.
The measured guest authenticates that CA before accepting KMS keys; its
`key-provider` event records the CA SPKI. `mr-kms` may then vary between boots.
This policy must be explicit in the operator-signed complete configuration.

Event mode uses `rtmrs: [rtmr0, rtmr1, rtmr2]` plus exact `mrTd`, `osImageHash`
and `keyProviderSpki` (lowercase DER SPKI hex). It replays the entire bounded event
log into all four verified quote registers. Firmware entries are structurally
validated; their register values remain exactly pinned. Every runtime event
payload digest is recomputed using the dstack 0.5.9 algorithm. GetQuote's empty
runtime digest fields are reconstructed from their retained event type, name and
payload before replay; a supplied digest must match. Firmware digests remain
mandatory. Certificate logs with populated digests follow the same checks.
Exactly ten RTMR3
events must appear in order: system-preparing, app-id, compose-hash, instance-id,
boot-mr-done, mr-kms, os-image-hash, key-provider, storage-fs, system-ready.
The sentinels have empty payloads; app/compose/instance/OS match policy exactly;
key-provider is exactly the canonical KMS CA JSON; storage-fs is `zfs`.
Only the `mr-kms` payload may vary, and it must be exactly 32 bytes. Unknown,
missing, reordered or duplicate runtime events are rejected. The log must match
this fresh verified quote; public provider metadata alone supplies no authority.
Intel chain/TCB, DEBUG rejection and fresh report-data key binding are unchanged.

The deployed dstack OS 0.5.9 pins source commit `282eeb27d22d8f091ad0fa5a90e638f85cf68751`.
See its [event digest](https://github.com/Dstack-TEE/dstack/blob/282eeb27d22d8f091ad0fa5a90e638f85cf68751/cc-eventlog/src/runtime_events.rs)
and [KMS authentication and measurement](https://github.com/Dstack-TEE/dstack/blob/282eeb27d22d8f091ad0fa5a90e638f85cf68751/dstack-util/src/system_setup.rs).

## Peer protocol and approved identity

The reachability URL uses ordinary HTTPS. Inner confidentiality and mutual
identity use a one-shot attested X25519 channel; an outer Phala proxy observes
only public evidence and encrypted packets. Each RPC performs a fresh handshake:

1. Caller sends its identity, random 32-byte challenge and ephemeral X25519 SPKI.
2. Responder contributes an independent challenge/key and session ID, then quotes
   SHA-512(domain || serialized complete transcript) as all 64 report-data bytes.
3. Caller runs Intel DCAP signature/certificate/TCB verification and compares
   MRTD and RTMRs through its approved measurement policy. It compares the exact intended
   role/node/app/instance/compose and previously discovered node incarnation
   before encrypting any RPC. Discovery is the only unpinned operation and
   returns public identity only. Caller quotes the same complete transcript.
4. Request and response use separate HKDF-SHA256 directional AES-256-GCM keys.
   Each is used exactly once with a fixed 96-bit nonce; the transcript digest is
   AAD. Responder consumes its bounded, 30-second session before verification,
   verifies caller evidence, and decrypts only after admission. Replaying a call,
   swapping a response/session, or changing either key/challenge fails closed.

No caller-supplied event log or app label replaces measured-boot verification.
Policy pins include all four exact RTMRs; after measured-boot changes the operator
must deliberately refresh reviewed public measurements. The default Intel TCB
policy accepts UpToDate only; any exception is explicit policy, never fallback.
Every RPC refreshes evidence, so there is no long-lived unverified peer session.
Bodies are limited to 8 MiB before encryption and bounded on the wire. Renewal
has an eight-second total client budget; execution/migration have 120 seconds.
Peer errors never include request plaintext, OAuth material, or results in logs.

## Directory and release

The first singleton uses fsynced atomic snapshots on its protected CVM volume,
with a kernel flock in the central launcher. This is the permitted dedicated
controller store rather than a new Gateway scheduler. Generation tombstones and
operator drain decisions persist across restart; readiness observations do not
survive and must be freshly queried. Admission verifies a fresh peer before
installing its runtime adapter.

Central declares every configured member at boot, before its first attestation
attempt. A declared entry carries an empty incarnation and `unavailable: true`,
installs no runtime adapter, and is therefore never selectable; it exists so a
stopped warm-pool machine is visible in status and can be durably drained while
it is down. Attestation later admits the same entry and keeps its drain
decision. Directory entries the signed policy no longer lists are pruned at
boot, except one a placement row still references, which is retained and warned
about. Repeated admission failures are logged edge-triggered: the first failure
of a code warns, repeats of that code are debug, and admission logs info. Exactly one active controller app is an operating
invariant; stop/fence its old instance before any replacement.

Worker activity reports {assignment,present,busy} without waking a sandbox.
Idle capacity is released only after a matching worker release acknowledgment;
release rechecks active references so a concurrent request/job cannot be cut off
by an earlier idle observation. Graceful drain blocks new work and renews only
within its bounded drain grace. A lost renewal acknowledgment retains its last
possibly granted expiry and disables further renewal/allocation to that node;
it never extends an unreachable node forever.

## MCP OAuth token model

The ingress mounts one OAuth server advertising `authorization_code` and
`refresh_token`. Both grants return the same shape: an opaque 32-byte access
token valid one hour (`expires_in` 3600), plus an opaque 32-byte refresh token
valid thirty days and bound to the connection id and the issuing `client_id`.
Durable state keeps only SHA-256 of each, never the raw token; the refresh hash
is domain separated so a refresh token cannot resolve as a bearer.

Every refresh rotates: one store update mints the new pair and retires the
presented refresh token, keeping its hash as the previous one. Presenting that
retired token is reuse — two holders have the family — so it returns 400
`invalid_grant` and drops every refresh token on the connection; the access
token keeps its own expiry, because cutting it short only punishes the client
that behaved. Revoking a connection clears the refresh family for the same
reason: the refresh token outlives the bearer by weeks.

Expiry fails closed. A record with no `tokenExpiresAt` or `refreshExpiresAt`
has no proven lifetime and reads as expired, so pre-TTL connections need one
re-consent rather than living forever. Both fleet and local paths resolve
tokens through the same predicates, so they cannot diverge.

## Activation, migration and rollback

Central starts durably paused. Import alone does not allocate or reenroll owners.
After verified state import and Gateway authority checks, an operator explicitly
calls admin /fleet/v1/activate. Activation resolves every approved connection
owner's latest sealed epoch and enrolls that tuple while still paused, without
allocating. An enrollment failure retains the pause and attempted membership
rows so partial or ambiguous acknowledgments can be reconciled. OAuth approval
enrolls the owner before persisting approval, even if no MCP read ever follows.
/fleet/v1/quiesce durably pauses new allocation,
public dispatch and periodic renewal, waits in-flight controller operations, and
joins in-flight OAuth approvals before reconciling all approved owners again,
including an epoch advanced without an MCP read. It begins draining immediately
alongside reconciliation and joins both even if either fails; rollback export
requires successful reconciliation.
Restart retains the pause and operator drain decisions. Fresh
attested health probes can restore node availability; a generation whose renewal
failed stays blocked until its last possible lease expires even after readmission.

Stage the central app and worker 2 before the serialized source update. Use exact
instance reachability: an app-scoped Phala URL can balance across replicas, so
starting worker 2 can change legacy routing before any DNS cutover. Resolve that
baseline URL risk before booting a second replica. Enabling fleet mode on the
source disables generic claims and bearer prewarm and is a cutover step.

Admin /fleet/v1/migrate accepts {sourceNodeId,migrationId}. Central calls the
admitted source's migration.export. Source closes public ingress, waits existing
HTTP requests, then atomically fences its OAuth writer on durable storage before
returning the snapshot on the encrypted peer channel. OAuth state reads and
writes fail after that fence, including after restart. A private read of approved
owner binding metadata remains available for recovery reconciliation; it cannot
read connection keys or permit OAuth mutations. Target rejects replacing
an active nonempty writer, imports connections/authorizations/owner bindings as
one snapshot, and reencrypts with its app-scoped dstack key. Admin receives only
counts, digest and restartRequired. Identical import retries return the receipt
without replaying a snapshot over later authorization changes.

Post-enrollment rollback requires the explicit Gateway recovery protocol. Apply
Gateway migrations 0057 and 0058 atomically before any fleet traffic. Feature
flags alone never undo enrollment or authorize generic claims. Recovery uses a
separate operator-only FLEET_RECOVERY_TOKEN, never provisioned to controllers or
workers. The exact sequence is:

1. Quiesce central durably, drain all owner calls/jobs, and acknowledge releases
   or wait every last possibly granted placement lease. Confirm no live job
   attempt remains; a failed drain is pending recovery, never success.
2. Call central migrate with direction=rollback. Central must already be paused
   with no live placements. It closes/fences its writer and sends the current
   snapshot to the original worker over the verified peer channel. Preserve the
   receipt; restartRequired means the closed source listener needs a restart.
3. For each enrolled owner, call Gateway POST /v1/fleet?action=rollback with
   {owner:{chainId,userPsId,identityEpoch},expectedGeneration,rollbackNodeId}.
   The transaction requires the current epoch, exact retained generation, no live
   placement/job lease and fleet mode. It fences stale attempts, retains history
   and allows legacy claims only by the chosen source node. Ordinary controller
   enrollment/publication is rejected while this explicit recovery mode is set.
4. Call private central POST /fleet/v1/prepare-rollback with
   {sourceNodeId,migrationId}. Central requires its writer fenced, the controller
   paused, and all placements drained. Over the freshly attested encrypted peer,
   the source resolves every imported approved owner using its dedicated node
   credential at Gateway /v1/fleet?action=recovery-envelope. Gateway requires the
   latest sealed epoch, exact rollback_legacy designated node and no live leases.
   The source derives the identity, unseals the envelope and verifies the owner
   signature inside the TEE. Only after all owners succeed does it atomically
   persist the encrypted cache and a receipt bound to migration, snapshot,
   approved membership, identities and recovery generations. A failed refresh
   clears any prior receipt. The administrator receives only counts/digest.
5. Restore the Gateway alias to a deployment of the reviewed recovery-capable
   Gateway source configured for legacy mode, preserving the recovery endpoint
   and direct source routing for new identities, sealing and prewarm. Then restart
   the chosen source using the same reviewed current source/image and an approved
   signed FLEET_ENABLED=false bundle. On the first legacy activation,
   before opening MCP or the job claim loop it requires the exact preparation
   receipt and repeats current recovery-envelope verification for every approved
   owner. Changed epochs, generations, modes, envelopes or node designations fail
   closed. It then atomically records successful legacy activation bound to the
   imported migration/snapshot/receipt. Later ordinary legacy approvals, revocations
   and identity rotations can restart without matching historical fleet membership;
   per-request current-identity checks and Gateway claim fences still apply. A new
   import resets activation, and an exported source remains durably fenced on
   restart. This adds no hardware monotonic protection against disk rollback.
   Do not restore the old source image or old OAuth state. Keep other generic
   workers stopped. The old baseline Gateway binary lacks the recovery endpoint
   required for the first legacy activation after an imported rollback.
   Central remains paused/fenced. Prove the original ordinary Claude token/grant,
   a fresh fleet-approved owner's MCP read without SDK prewarm, an actual SDK job,
   and another source restart followed by the same MCP read.
6. To return to fleet, fence/stop legacy public execution and claims first,
   transfer protected state back, and wait/fence outstanding legacy attempts.
   Operator Gateway POST /v1/fleet?action=resume takes {owner,expectedGeneration}
   under the same recovery credential and restores fleet mode. Restart central
   if its receipt requires it, freshly admit workers with resume=true to clear
   planned drains, then explicitly activate. The next allocation must increase
   the retained generation. Restore routing serially and repeat the live reads.

Never delete enrollment, reset a generation, remove database fencing triggers,
copy old encrypted state over an active writer or export state keys/snapshots to
an operator machine. Worker app identity, wallet derivation and owner ciphertext
remain unchanged throughout. All rollback steps require actual runtime proof;
local tests and a restartRequired receipt alone do not establish service recovery.
