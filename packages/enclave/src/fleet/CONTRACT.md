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

Dstack encrypted environment values are not measured or authenticated. Every
fleet application boot verifies an operator Ed25519 signature before deriving
protected state keys or opening admin, migration, or peer listeners. The complete
runtime configuration is returned as a new environment map; unsigned values are
never merged. The signed payload binds role, node, current app and instance and
has a maximum 24-hour validity window checked at startup. This limits replay of
old signed configuration; it does not claim hardware monotonic rollback defense
or terminate an already-running process when its boot window ends.

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

## Peer protocol and approved identity

The reachability URL uses ordinary HTTPS. Inner confidentiality and mutual
identity use a one-shot attested X25519 channel; an outer Phala proxy observes
only public evidence and encrypted packets. Each RPC performs a fresh handshake:

1. Caller sends its identity, random 32-byte challenge and ephemeral X25519 SPKI.
2. Responder contributes an independent challenge/key and session ID, then quotes
   SHA-512(domain || serialized complete transcript) as all 64 report-data bytes.
3. Caller runs Intel DCAP signature/certificate/TCB verification and compares
   MRTD and every RTMR with its approved policy. It compares the exact intended
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
installing its runtime adapter. Exactly one active controller app is an operating
invariant; stop/fence its old instance before any replacement.

Worker activity reports {assignment,present,busy} without waking a sandbox.
Idle capacity is released only after a matching worker release acknowledgment;
release rechecks active references so a concurrent request/job cannot be cut off
by an earlier idle observation. Graceful drain blocks new work and renews only
within its bounded drain grace. A lost renewal acknowledgment retains its last
possibly granted expiry and disables further renewal/allocation to that node;
it never extends an unreachable node forever.

## Activation, migration and rollback

Central starts durably paused. Import alone does not allocate or reenroll owners.
After verified state import and Gateway authority checks, an operator explicitly
calls admin /fleet/v1/activate. /fleet/v1/quiesce durably pauses new allocation,
public dispatch and periodic renewal, waits in-flight controller operations, and
drains workers. Restart retains the pause and operator drain decisions. Fresh
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
returning the snapshot on the encrypted peer channel. All source state reads and
writes fail after that fence, including after restart. Target rejects replacing
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
4. Only after successful database receipts, restart the chosen source with the
   approved legacy runtime/flags, keep all other generic workers stopped, and
   restore the verified Gateway routing/DNS. Central remains paused/fenced.
   Prove the original ordinary Claude token/grant and an actual SDK job.
5. To return to fleet, fence/stop legacy public execution and claims first,
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
