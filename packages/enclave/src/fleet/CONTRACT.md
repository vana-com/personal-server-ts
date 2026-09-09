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
