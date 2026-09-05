# TEE provisioning

Prerequisites: Phala CLI 1.1.21 logged in and Node.js 24.

```sh
export ENCLAVE_AGENT_SECRET=...
export AGENT_IMAGE=node@sha256:...
export DIND_IMAGE=docker@sha256:...
export NODE_SECRET="$(openssl rand -hex 32)"
export NODE_ID=node-1
export GATEWAY_URL=https://gateway.example
export PS_IMAGE=vanaorg/personal-server@sha256:...
export PS_IMAGE_REF=<same-40-hex-commit-sha>
scripts/tee/provision.sh <name> --ref <40-hex-commit-sha>
scripts/tee/replicate.sh <name> <source-cvm-uuid> --node-id <phala-placement-id>
scripts/tee/destroy.sh <uuid>
node scripts/tee/kms-root.mjs
```

`provision.sh` defaults to `deploy/dstack/docker-compose.enclave.yml`. The
agent receives only the dstack socket and reaches the privileged nested Docker
runtime over the private compose network. `AGENT_IMAGE` and `DIND_IMAGE` must
be digest-pinned base images; provisioning rejects mutable tags. `PS_IMAGE`
must be a digest built from this branch's root `Dockerfile`; do not use a tag.
Run the Docker workflow on the branch, then download its `images.env` artifact
to `deploy/dstack/images.env` or copy the two lines from the job summary. The
production-compose paths read only `PS_IMAGE` and `PS_IMAGE_REF` from that file
and only when the corresponding environment value is unset; inline paths do
not read it. `PS_IMAGE_REF` records the image's source commit and must match the
40-hex `--ref`/`GIT_REF`; if it is omitted, the scripts warn that provenance is
unverified.

For the enclave compose, `--ref` must be an immutable 40-hex commit SHA. The
level-B clone bootstrap fetches that exact commit and verifies the checkout;
production follows architecture decision 23 and uses a digest-pinned agent
image under one approved compose hash. `SANDBOX_MAX`,
`SANDBOX_IDLE_TTL_SECONDS`, and `LEASE_SECONDS` are optional and default to 20,
600, and 30. Each sandbox is limited by `SANDBOX_MEMORY`, `SANDBOX_CPUS`, and
`SANDBOX_PIDS_LIMIT`, which default to `512m`, `2`, and `256`. `CHAIN_ID`
accepts 1480 or 14800 and defaults to Moksha (14800).
`STORAGE_API_URL` follows the chain when unset: `https://storage-dev.vana.org`
for Moksha and `https://storage.vana.org` for mainnet. Operators may override
`DATA_REGISTRY_CONTRACT`, `DATA_PORTABILITY_SERVER_CONTRACT`,
`DATA_PORTABILITY_GRANTEES_CONTRACT`, and
`DATA_PORTABILITY_PERMISSIONS_CONTRACT`; unset addresses preserve the current
Moksha defaults. Provision, replicate, and update forward all of these optional
variables to the agent and owner sandboxes.

Sandbox credentials, including `VERCEL_PROTECTION_BYPASS`, are supplied to
Docker through a mode-0600 env file in a private temporary directory. The agent
deletes that file immediately after `docker create`; secret values are never
placed on the Docker command line.

Use `--inline` for the registry-free level-B jobs variant, which builds the
root `Dockerfile` inside the CVM and resolves its own `PS_IMAGE` to a Docker
image id. The operator does not need to supply `PS_IMAGE`; the local build tag
defaults to `personal-server:local`, and an explicitly supplied tag is still
accepted. The default enclave compose continues to require a digest. The old
identity-only `docker-compose.agent.inline.yml` remains available through
`--compose <path>` and keeps branch-name support.

The nested Docker daemon binds its unauthenticated TCP API to the private
compose interface. Firewall rules drop Docker API traffic originating from
`docker0` and `br-+`, and `--icc=false` prevents Personal Server sandboxes from
talking directly to one another.

The provisioner prints a registration payload without revealing `NODE_SECRET`.
Save it as `node-registration.json`, replace its placeholder once, and register
the node with the operator bearer:

```sh
curl -fsS -X POST "$GATEWAY_URL/v1/tee-nodes" \
  -H "Authorization: Bearer $OPERATOR_SECRET" \
  -H 'Content-Type: application/json' \
  --data @node-registration.json
```

## Replicating a fleet node

Use `replicate.sh` to add a cheaper replica that retains the source CVM's
`app_id`, so dstack derives the same owner job keys. Export the same fleet
settings used for provisioning (`ENCLAVE_AGENT_SECRET`, `GATEWAY_URL`,
`GIT_REF`, `PS_IMAGE`, and any optional sandbox settings); the script generates
a fresh 32-byte `NODE_SECRET`. Exactly one secret destination is required:
`--secret-out` creates a new mode-0600 file and refuses to overwrite an existing
path, while `--secret-keychain` creates a macOS generic-password item and
refuses to update an existing item. The script never prints the secret.

Replication and updates require the same digest-pinned `AGENT_IMAGE`,
`DIND_IMAGE`, and `PS_IMAGE` values as provisioning. A replica inherits its
source CVM's compose, so once the source uses a compose that requires an image
variable, every replica must supply that variable too.

```sh
scripts/tee/replicate.sh replica-a <source-cvm-uuid> \
  --secret-out ./replica-a.node-secret

scripts/tee/replicate.sh replica-b <source-cvm-uuid> \
  --secret-keychain personal-server-fleet/replica-b
security find-generic-password -s personal-server-fleet -a replica-b -w
```

The raw secret in the output file, or the value recovered from Keychain, is the
value to paste once into the registration payload's `secret` placeholder. The
script's `--node-id` is the numeric Phala placement ID, while `--tee-node-id` is
the identity registered with the Gateway and defaults to `<name>`.

A fresh `provision.sh` deploy creates an independent `app_id`; use that only
when the new node should deliberately be unable to decrypt the fleet's jobs.
All nodes serving one owner's jobs must otherwise be replicas under one
`app_id`.

The registration payload's `nodeId` must exactly equal the CVM's baked
`NODE_ID`. Before printing the payload, both scripts poll `/agent/v1/health`
with `ENCLAVE_AGENT_SECRET` until the agent reports its baked `nodeId`. A match
continues; a mismatch fails immediately and names both values. An unreachable
or not-yet-booted agent is retried for up to 120 attempts at five-second
intervals, then fails without printing a registration payload.

The agent begins node heartbeats immediately. Once a fresh heartbeat records
the expected compose hash, admit the node:

```sh
curl -fsS -X POST "$GATEWAY_URL/v1/tee-nodes/$NODE_ID/admit" \
  -H "Authorization: Bearer $OPERATOR_SECRET"
```

To stop new claims, wait for running jobs, and destroy all sandboxes:

```sh
curl -fsS -X POST "$AGENT_URL/agent/v1/drain" \
  -H "Authorization: Bearer $ENCLAVE_AGENT_SECRET"
```

If Docker reports a non-transient create/start fault such as an unavailable
image/runtime or invalid resource limit, the agent logs `Sandbox node fault;
draining agent` at error level and automatically stops claiming. Operators can
confirm the state from `GET /agent/v1/health` (`draining: true`); the affected
job is not failed and becomes claimable by another node when its lease lapses.

## Rolling out a compose change

Replicas inherit the source CVM's compose, so replication does not roll out a
compose change. Update each existing CVM in place with a fresh Gateway node ID:

```sh
scripts/tee/update.sh <cvm-uuid> --tee-node-id <new-id> \
  --secret-out ./<new-id>.node-secret
```

Register the printed payload, admit `<new-id>` after its heartbeat arrives,
then drain the old agent and remove its old Gateway node ID:

```sh
curl -fsS -X POST "$GATEWAY_URL/v1/tee-nodes/<new-id>/admit" \
  -H "Authorization: Bearer $OPERATOR_SECRET"
curl -fsS -X POST "$OLD_AGENT_URL/agent/v1/drain" \
  -H "Authorization: Bearer $ENCLAVE_AGENT_SECRET"
curl -fsS -X POST "$GATEWAY_URL/v1/tee-nodes/<old-id>/remove" \
  -H "Authorization: Bearer $OPERATOR_SECRET"
```

`phala logs` returns only the first roughly 300 container log lines. Use the
Phala dashboard log panel for runtime job stages and lease warnings; agent node
ID dumps from the CLI are boot-only. A newly created CVM can stop after its
first boot; recover it with `phala cvms start <uuid>`.

## Reading sandbox state on a CVM

For the complete agent or dind container log, open the Phala dashboard log
panel and choose `⋮` → **Open in New Window**; `phala logs` returns only the
first roughly 300 lines. For temporary diagnosis only, provision with
`SANDBOX_DEBUG=1` (do not enable it in production), then use the existing agent
bearer with `GET /agent/v1/sandboxes` or `GET
/agent/v1/sandboxes/<containerId>/logs?tail=500`. Acquisition emits
`sandbox-acquire` events `start`, `healthy`, and `synced` with `elapsedMs`;
while blocked, 30-second health/sync messages include the container name and
latest health or sync status, and a lapsed lease logs `Job lease lost` with its
stage and elapsed time.

## Remote lease-recovery test

Provision the slow node with `WORK_DELAY_MS=120000`, then unset it before
provisioning or replicating the fast node. Run the remote e2e with
`E2E_REMOTE=1`, `E2E_RECOVERY=1`, and both registration IDs in `E2E_NODE_IDS`.

```sh
export NODE_ID=slow-node
export WORK_DELAY_MS=120000
scripts/tee/provision.sh slow-node --ref <40-hex-commit-sha>
unset WORK_DELAY_MS
scripts/tee/replicate.sh fast-node <slow-node-cvm-uuid> \
  --node-id <phala-placement-id> --secret-out ./fast-node.node-secret
E2E_REMOTE=1 E2E_RECOVERY=1 E2E_NODE_IDS=slow-node,fast-node npm run e2e:job
```

The driver detects the slow node's `claimed` or `running` job within 15 seconds
and prints `RECOVERY_JOB <id> in flight on the slow node; stop that node now`.
At that point, drain the slow node with `POST /agent/v1/drain`. The fast node
then claims and completes the same job as attempt 2, which the driver asserts.

`WORK_DELAY_MS` artificially delays every job and is only for this test. Leave
it unset on production nodes and on the fast recovery node.

## Builder-only run

Use builder-only mode to verify a registered builder against an existing grant
from a real owner flow without access to the owner's private key:

```sh
E2E_BUILDER_ONLY=1 \
E2E_REMOTE=1 \
E2E_SKIP_BUILDER_REGISTRATION=1 \
GATEWAY_URL=https://gateway.example \
OWNER_ADDRESS=0x... \
GRANT_ID=0x... \
BUILDER_PRIVATE_KEY=0x... \
npm run e2e:job
```

Set `SCOPE` to select a granted scope (the first grant scope is used by
default), and set `E2E_BUILDER_ONLY_NEGATIVES=1` to also test a wrong builder
signature. Existing Gateway bypass, chain, and contract overrides still apply.

The last command prints the uncompressed KMS root key; use that form for the Gateway's `ENCLAVE_KMS_ROOT_PUBKEY`. Configure the Gateway with `ENCLAVE_AGENT_URL`, `ENCLAVE_AGENT_SECRET`, `ENCLAVE_KMS_ROOT_PUBKEY`, and `ENCLAVE_APP_ID_ALLOWLIST=0x<app_id>`.
