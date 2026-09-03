# TEE provisioning

Prerequisites: Phala CLI 1.1.21 logged in and Node.js 24.

```sh
export ENCLAVE_AGENT_SECRET=...
export NODE_SECRET="$(openssl rand -hex 32)"
export NODE_ID=node-1
export GATEWAY_URL=https://gateway.example
export PS_IMAGE=vanaorg/personal-server@sha256:...
scripts/tee/provision.sh <name> --ref <40-hex-commit-sha>
scripts/tee/replicate.sh <name> <source-cvm-uuid> --node-id <phala-placement-id>
scripts/tee/destroy.sh <uuid>
node scripts/tee/kms-root.mjs
```

`provision.sh` defaults to `deploy/dstack/docker-compose.enclave.yml`. The
agent receives only the dstack socket and reaches the privileged nested Docker
runtime over the private compose network. `PS_IMAGE` must be a digest built
from this branch's root `Dockerfile`; do not use a tag. The previously published
digest lacks the runtime Vana SDK dependency and exits with
`ERR_MODULE_NOT_FOUND @opendatalabs/vana-sdk`.

For the enclave compose, `--ref` must be an immutable 40-hex commit SHA. The
level-B clone bootstrap fetches that exact commit and verifies the checkout;
production follows architecture decision 23 and uses a digest-pinned agent
image under one approved compose hash. `SANDBOX_MAX`,
`SANDBOX_IDLE_TTL_SECONDS`, and `LEASE_SECONDS` are optional and default to 20,
600, and 30.

Use `--inline` for the registry-free level-B jobs variant, which builds the
root `Dockerfile` inside the CVM and therefore requires `PS_IMAGE` to be a tag.
The default enclave compose continues to require a digest. The old
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
a fresh 32-byte `NODE_SECRET`. Its `--node-id` is the numeric Phala placement
ID, while `--tee-node-id` is the identity registered with the Gateway and
defaults to `<name>`.

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

## Remote lease-recovery test

Provision the slow node with `WORK_DELAY_MS=120000`, then unset it before
provisioning or replicating the fast node. Run the remote e2e with
`E2E_REMOTE=1`, `E2E_RECOVERY=1`, and both registration IDs in `E2E_NODE_IDS`.

```sh
export NODE_ID=slow-node
export WORK_DELAY_MS=120000
scripts/tee/provision.sh slow-node --ref <40-hex-commit-sha>
unset WORK_DELAY_MS
scripts/tee/replicate.sh fast-node <slow-node-cvm-uuid> --node-id <phala-placement-id>
E2E_REMOTE=1 E2E_RECOVERY=1 E2E_NODE_IDS=slow-node,fast-node npm run e2e:job
```

The driver detects the slow node's `claimed` or `running` job within 15 seconds
and prints `RECOVERY_JOB <id> in flight on the slow node; stop that node now`.
At that point, drain the slow node with `POST /agent/v1/drain`. The fast node
then claims and completes the same job as attempt 2, which the driver asserts.

`WORK_DELAY_MS` artificially delays every job and is only for this test. Leave
it unset on production nodes and on the fast recovery node.

The last command prints the uncompressed KMS root key; use that form for the Gateway's `ENCLAVE_KMS_ROOT_PUBKEY`. Configure the Gateway with `ENCLAVE_AGENT_URL`, `ENCLAVE_AGENT_SECRET`, `ENCLAVE_KMS_ROOT_PUBKEY`, and `ENCLAVE_APP_ID_ALLOWLIST=0x<app_id>`.
