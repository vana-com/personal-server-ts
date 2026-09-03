# TEE provisioning

Prerequisites: Phala CLI 1.1.21 logged in and Node.js 24.

```sh
export ENCLAVE_AGENT_SECRET=...
export NODE_SECRET="$(openssl rand -hex 32)"
export NODE_ID=node-1
export GATEWAY_URL=https://gateway.example
export PS_IMAGE=vanaorg/personal-server@sha256:...
scripts/tee/provision.sh <name> --ref feat/enclave-jobs
scripts/tee/destroy.sh <uuid>
node scripts/tee/kms-root.mjs
```

`provision.sh` defaults to `deploy/dstack/docker-compose.enclave.yml`. The
agent receives only the dstack socket and reaches the privileged nested Docker
runtime over the private compose network. `PS_IMAGE` must be a digest built
from this branch's root `Dockerfile`; do not use a tag. The previously published
digest lacks the runtime Vana SDK dependency and exits with
`ERR_MODULE_NOT_FOUND @opendatalabs/vana-sdk`.

The compose clones `GIT_REF` (default `main`); pass `--ref <branch>` to test a
branch. `SANDBOX_MAX`, `SANDBOX_IDLE_TTL_SECONDS`, and `LEASE_SECONDS` are
optional and default to 20, 600, and 30. Use `--inline` (or pass the inline
compose with `--compose`) for the old identity-only deployment; it requires
only `ENCLAVE_AGENT_SECRET`.

The provisioner prints a registration payload without revealing `NODE_SECRET`.
Save it as `node-registration.json`, replace its placeholder once, and register
the node with the operator bearer:

```sh
curl -fsS -X POST "$GATEWAY_URL/v1/tee-nodes" \
  -H "Authorization: Bearer $OPERATOR_SECRET" \
  -H 'Content-Type: application/json' \
  --data @node-registration.json
```

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

The last command prints the uncompressed KMS root key; use that form for the Gateway's `ENCLAVE_KMS_ROOT_PUBKEY`. Configure the Gateway with `ENCLAVE_AGENT_URL`, `ENCLAVE_AGENT_SECRET`, `ENCLAVE_KMS_ROOT_PUBKEY`, and `ENCLAVE_APP_ID_ALLOWLIST=0x<app_id>`.
