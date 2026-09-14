# TEE provisioning

Prerequisites: Phala CLI 1.1.21 logged in and Node.js 24.

`provision.sh`, `replicate.sh` and `update.sh` are the **pre-fleet (level B)**
path: one standalone CVM, an unsigned environment and a Gateway node id. They
cannot stage a signed fleet, so do not use them for a controller or a worker —
see [From-scratch fleet (level A)](#from-scratch-fleet-level-a).

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
node scripts/tee/pool-loop.mjs --dry-run
```

## Warm-pool loop

`pool-loop.mjs` starts and stops pre-declared fleet members and drives their
admission through the controller's admin listener. It never calls the Gateway:
Gateway admit forwards no `resume` and Gateway drain is one-way to removed.

It reads `~/.vana/pool.json` — either an array of
`{nodeId,cvmId,publicUrl,capacity,bundleExpiresAt,composeHash?}` with
`VANA_FLEET_ADMIN_URL` set, or `{controllerAdminUrl, members:[...]}`. Both the
admin URL and every `publicUrl` must be `https`, or the loop refuses to start:
the admin bearer rides every request. That file holds no secrets. The controller admin token comes from the login keychain item
`vana-fleet-admin` and each member's `ENCLAVE_AGENT_SECRET` from
`vana-fleet-agent-<nodeId>`, read per command and never written to disk. Phase
state persists in `~/.vana/pool-loop-state.json`
(`VANA_POOL_PATH`/`VANA_POOL_STATE_PATH` override both paths).

`pool.json` needs no repin on a fleet roll. The controller's signed directory
decides which image may run: the loop takes its reference compose hash from the
hash a member's health reported under the admission the controller currently
stands behind, and a re-admission after a roll replaces it. The per-member
`composeHash` is an optional soft check that warns on a mismatch; neither it
nor the reference ever restarts or quarantines a member.

The loop ticks every 15 s: it brings the pool straight up to `MIN_RUNNING`,
then scales up only after 60 s with no free capacity and at most `MAX_RUNNING`
members, scales down a member idle for 15 min while more than `MIN_RUNNING`
remain, and stops a machine only once the controller reports it draining with
no live lease. A member that has not been admitted 8 minutes after start, or
whose event log carries a second `mr-kms` entry, is restarted once and then
quarantined; neither a stop nor a restart happens while a lease on it is still
live. A member that reaches the pool while the controller still carries its earlier
`draining` flag is resumed with `admit {resume:true}` — whether the loop or the
controller's own re-attest admitted it — so it never sits admitted with no
slots. One loop runs per state file, fenced by a `<state>.lock` pidfile.
`--once` runs a single tick; `--dry-run` logs every decision without invoking
`phala`.

Before its first tick, every start reconciles state against the controller's
status: a member it did not itself act on this run is set to `running` if the
controller has it ADMITTED. A missing admission is not evidence the machine is
down - the controller's admissions map is in memory and every node reads
unavailable for ~30 s after a controller boot - so it is demoted to `stopped`
only when the controller reports it unavailable, it holds no live lease, and
the loop does not already believe it to be running; otherwise the phase is left
alone and an `ADOPT_UNDECIDED` line is logged. A running or admit-wait member's
`since` also self-heals every tick if it is somehow newer than the controller's
own admission record, since the controller is the only authority on an
admission it granted - but never from an admission raised before the loop's own
start or restart, which describes the machine that command replaced. After a
roll: restart the loop; no state edits.

`provision.sh` defaults to `deploy/dstack/docker-compose.enclave.yml`. The
agent receives only the dstack socket and reaches the privileged nested Docker
runtime over the private compose network. `AGENT_IMAGE` and `DIND_IMAGE` must
be digest-pinned base images; provisioning rejects mutable tags. `PS_IMAGE`
must be a digest built from this branch's root `Dockerfile`; do not use a tag.
Run the Docker workflow on the branch, then download its `images.env` artifact
to `deploy/dstack/images.env` or copy the lines from the job summary. The
production-compose paths read only `PS_IMAGE` and `PS_IMAGE_REF` from that file
and only when the corresponding environment value is unset; inline paths do
not read it. `PS_IMAGE_REF` records the image's source commit and must match the
40-hex `--ref`/`GIT_REF`; if it is omitted, the scripts warn that provenance is
unverified.

`images.env` also records the prebuilt fleet images: `AGENT_IMAGE` and
`CONTROLLER_IMAGE` (one `personal-server-enclave` digest serving both roles,
built by `Dockerfile.enclave`) and `RUNTIME_IMAGE`
(`personal-server-sandbox-runtime`, built by
`deploy/dstack/Dockerfile.sandbox-runtime`). Those lines never override the
environment; they only reject a stale pin. If `AGENT_IMAGE` or `DIND_IMAGE`
names one of those repositories, it must equal the recorded digest. A base
image (`node@sha256:…`, `docker@sha256:…`) names a different repository, so the
level-B composes that still build inside the CVM are unaffected.

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
talking directly to one another. gVisor runs on the systrap platform.

The provisioner prints a registration payload without revealing `NODE_SECRET`.
Save it as `node-registration.json`, replace its placeholder once, and register
the node with the operator bearer:

```sh
curl -fsS -X POST "$GATEWAY_URL/v1/tee-nodes" \
  -H "Authorization: Bearer $OPERATOR_SECRET" \
  -H 'Content-Type: application/json' \
  --data @node-registration.json
```

## From-scratch fleet (level A)

Proven on prod9 2026-09-11: zero to 3 admitted CVMs, MCP ingress and Gateway
rows in **13 min**. One app id per role; the workers share one, so dstack
derives the same owner job keys for both.

1. Allocate one app id per role — `phala api /kms/phala/next_app_id` — and keep
   each `{app_id, nonce}` pair.
2. Deploy every CVM fail-closed with `FLEET_SIGNED_CONFIG={}` in a mode-0600 env
   file, so the first boot opens no listener:

   ```sh
   phala deploy -n <name> -c <compose> --custom-app-id <app-id> --nonce <n> \
     --image dstack-0.5.9-bd369a8c --instance-type tdx.medium --disk-size 20G \
     --node-id <teepod-id> --no-dev-os --kms phala -e <dummy-env> --json
   ```

3. Poll `phala api /cvms/<uuid>` until `status: running`. `--wait` returns in
   4–7 s when the _record_ exists, not when the CVM runs.
4. Harvest each CVM's measured identity. `/cvms/<uuid>` leaves `instance_id`
   null forever; instance id, compose hash, mr-kms, key-provider SPKI and
   MRTD/RTMRs all come from the attestation event log:

   ```sh
   python3 scripts/tee/harvest-identity.py --nodes nodes.json > identities.json
   ```

5. Render one signed-config draft per node from `identities.json`:
   `expiresAt: null`, `issuedAt` at the current second (the verifier rejects
   `now + 60 s`), and on a NET-NEW controller **both** `MCP_MIGRATION_REQUIRED=0`
   and `MCP_STATE_REQUIRED=0`.
6. Sign each draft and push it as the sealed environment:
   `phala envs update <uuid> -e <sealed.env> --json`. That restart is what boots
   the signed config. Read every secret from the keychain inline, per command.
7. Health, 78–87 s after the env update: worker `GET :8787/agent/v1/health`,
   controller `POST :8791/fleet/v1/status`, each with its bearer. All 200.
8. **First deploy only** — `POST :8791/fleet/v1/activate` on the controller's
   admin listener. A roll never needs it.
9. Per worker, against the Gateway: `POST /v1/tee-nodes` with the row and node
   secret, wait for a fresh heartbeat carrying the staged compose hash, then
   `POST /v1/tee-nodes/<node-id>/admit`.
10. Re-sign the controller with `MCP_STATE_REQUIRED=1` **only after** the first
    real owner MCP connection has written sealed state. An OAuth DCR does not
    write it, and signing 1 on an empty fleet crash-loops the controller.

### Custom domain (optional)

| record                           | value                               |
| -------------------------------- | ----------------------------------- |
| CNAME `<host>`                   | `_.dstack-pha-<node>.phala.network` |
| TXT `_dstack-app-address.<host>` | `<app-id>:8788`                     |

Keep `mcp-tls` with `GATEWAY_DOMAIN=<host>` once both records resolve. Until
then `DNS_SETUP_MODE=wait` blocks the CVM 3600 s: drop `mcp-tls` and serve MCP
on `https://<app-id>-8788.dstack-pha-<node>.phala.network`.

### Rolling an existing fleet

Steps 2, 3, 6, 7 and 9 only — no app id, no `activate`, no MCP state flag change.

1. Stage every compose first, **the controller first**, so its real dstack
   `compose_hash` is readable before any worker bundle is signed against it.
2. Staged reciprocal pin: each worker's `FLEET_PEER_POLICIES` carries the
   current **and** next controller hash, so it admits either side of the roll.
3. Settle every CVM to `running` before its `envs update`. That ordering is what
   keeps the 409 count at 0.
4. Rotate each Gateway row `drain → remove → register → heartbeat → admit`, each
   followed by a controller `admit {resume:true}`: a Gateway drain sets the
   controller's own `draining` flag.
5. Repin `~/.vana/pool.json` to the new hashes, restart the loop, **no state edits**.

### Fleet tooling

Three commands cover render, sign and the Gateway rows. All three read one
fleet manifest — `deploy/dstack/fleets/<fleet>.json`, which carries ids,
measured pins and non-secret env only — and every credential is a keychain
item named on the command line and read per invocation, never from a file.

| command                         | does                                                                                                                                 |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `scripts/tee/render-fleet.py`   | renders the measured composes and one unsigned draft per node; `--stage` applies each compose and reads the real `compose_hash` back |
| `scripts/tee/sign-fleet.cjs`    | signs each draft with the operator key, writes receipts; `--apply` settles the CVM, then `phala envs update` with the 409 retry      |
| `scripts/tee/gateway-nodes.cjs` | `register`/`wait`/`admit`/`drain`/`remove`/`resume`, and `rotate` for the whole roll sequence                                        |

Rolling the prod5 preview fleet to a new head:

```sh
# 1. Render, stage every compose (controller first), pin the read-back hashes.
python3 scripts/tee/render-fleet.py \
  --manifest deploy/dstack/fleets/preview-prod5.json \
  --images-env <ci-docker-dir>/images.env \
  --out rendered/ --stage --settle --write-manifest

# 2. Sign each draft and push it as the sealed environment.
node scripts/tee/sign-fleet.cjs \
  --manifest deploy/dstack/fleets/preview-prod5.json \
  --drafts rendered/ --key-item <signing-key item> --apply

# 3. Rotate each worker's Gateway row onto the new hash.
for node in worker-1 worker-2 worker-3 worker-4; do
  node scripts/tee/gateway-nodes.cjs rotate \
    --manifest deploy/dstack/fleets/preview-prod5.json \
    --node "$node" --receipts receipts/
done
```

A net-new fleet is the same without the staged prior hash: deploy each CVM
fail-closed, fill the manifest's `measured` and `pinned` blocks from
`harvest-identity.py`, render without `--stage`, sign with `--apply`, then
`gateway-nodes.cjs register`, `wait` and `admit` per worker.

Still done by hand: app-id allocation, the first `phala deploy -n <name>` of a
net-new CVM, `harvest-identity.py` into the manifest, the controller's one-time
`/fleet/v1/activate`, the `MCP_STATE_REQUIRED=1` re-sign, and `~/.vana/pool.json`.

A keychain item whose ACL does not cover the `security` CLI needs
`--keychain-reader <script>`: the script gets `{"service","account"}` on stdin
and prints the secret.

Tests: `python3 scripts/tee/render-fleet.test.py` and
`node --test scripts/tee/fleet-common.test.mjs`. Neither calls `phala`.

### Known gaps

| gap                                                                        | workaround                                                                                                    |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| A byte-identical compose hashes differently on a different node            | always read `compose_hash` back from the staged CVM                                                           |
| Container logs unreachable on prod9 (`phala logs` → "Container not found") | serial console only                                                                                           |
| No resize verb; no base domain in `phala nodes list`                       | `phala api -X PATCH /cvms/<uuid>` with the new type, CVM stopped; `phala api /teepods` → `tproxy_base_domain` |
| Gateway `admit` → 500 for a node its `FLEET_CONTROLLER_URL` does not know  | point the Gateway at this fleet's controller, or leave the rows `pending`                                     |

## Fleet composes

`deploy/dstack/docker-compose.fleet-worker.yml` and
`docker-compose.fleet-controller.yml` are rendered by `render-fleet.py`, not by
`provision.sh`. Replace
`REPLACE_WITH_REVIEWED_AGENT_IMAGE_DIGEST` with `AGENT_IMAGE` and
`REPLACE_WITH_REVIEWED_RUNTIME_IMAGE_DIGEST` with `RUNTIME_IMAGE` from the same
`images.env`, and pin digests rather than tags so the compose hash stays
deterministic.

Both services run prebuilt images: the agent and controller start
`packages/enclave/dist/agent/main.js` or `central/main.js` directly, and the
sandbox runtime starts `dockerd` with gVisor already installed. No boot does
`apk add`, `git fetch`, `npm ci`, or `tsc --build` any more, which removes about
130 s of the measured 206 s from start to health.
`REPLACE_WITH_REVIEWED_40_HEX_COMMIT` stays in both composes as measured
provenance for the commit the enclave image was built from
(`PS_IMAGE_REF` in `images.env`); nothing is fetched from it.

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

## Rolling a fleet back (and forward again)

A roll in either direction is the same procedure: the target head's already
reviewed composes are re-staged byte for byte, so the dstack compose hash comes
back identical to when that head was last measured and nothing is rebuilt. Only
`issuedAt` and the staged reciprocal controller pins move. Rehearsed end to end
on the four-worker preview fleet on 2026-09-11: **14m53s** back, **11m43s**
forward, zero `409`s, one CVM restart.

Pause the ticker from a detached shell, not a foreground one: a foreground
`kill -STOP "$TICKER_PID"` self-resumes mid-roll. Use `nohup sh -c 'kill -STOP
'"$TICKER_PID"'' &` (or a pause file the loop checks) instead.

Before anything, stage the pins. Every worker's `FLEET_PEER_POLICIES` must carry
the controller compose hash it is running on **and** the one it is rolling to,
in that order, or the workers stop admitting the controller mid-roll.

```sh
kill -STOP "$TICKER_PID"                      # the loop must not act mid-roll
python3 render-slice16.py rollback            # composes copied, issuedAt stamped
python3 cvm-snapshot.py rollback cvm-before-rollback

# 1. Stage all five composes, controller first. Fail-closed: the dummy env
#    keeps each enclave from opening a listener until the signed bundle lands.
for n in controller worker-1 worker-2 worker-3 worker-4; do
  python3 stage-slice16.py rollback "$n"      # asserts the staged hash == expected
done
python3 settle16.py rollback                  # every CVM `running` before step 2

# 2. Only then the signed configs, workers first.
for n in worker-1 worker-2 worker-3 worker-4 controller; do
  node sign-and-update-slice16.cjs rollback "$n"
done
python3 poll-health-slice16.py rollback       # 200 on the NEW hash, all five

# 3. Rotate the Gateway rows one node at a time. The Gateway `drain` step
#    propagates to the controller, so resume between nodes.
for w in 1 2 3 4; do
  node admit-gateway-slice16.cjs "$PLAN" "$PLAN_SHA256" "moksha-...-worker-$w"
  node resume-worker.cjs "moksha-...-worker-$w"
done
kill -CONT "$TICKER_PID"
```

Then prove it: one SDK job to `completed` attempt 1, one MCP `tools/call` 200,
`POST /fleet/v1/status` 200 with every member `draining:false,
unavailable:false`, and `POST /agent/v1/identity` against each worker.

Five things need a hand, in rough order of likelihood:

- A member reads back `stopped` after its own `envs update` (exit 0). Recover
  with `phala cvms start <uuid>`; staging also restarts an already-stopped CVM.
- A member sits at `PEER_EVENTS_REJECTED` on its pre-roll incarnation and
  `admit {resume:true}` returns 503. One `phala cvms restart <uuid>` re-measures
  it; it readmits about 90 s later on a fresh incarnation.
- A member returns `ADMITTED` but `draining:true`, the stale flag from an
  earlier scale-down. One `admit {resume:true}` clears it; the rotation's
  precondition is all four serving.
- The loop stops a freshly rolled idle member on its first tick after
  `kill -CONT`. That is `MIN_RUNNING` doing its job, not a failed roll.
- `drain` returns 500 within about 30 s of a member's own health going green.
  Not the stale-owner failure above — just retry 60 s later.

**Do not roll across a Gateway database change.** `drain` releases each of the
node's placements through a CAS against `fleet_owners`; if the owner row is not
in the database the controller is now talking to, `releaseAssignment` raises
`FleetConflict('Stale release')`, `drain` fails closed, and the member's Gateway
row can never be rotated. There is no operator path out of it — the rows have to
be put back before the fleet can let go of them. Roll the fleet and cut the
database over in separate windows.

### Rolling the Gateway back

The Gateway rolls back by alias, in about a second, and is worth reaching for
before any fleet roll:

```sh
vercel inspect "https://$ALIAS" --scope "$SCOPE"     # record the current target
vercel alias set "$PREVIOUS_DEPLOYMENT_URL" "$ALIAS" --scope "$SCOPE"
# prove it: one SDK job to `completed`
vercel alias set "$CURRENT_DEPLOYMENT_URL" "$ALIAS" --scope "$SCOPE"
```

Pause the ticker across the flip so the loop never reads one deployment's state
and writes the other's. Measured: 1 s out, 2 s back, 31 s including the job.
