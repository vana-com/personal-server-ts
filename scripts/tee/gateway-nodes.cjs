#!/usr/bin/env node
// Drive one worker's tee-node row on the Gateway, and the controller-side
// drain flag that a Gateway drain sets.
//
//   node scripts/tee/gateway-nodes.cjs rotate \
//     --manifest deploy/dstack/fleets/<f>.json --node worker-1
//
// Verbs: list | register | wait | admit | drain | remove | resume | rotate.
// `rotate` is the roll sequence: drain -> remove -> register -> heartbeat ->
// admit -> controller resume. Every bearer is a keychain item named in the
// manifest (or overridden here) and read per invocation.
const path = require("node:path");
const {
  controllerAdminUrl,
  findNode,
  gatewayRow,
  loadManifest,
  parseArgs,
  readKeychain,
  sleep,
  trimRow,
  writeJson,
} = require("./fleet-common.cjs");

const USAGE = `gateway-nodes.cjs <verb> --manifest <fleet.json> --node <name>
  verbs: list | register | wait | admit | drain | remove | resume | rotate
  [--operator-item <keychain item>]  default: manifest gatewaySecretRefs.operator
  [--bypass-item <keychain item>]    default: manifest gatewaySecretRefs.bypass
  [--admin-item <keychain item>]     default: controller FLEET_CONTROLLER_ADMIN_TOKEN
  [--key-account <account>]          keychain account, default spike-agent
  [--keychain-reader <script>]       non-interactive reader; stdin {service,account}
  [--receipts <dir>]                 default: the working directory
  [--allow-active]                   admit a node that still has live sandboxes
  [--skip-health]                    skip the attested agent health fence`;

const DEFAULT_ACCOUNT = "spike-agent";
const NODES_PATH = "/v1/tee-nodes";
const ADMIT_PATH = "/fleet/v1/admit";
const STATUS_PATH = "/fleet/v1/status";
const HEALTH_PATH = "/agent/v1/health";
const OK = 200;
const CREATED = 201;
const HTTP_TIMEOUT_MS = 30_000;
const HEARTBEAT_POLL_MS = 10_000;
const HEARTBEAT_ATTEMPTS = 30;
const HEARTBEAT_MAX_AGE_MS = 60_000;
// dstack reports measurements bare; the Gateway row carries them 0x-prefixed.
const HEX_PREFIX_LENGTH = 2;
const ROW_FIELDS = ["nodeId", "appId", "composeHash", "publicUrl", "capacity"];

const matchesRow = (body, row) =>
  ROW_FIELDS.every((key) => body[key] === row[key]);

async function callJson(url, init) {
  const response = await fetch(url, {
    ...init,
    signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
  });
  const body = await response.json().catch(() => ({}));

  return { status: response.status, body };
}

/** The attested agent must already serve the hash the row is about to pin. */
async function assertHealth(row, node, secret, allowActive) {
  const token = secret(node.gateway.agentSecretRef);
  const { status, body } = await callJson(row.publicUrl + HEALTH_PATH, {
    headers: { authorization: "Bearer " + token },
  });

  if (status !== OK) throw new Error(`${row.nodeId}: agent health ${status}`);

  const mismatch =
    body.nodeId !== row.nodeId ||
    body.appId !== row.appId.slice(HEX_PREFIX_LENGTH) ||
    body.composeHash !== row.composeHash.slice(HEX_PREFIX_LENGTH) ||
    body.instanceId !== node.pinned.instanceId;

  if (mismatch)
    throw new Error(`${row.nodeId}: agent is not the pinned instance`);

  if (body.activeSandboxes !== 0 && !allowActive) {
    throw new Error(
      `${row.nodeId}: agent still has ${body.activeSandboxes} sandboxes`,
    );
  }

  return body;
}

/** Clear the controller's own drain flag; it re-verifies the peer's quote. */
async function controllerResume(manifest, nodeId, secret, adminItem) {
  const url = controllerAdminUrl(manifest);
  const headers = {
    authorization: "Bearer " + secret(adminItem),
    "content-type": "application/json",
  };
  const admit = await callJson(url + ADMIT_PATH, {
    method: "POST",
    headers,
    body: JSON.stringify({ nodeId, resume: true }),
  });

  if (admit.status !== OK || admit.body.success !== true) {
    throw new Error(`${nodeId}: controller resume ${admit.status}`);
  }

  const status = await callJson(url + STATUS_PATH, {
    method: "POST",
    headers,
    body: "{}",
  });

  return { admit: admit.status, nodes: status.body.nodes };
}

/** The worker's own heartbeat must land against the newly pinned hash. */
async function waitForHeartbeat(gateway, row, headers) {
  for (let attempt = 0; attempt < HEARTBEAT_ATTEMPTS; attempt += 1) {
    await sleep(HEARTBEAT_POLL_MS);
    const listed = await callJson(gateway + NODES_PATH, { headers });
    const pending = (listed.body || []).find((n) => n.nodeId === row.nodeId);
    const age = pending?.lastHeartbeatAt
      ? Date.now() - Date.parse(pending.lastHeartbeatAt)
      : Infinity;

    if (
      pending?.state === "pending" &&
      age < HEARTBEAT_MAX_AGE_MS &&
      pending.composeHash === row.composeHash
    ) {
      return pending;
    }
  }

  throw new Error(`${row.nodeId}: no fresh heartbeat on the pinned hash`);
}

async function runVerb({ verb, manifest, name, node, args, secret, headers }) {
  const gateway = manifest.gatewayUrl;
  const row = node.role === "worker" ? gatewayRow(manifest, name) : null;
  const post = (suffix, body = "{}") =>
    callJson(gateway + suffix, { method: "POST", headers, body });
  const list = async () =>
    (await callJson(gateway + NODES_PATH, { headers })).body;

  if (verb === "list") return { rows: (await list()).map(trimRow) };

  if (verb === "resume") {
    return controllerResume(manifest, node.nodeId, secret, args.adminItem);
  }

  if (verb === "wait")
    return {
      heartbeat: trimRow(await waitForHeartbeat(gateway, row, headers)),
    };

  if (verb === "drain" || verb === "remove") {
    const result = await post(`${NODES_PATH}/${row.nodeId}/${verb}`);
    const expected = verb === "drain" ? "draining" : "removed";
    if (result.status !== OK || result.body.state !== expected) {
      throw new Error(`${row.nodeId}: ${verb} rejected (${result.status})`);
    }

    return { [verb]: trimRow(result.body) };
  }

  if (verb === "register") {
    const secretValue = secret(node.gateway.nodeSecretRef);
    const result = await post(
      NODES_PATH,
      JSON.stringify({ ...row, secret: secretValue }),
    );
    if (
      ![OK, CREATED].includes(result.status) ||
      !matchesRow(result.body, row)
    ) {
      throw new Error(`${row.nodeId}: unexpected registration response`);
    }

    return { register: trimRow(result.body) };
  }

  if (verb === "admit") {
    if (!args.skipHealth)
      await assertHealth(row, node, secret, args.allowActive);

    const result = await post(`${NODES_PATH}/${row.nodeId}/admit`);
    if (
      result.status !== OK ||
      result.body.state !== "admitted" ||
      !matchesRow(result.body, row)
    ) {
      throw new Error(`${row.nodeId}: unexpected admission response`);
    }

    return { admit: trimRow(result.body) };
  }

  throw new Error(`Unknown verb ${verb}`);
}

/** drain -> remove -> register -> heartbeat -> admit -> controller resume. */
async function rotate(context) {
  const { manifest, name, node, args, secret, headers } = context;
  const row = gatewayRow(manifest, name);
  const steps = [];
  const step = async (verb) => {
    const result = await runVerb({ ...context, verb });
    steps.push({ step: verb, ...result });
  };

  if (!args.skipHealth) await assertHealth(row, node, secret, args.allowActive);

  const before = (
    await callJson(manifest.gatewayUrl + NODES_PATH, { headers })
  ).body.find((n) => n.nodeId === row.nodeId);
  steps.push({ step: "before", row: trimRow(before) });

  if (before) {
    if (before.state !== "admitted")
      throw new Error(`${row.nodeId}: row is ${before.state}`);

    await step("drain");
    await step("remove");
  }

  await step("register");
  await step("wait");
  await step("admit");
  // A Gateway drain also set the controller's own flag; clear it.
  steps.push({
    step: "resume",
    ...(await controllerResume(manifest, row.nodeId, secret, args.adminItem)),
  });

  return { steps };
}

async function main() {
  const args = parseArgs(process.argv.slice(2), {
    booleans: ["allowActive", "skipHealth", "help"],
  });
  const verb = args._[0];

  if (args.help || !verb || !args.manifest || (!args.node && verb !== "list")) {
    console.log(USAGE);
    process.exitCode = args.help ? 0 : 1;

    return;
  }

  const manifest = loadManifest(args.manifest);
  const account = args.keyAccount || DEFAULT_ACCOUNT;
  const secret = (item) =>
    readKeychain({ item, account, reader: args.keychainReader });
  const controller = Object.values(manifest.nodes).find(
    (n) => n.role === "controller",
  );

  args.receipts = args.receipts || ".";
  args.operatorItem = args.operatorItem || manifest.gatewaySecretRefs.operator;
  args.bypassItem = args.bypassItem || manifest.gatewaySecretRefs.bypass;
  args.adminItem =
    args.adminItem || controller.secretRefs.FLEET_CONTROLLER_ADMIN_TOKEN;

  const headers = {
    authorization: "Bearer " + secret(args.operatorItem),
    "content-type": "application/json",
  };
  if (args.bypassItem)
    headers["x-vercel-protection-bypass"] = secret(args.bypassItem);

  const { name, node } = args.node
    ? findNode(manifest, args.node)
    : { name: null, node: controller };
  const context = { verb, manifest, name, node, args, secret, headers };
  const startedAt = new Date().toISOString();
  const result =
    verb === "rotate" ? await rotate(context) : await runVerb(context);

  const receipt = {
    verb,
    node: node.nodeId,
    startedAt,
    finishedAt: new Date().toISOString(),
    ...result,
  };
  writeJson(
    path.join(args.receipts, `${node.nodeId}-gateway-${verb}-receipt.json`),
    receipt,
  );
  console.log(JSON.stringify(receipt, null, 2));
}

main().catch((error) => {
  console.error("Gateway action stopped:", error.name, error.message);
  process.exitCode = 1;
});
