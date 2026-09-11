#!/usr/bin/env node
// Sign the drafts render-fleet.py produced and push each one as its CVM's
// sealed FLEET_SIGNED_CONFIG.
//
//   node scripts/tee/sign-fleet.cjs --manifest deploy/dstack/fleets/<f>.json \
//     --drafts rendered/ --key-item <keychain item> [--node worker-1] [--apply]
//
// The operator key and every referenced credential are read from the keychain
// per invocation, by item name given here - never from an env file, and never
// written anywhere. The signed bundle carries those credentials, so it is
// never printed and never lands in a receipt.
const { spawnSync, execFileSync } = require("node:child_process");
const { createPrivateKey, createPublicKey, sign } = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const {
  findNode,
  isBusy,
  loadManifest,
  parseArgs,
  readKeychain,
  sha256,
  sleep,
  writeJson,
  writePrivate,
} = require("./fleet-common.cjs");

const USAGE = `sign-fleet.cjs --manifest <fleet.json> --drafts <dir> --key-item <keychain item>
  [--key-account <account>]     keychain account, default spike-agent
  [--keychain-reader <script>]  non-interactive reader; stdin {service,account}
  [--node <name>]...            sign only these nodes, default all
  [--receipts <dir>]            default: the drafts dir
  [--verifier <path>]           default: packages/enclave/dist/fleet/security-config.js
  [--apply]                     settle the CVM, then phala envs update
  [--no-digest-check]           skip the render-receipt.json draft digest fence`;

const DEFAULT_ACCOUNT = "spike-agent";
const RENDER_RECEIPT = "render-receipt.json";
const VERIFIER = "packages/enclave/dist/fleet/security-config.js";
const ALLOWED_ENVS = ["FLEET_SIGNED_CONFIG"];
const SIGNED_CONFIG_ENV = "FLEET_SIGNED_CONFIG";
// dstack 0.5.9 loses backslashes from an EnvironmentFile, so the bundle goes
// over the wire as strict canonical base64.
const WIRE_PREFIX = "base64:";
const PHALA_TIMEOUT_MS = 600_000;
const SETTLE_POLL_MS = 15_000;
const SETTLE_TIMEOUT_MS = 20 * 60_000;
const BUSY_RETRY_MS = 30_000;
const BUSY_MAX_ATTEMPTS = 6;
const RUNNING = "running";

const now = () => new Date().toISOString();

const phala = (args) =>
  JSON.parse(
    execFileSync("phala", args, {
      encoding: "utf8",
      timeout: PHALA_TIMEOUT_MS,
    }),
  );

/** The sealed payload: the reviewed draft with its credentials filled in. */
function signingPayload(draft, node, secret) {
  const { secretRefs, ...payload } = draft;
  payload.issuedAt = now();
  // A fleet config never expires on its own; the next roll replaces it.
  payload.expiresAt = null;
  payload.env = { ...payload.env };

  for (const [key, item] of Object.entries(secretRefs || {})) {
    if (node.secretRefs?.[key] !== item) {
      throw new Error(`Unapproved credential reference ${key}=${item}`);
    }

    if (Object.hasOwn(payload.env, key)) {
      throw new Error(`${key} is both a signed env value and a credential`);
    }

    payload.env[key] = secret(item);
  }

  return payload;
}

/** Wait for a staged CVM to finish applying before its env is replaced. */
async function settle(uuid) {
  const deadline = Date.now() + SETTLE_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const status = phala(["api", "/cvms/" + uuid, "--json"]).status;
    if (status === RUNNING) return now();

    await sleep(SETTLE_POLL_MS);
  }

  throw new Error(`CVM ${uuid} never settled to ${RUNNING}`);
}

/** Fence the live manifest against what was rendered, before anything lands. */
function assertStaged(name, node, composeText) {
  const before = phala(["api", "/cvms/" + node.uuid, "--json"]);
  const actual = JSON.stringify(before.compose_file.allowed_envs);

  if (before.app_id !== node.appId) throw new Error(`${name}: app id moved`);
  if (before.compose_hash !== node.pinned.composeHash) {
    throw new Error(`${name}: staged compose_hash is ${before.compose_hash}`);
  }

  if (actual !== JSON.stringify(ALLOWED_ENVS)) {
    throw new Error(`${name}: allowed_envs is ${actual}`);
  }

  if (composeText && before.compose_file.docker_compose_file !== composeText) {
    throw new Error(`${name}: staged compose differs from the rendered file`);
  }

  return before;
}

/** Push the sealed bundle, retrying the 409 a still-applying deploy returns. */
async function updateEnv(name, uuid, bundle, receipts) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `fleet-signed-${name}-`));
  fs.chmodSync(dir, 0o700);
  const attempts = [];

  try {
    const envFile = path.join(dir, "sealed.env");
    writePrivate(envFile, `${SIGNED_CONFIG_ENV}=${bundle}\n`);

    for (let attempt = 1; attempt <= BUSY_MAX_ATTEMPTS; attempt += 1) {
      const startedAt = now();
      const run = spawnSync(
        "phala",
        ["envs", "update", uuid, "-e", envFile, "--json"],
        {
          encoding: "utf8",
          cwd: dir,
        },
      );
      const output = (run.stdout || "") + (run.stderr || "");
      writePrivate(
        path.join(receipts, `${name}-env-update-private.txt`),
        output,
      );
      attempts.push({
        attempt,
        startedAt,
        finishedAt: now(),
        exit: run.status,
      });

      if (run.status === 0) return attempts;

      if (!isBusy(output))
        throw new Error(`${name}: envs update exit ${run.status}`);

      // The compose deploy is still applying; that is the known 409.
      await sleep(BUSY_RETRY_MS);
    }

    throw new Error(
      `${name}: envs update stayed busy after ${BUSY_MAX_ATTEMPTS} attempts`,
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

async function signNode({ manifest, name, node, args, secret, digests }) {
  const draftName = node.draft || `${name}-config.draft.json`;
  const draftPath = path.join(args.drafts, draftName);
  const bytes = fs.readFileSync(draftPath);
  const draftSha256 = sha256(bytes);

  if (digests && digests[draftName] !== draftSha256) {
    throw new Error(`${name}: draft does not match ${RENDER_RECEIPT}`);
  }

  const payload = signingPayload(
    JSON.parse(bytes.toString("utf8")),
    node,
    secret,
  );
  const verifier = await import(
    pathToFileURL(path.resolve(args.verifier)).href
  );
  const signingBytes = verifier.canonicalFleetConfigPayload(payload);

  const privateKey = createPrivateKey({
    key: Buffer.from(secret(args.keyItem), "base64"),
    format: "der",
    type: "pkcs8",
  });
  const publicKey = createPublicKey(privateKey)
    .export({ format: "der", type: "spki" })
    .toString("base64");

  if (publicKey !== manifest.operatorPublicKeySpkiBase64) {
    throw new Error("Signing key differs from the measured trust root");
  }

  const signature = sign(null, signingBytes, privateKey).toString("base64");
  const document = JSON.stringify({ payload, signature });
  const bundle = WIRE_PREFIX + Buffer.from(document, "utf8").toString("base64");

  // Local structural and signature proof only; the enclave re-checks these
  // bindings against its own dstack identity before any state loads.
  await verifier.verifiedFleetEnvironment(
    { FLEET_CONFIG_PUBLIC_KEY: publicKey, [SIGNED_CONFIG_ENV]: bundle },
    {
      role: payload.role,
      identity: async () => ({
        appId: payload.appId,
        instanceId: payload.instanceId,
      }),
    },
  );

  const receipt = {
    node: name,
    draftPath,
    draftSha256,
    wireEncoding: WIRE_PREFIX,
    wireBytes: Buffer.byteLength(bundle),
    wireSha256: sha256(bundle),
    signingPayloadSha256: sha256(signingBytes),
    publicKeySpkiBase64: publicKey,
    role: payload.role,
    appId: payload.appId,
    instanceId: payload.instanceId,
    nodeId: payload.nodeId,
    issuedAt: payload.issuedAt,
    expiresAt: payload.expiresAt,
    expectedComposeHash: node.pinned.composeHash,
    signedEnvKeys: Object.keys(payload.env).sort(),
    secretReferences: node.secretRefs,
    applied: Boolean(args.apply),
  };

  if (args.apply) {
    const composeFile =
      node.composeOut && path.join(args.drafts, node.composeOut);
    const composeText =
      composeFile && fs.existsSync(composeFile)
        ? fs.readFileSync(composeFile, "utf8")
        : null;

    assertStaged(name, node, composeText);
    const settleStartedAt = now();
    const runningAt = await settle(node.uuid);
    const attempts = await updateEnv(name, node.uuid, bundle, args.receipts);
    receipt.timings = {
      settleStartedAt,
      runningAt,
      attempts,
      finishedAt: now(),
    };
  }

  writeJson(
    path.join(args.receipts, `${name}-signed-config-receipt.json`),
    receipt,
  );
  console.log(
    JSON.stringify({
      node: name,
      issuedAt: receipt.issuedAt,
      expiresAt: receipt.expiresAt,
      composeHash: receipt.expectedComposeHash,
      applied: receipt.applied,
      attempts: receipt.timings?.attempts.length ?? 0,
    }),
  );
}

async function main() {
  const args = parseArgs(process.argv.slice(2), {
    booleans: ["apply", "noDigestCheck", "help"],
    repeatable: ["node"],
  });

  if (args.help || !args.manifest || !args.drafts || !args.keyItem) {
    console.log(USAGE);
    process.exitCode = args.help ? 0 : 1;

    return;
  }

  const manifest = loadManifest(args.manifest);
  args.receipts = args.receipts || args.drafts;
  args.verifier = args.verifier || path.join(__dirname, "..", "..", VERIFIER);
  const account = args.keyAccount || DEFAULT_ACCOUNT;
  const secret = (item) =>
    readKeychain({ item, account, reader: args.keychainReader });

  const receiptPath = path.join(args.drafts, RENDER_RECEIPT);
  const digests = args.noDigestCheck
    ? null
    : JSON.parse(fs.readFileSync(receiptPath, "utf8")).draftSha256;

  const wanted = args.node || Object.keys(manifest.nodes);
  for (const entry of wanted) {
    const { name, node } = findNode(manifest, entry);
    await signNode({ manifest, name, node, args, secret, digests });
  }
}

main().catch((error) => {
  console.error("Signing stopped:", error.name, error.message);
  process.exitCode = 1;
});
