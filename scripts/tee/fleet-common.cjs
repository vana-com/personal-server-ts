// Shared helpers for the fleet operator tools. Nothing here reads a secret
// from a file or an env var: every credential is named on the command line and
// read from the keychain once, per invocation.
const { execFileSync } = require("node:child_process");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

// The only Gateway row fields safe to keep in a receipt.
const ROW_KEYS = [
  "nodeId",
  "appId",
  "composeHash",
  "publicUrl",
  "state",
  "capacity",
  "activeSandboxes",
  "lastHeartbeatAt",
  "error",
  "code",
];
// The Gateway takes 0x-prefixed measurements; dstack reports them bare.
const HEX_PREFIX = "0x";
const KEYCHAIN_TIMEOUT_MS = 10_000;
const PRIVATE_MODE = 0o600;
const AGENT_PORT_KEY = "ENCLAVE_AGENT_PORT";
const ADMIN_PORT_KEY = "FLEET_ADMIN_PORT";

// `rotate` is drain -> remove -> register -> wait -> admit -> resume. Each
// state names the row's position in that sequence; the plan is what is still
// left to do to reach `admitted` + a clean controller resume from there.
const ROTATE_PLAN = {
  admitted: ["drain", "remove", "register", "wait", "admit", "resume"],
  draining: ["remove", "register", "wait", "admit", "resume"],
  removed: ["register", "wait", "admit", "resume"],
  registered: ["wait", "admit", "resume"],
  heartbeating: ["admit", "resume"],
};
const ROTATE_STATES = Object.keys(ROTATE_PLAN);

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** A minimal `--flag value` parser; unknown flags are an operator typo. */
function parseArgs(argv, { booleans = [], repeatable = [] } = {}) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) {
      args._.push(token);
      continue;
    }

    const key = token.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    if (booleans.includes(key)) {
      args[key] = true;
      continue;
    }

    const value = argv[i + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new Error(`${token} needs a value`);
    }

    i += 1;
    if (repeatable.includes(key)) {
      args[key] = (args[key] || []).concat(value);
      continue;
    }

    args[key] = value;
  }

  return args;
}

/** Read one keychain item. `reader` is an optional non-interactive helper. */
function readKeychain({ item, account, reader }) {
  if (!item || !account) throw new Error("Keychain item and account required");

  if (reader) {
    return execFileSync("python3", [reader], {
      input: JSON.stringify({ service: item, account }),
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
      timeout: KEYCHAIN_TIMEOUT_MS,
    }).trim();
  }

  return execFileSync(
    "security",
    ["find-generic-password", "-a", account, "-s", item, "-w"],
    {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: KEYCHAIN_TIMEOUT_MS,
    },
  ).trim();
}

/** A dstack Gateway URL for one measured port of a node. */
function nodeUrl(manifest, node, portKey) {
  const port = node.env[portKey];
  if (!port) throw new Error(`${node.nodeId} has no ${portKey}`);

  return `https://${node.pinned.instanceId}-${port}.${manifest.gatewayDomain}`;
}

/** The Gateway directory row a worker must be registered and admitted with. */
function gatewayRow(manifest, name) {
  const node = manifest.nodes[name];
  if (!node || node.role !== "worker")
    throw new Error(`${name} is not a worker`);

  return {
    nodeId: node.nodeId,
    appId: HEX_PREFIX + node.appId,
    composeHash: HEX_PREFIX + node.pinned.composeHash,
    publicUrl: nodeUrl(manifest, node, AGENT_PORT_KEY),
    capacity: node.capacity,
  };
}

/** The controller's admin listener, where drains are resumed. */
function controllerAdminUrl(manifest) {
  const entry = Object.values(manifest.nodes).find(
    (n) => n.role === "controller",
  );
  if (!entry) throw new Error("Manifest has no controller node");

  return nodeUrl(manifest, entry, ADMIN_PORT_KEY);
}

/** Resolve a manifest node by its manifest name or its nodeId. */
function findNode(manifest, wanted) {
  const names = Object.keys(manifest.nodes);
  const name = names.find(
    (n) => n === wanted || manifest.nodes[n].nodeId === wanted,
  );
  if (!name) throw new Error(`Unknown node ${wanted}`);

  return { name, node: manifest.nodes[name] };
}

/**
 * Classify a Gateway row into the rotate state machine, so a rerun resumes
 * instead of exiting `row is draining`. `before` is undefined when the row
 * was already removed and dropped from the list.
 */
function detectRotateState(before, heartbeatMaxAgeMs) {
  if (!before || before.state === "removed") return "removed";
  if (before.state === "draining") return "draining";
  if (before.state === "admitted") return "admitted";

  if (before.state === "pending") {
    const age = before.lastHeartbeatAt
      ? Date.now() - Date.parse(before.lastHeartbeatAt)
      : Infinity;

    return age < heartbeatMaxAgeMs ? "heartbeating" : "registered";
  }

  throw new Error(`${before.nodeId}: no rotate state for row ${before.state}`);
}

const trimRow = (row) =>
  Object.fromEntries(
    Object.entries(row || {}).filter(([k]) => ROW_KEYS.includes(k)),
  );

/** `envs update` fails while a compose deploy is still applying; that retries. */
const isBusy = (text) => /409|already in progress/i.test(text || "");

/** Create the receipts dir if needed, and refuse to push without one. */
function ensureReceiptsWritable(dir) {
  fs.mkdirSync(dir, { recursive: true });

  try {
    fs.accessSync(dir, fs.constants.W_OK);
  } catch {
    throw new Error(`Receipts dir ${dir} is not writable`);
  }
}

function writeJson(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + "\n");

  return file;
}

/** CLI output can echo a pushed env, so it never lands in public evidence. */
function writePrivate(file, text) {
  fs.writeFileSync(file, text, { mode: PRIVATE_MODE });

  return file;
}

function loadManifest(file) {
  const manifest = JSON.parse(fs.readFileSync(path.resolve(file), "utf8"));
  if (!manifest.nodes || !manifest.operatorPublicKeySpkiBase64) {
    throw new Error("Manifest needs nodes and operatorPublicKeySpkiBase64");
  }

  return manifest;
}

module.exports = {
  ROTATE_PLAN,
  ROTATE_STATES,
  ROW_KEYS,
  controllerAdminUrl,
  detectRotateState,
  ensureReceiptsWritable,
  findNode,
  gatewayRow,
  isBusy,
  loadManifest,
  nodeUrl,
  parseArgs,
  readKeychain,
  sha256,
  sleep,
  trimRow,
  writeJson,
  writePrivate,
};
