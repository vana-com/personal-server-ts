// `node --test scripts/tee/fleet-common.test.mjs` - pure helpers only; the
// signing and Gateway paths are exercised against a real fleet, never here.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));
const common = require("./fleet-common.cjs");
const manifest = JSON.parse(
  readFileSync(
    path.join(
      here,
      "..",
      "..",
      "deploy",
      "dstack",
      "fleets",
      "preview-prod5.json",
    ),
    "utf8",
  ),
);

test("parseArgs reads flags, booleans and repeats", () => {
  const args = common.parseArgs(
    [
      "rotate",
      "--manifest",
      "f.json",
      "--key-item",
      "k",
      "--node",
      "a",
      "--node",
      "b",
      "--apply",
    ],
    { booleans: ["apply"], repeatable: ["node"] },
  );

  assert.deepEqual(args._, ["rotate"]);
  assert.equal(args.manifest, "f.json");
  assert.equal(args.keyItem, "k");
  assert.deepEqual(args.node, ["a", "b"]);
  assert.equal(args.apply, true);
});

test("parseArgs refuses a flag with no value", () => {
  assert.throws(() =>
    common.parseArgs(["--manifest", "--apply"], { booleans: ["apply"] }),
  );
});

test("gatewayRow is the 0x-prefixed pinned row", () => {
  const row = common.gatewayRow(manifest, "worker-1");
  const node = manifest.nodes["worker-1"];

  assert.equal(row.nodeId, node.nodeId);
  assert.equal(row.appId, "0x" + node.appId);
  assert.equal(row.composeHash, "0x" + node.pinned.composeHash);
  assert.equal(row.capacity, node.capacity);
  assert.equal(
    row.publicUrl,
    `https://${node.pinned.instanceId}-${node.env.ENCLAVE_AGENT_PORT}.${manifest.gatewayDomain}`,
  );
});

test("gatewayRow refuses the controller", () => {
  assert.throws(
    () => common.gatewayRow(manifest, "controller"),
    /not a worker/,
  );
});

test("controllerAdminUrl uses the signed admin port", () => {
  const controller = manifest.nodes.controller;

  assert.equal(
    common.controllerAdminUrl(manifest),
    `https://${controller.pinned.instanceId}-${controller.env.FLEET_ADMIN_PORT}.${manifest.gatewayDomain}`,
  );
});

test("findNode accepts a manifest name or a nodeId", () => {
  assert.equal(common.findNode(manifest, "worker-2").name, "worker-2");
  assert.equal(
    common.findNode(manifest, manifest.nodes["worker-2"].nodeId).name,
    "worker-2",
  );
  assert.throws(() => common.findNode(manifest, "worker-9"), /Unknown node/);
});

test("trimRow keeps only reportable row fields", () => {
  const trimmed = common.trimRow({
    nodeId: "n",
    state: "admitted",
    secret: "s",
    token: "t",
  });

  assert.deepEqual(trimmed, { nodeId: "n", state: "admitted" });
});

test("isBusy matches the still-applying deploy", () => {
  assert.equal(
    common.isBusy("409 Another operation is already in progress for this CVM"),
    true,
  );
  assert.equal(common.isBusy("Another operation is already in progress"), true);
  assert.equal(common.isBusy("401 Unauthorized"), false);
  assert.equal(common.isBusy(""), false);
});

test("loadManifest rejects a manifest with no trust root", () => {
  assert.throws(
    () => common.loadManifest(path.join(here, "..", "..", "package.json")),
    /Manifest/,
  );
});

test("ensureReceiptsWritable creates a missing dir", () => {
  const parent = mkdtempSync(path.join(os.tmpdir(), "fleet-receipts-"));
  const dir = path.join(parent, "receipts");

  try {
    assert.equal(existsSync(dir), false);
    common.ensureReceiptsWritable(dir);
    assert.equal(existsSync(dir), true);
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test("ensureReceiptsWritable refuses a read-only dir", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "fleet-receipts-ro-"));

  try {
    chmodSync(dir, 0o500);
    assert.throws(() => common.ensureReceiptsWritable(dir), /not writable/);
  } finally {
    chmodSync(dir, 0o700);
    rmSync(dir, { recursive: true, force: true });
  }
});

test("detectRotateState resumes from wherever the row already sits", () => {
  assert.equal(common.detectRotateState(undefined, 60_000), "removed");
  assert.equal(
    common.detectRotateState({ state: "removed" }, 60_000),
    "removed",
  );
  assert.equal(
    common.detectRotateState({ state: "draining" }, 60_000),
    "draining",
  );
  assert.equal(
    common.detectRotateState({ state: "admitted" }, 60_000),
    "admitted",
  );
});

test("detectRotateState splits pending on heartbeat freshness", () => {
  const fresh = new Date().toISOString();
  const stale = new Date(Date.now() - 120_000).toISOString();

  assert.equal(
    common.detectRotateState(
      { state: "pending", lastHeartbeatAt: fresh },
      60_000,
    ),
    "heartbeating",
  );
  assert.equal(
    common.detectRotateState(
      { state: "pending", lastHeartbeatAt: stale },
      60_000,
    ),
    "registered",
  );
  assert.equal(
    common.detectRotateState({ state: "pending" }, 60_000),
    "registered",
  );
});

test("detectRotateState refuses a state with no rotate plan", () => {
  assert.throws(
    () => common.detectRotateState({ nodeId: "n", state: "weird" }, 60_000),
    /no rotate state/,
  );
});

test("ROTATE_PLAN ends every state at admit + resume", () => {
  for (const state of common.ROTATE_STATES) {
    const plan = common.ROTATE_PLAN[state];

    assert.deepEqual(plan.slice(-2), ["admit", "resume"]);
  }
});

test("the shipped manifest names credentials but never carries one", () => {
  for (const node of Object.values(manifest.nodes)) {
    for (const key of Object.keys(node.env)) {
      assert.equal(/SECRET|TOKEN|BYPASS/.test(key), false, key);
    }

    // A secretRef is a keychain item name, not the credential itself.
    for (const item of Object.values(node.secretRefs)) {
      assert.match(item, /^[a-z0-9][a-z0-9-]{0,63}$/);
    }
  }
});
