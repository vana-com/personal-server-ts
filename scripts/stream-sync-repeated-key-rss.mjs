// Peak memory of one stream-sync publish of a repeated-key stream (lane P1
// oracle, design §2.6: memory scales with distinct keys, not versions).
//
// Usage (after `npm run build`):
//   node scripts/stream-sync-repeated-key-rss.mjs \
//     --gateway http://127.0.0.1:55441 --dir ~/.tmp/rss --mb 312 --keys 10000
//
// The gateway must accept AddData signed by the owner (Anvil account #0).
// Spool and blobs are files under --dir. Prints one JSON line.

import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { parseArgs } from "node:util";
import { privateKeyToAccount } from "viem/accounts";
import {
  StreamSyncWriter,
  createGatewayStreamSyncRegistry,
  createStreamSyncKeyPorts,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createFsStreamSyncFiles } from "../packages/server/dist/stream-sync/fs-files.js";

const { values } = parseArgs({
  options: {
    gateway: { type: "string" },
    dir: { type: "string" },
    mb: { type: "string", default: "312" },
    keys: { type: "string", default: "10000" },
    record: { type: "string", default: "1000" },
  },
});
if (!values.gateway || !values.dir)
  throw new Error("--gateway and --dir are required");

const OWNER_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const account = privateKeyToAccount(OWNER_KEY);
const config = ServerConfigSchema.parse({});
const root = values.dir;
await rm(root, { recursive: true, force: true });

const blobs = {
  async put(key, bytes) {
    const path = join(root, "blobs", key);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, bytes, { flag: "wx" }).catch((e) => {
      if (e.code !== "EEXIST") throw e;
    });
  },
  async get(key) {
    return readFile(join(root, "blobs", key)).then(
      (b) => new Uint8Array(b),
      (e) => {
        if (e.code === "ENOENT") return null;
        throw e;
      },
    );
  },
};

const writer = new StreamSyncWriter({
  ownerAddress: account.address,
  registry: createGatewayStreamSyncRegistry({
    gatewayUrl: values.gateway,
    ownerAddress: account.address,
  }),
  blobs,
  files: createFsStreamSyncFiles(join(root, "outbox")),
  keys: createStreamSyncKeyPorts(
    await account.signMessage({ message: "vana-master-key-v1" }),
  ),
  signer: createServerSigner(
    {
      address: account.address,
      publicKey: account.publicKey,
      signTypedData: (p) => account.signTypedData(p),
      signMessage: (message) => account.signMessage({ message }),
    },
    { chainId: config.gateway.chainId, contracts: config.gateway.contracts },
  ),
});

let peak = 0;
const sample = () => {
  peak = Math.max(peak, process.memoryUsage.rss());
};
const timer = setInterval(sample, 50);
global.gc?.();
const baseline = process.memoryUsage.rss();

const connector = `rss-${Date.now().toString(36)}`;
const keys = Number(values.keys);
const recordBytes = Number(values.record);
const target = Number(values.mb) * 1e6;
const pad = "x".repeat(recordBytes);
let bytes = 0;
let records = 0;
const start = Date.now();
await writer.refreshControls();
await writer.beginRun({
  runId: "rss-run",
  connector,
  userConnect: false,
  identity: "none",
});
await writer.declareStream("rss-run", "s", {
  primaryKey: ["id"],
  profile: { key: null, version: "1.0.0" },
});
while (bytes < target) {
  const record = { id: `k${records % keys}`, rev: records, body: pad };
  await writer.append("rss-run", "s", record);
  bytes += recordBytes + 40;
  records += 1;
}
sample();
const afterIntake = peak;
await writer.finishRun("rss-run", { checkpointCandidate: null });
sample();
const afterFinish = peak;
const report = await writer.publishPending();
sample();
clearInterval(timer);
const run = report.runs[0];
const mib = (n) => Math.round(n / 1048576);
console.log(
  JSON.stringify({
    inputMB: Math.round(bytes / 1e6),
    records,
    distinctKeys: keys,
    outcome: run?.outcome,
    stream: run?.streams.s,
    baselineRssMiB: mib(baseline),
    peakRssMiB: mib(peak),
    peakIntakeMiB: mib(afterIntake),
    peakFinishMiB: mib(afterFinish),
    maxRssMiB: mib(process.resourceUsage().maxRSS * 1024),
    seconds: Math.round((Date.now() - start) / 1000),
  }),
);
await rm(root, { recursive: true, force: true });
