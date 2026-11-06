// Wall time of one connector run: today's legacy write versus stream sync.
//
// Usage (after `npm run build`; a data-gateway must run at --gateway with
// Anvil account #2 registered as the owner's (account #0) server):
//   node scripts/stream-sync-bench.mjs --mode legacy|intake|whole \
//     --fixture repeated|chatgpt --gateway http://127.0.0.1:55442 \
//     --dir ~/.tmp/bench [--mb 312] [--conversations 2700]
//
// Modes:
//   legacy  collect the run's records in memory, write one legacy
//           `{records}` file per stream (`writeDataFile`), then publish it
//           (`publishVersion`: encrypt, upload, POST), as the upload worker does.
//   intake  stream sync `beginRun`..`finishRun` only (spool, compaction).
//   whole   intake, then `publishPending` (plan, merge, upload, POST).
//
// Blobs are served by a child process of this script, kept on disk under
// --dir/blobs, so the measured process holds no blob bytes. Prints one JSON
// line. Run under `--max-old-space-size=<MiB>` to test a heap cap.

import { fork } from "node:child_process";
import { createServer } from "node:http";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { parseArgs } from "node:util";
import { getHeapStatistics } from "node:v8";
import { privateKeyToAccount } from "viem/accounts";
import { createGatewayClient } from "@opendatalabs/vana-sdk/node";
import {
  StreamSyncWriter,
  createGatewayStreamSyncRegistry,
  createStorageStreamSyncBlobs,
  createStreamSyncKeyPorts,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createVanaSyncStorageAdapter } from "@opendatalabs/personal-server-ts-core/storage/adapters";
import { publishVersion } from "../packages/core/dist/publication/publish.js";
import { writeDataFile } from "../packages/server/dist/storage/hierarchy.js";
import { createFsStreamSyncFiles } from "../packages/server/dist/stream-sync/fs-files.js";

const { values } = parseArgs({
  options: {
    mode: { type: "string" },
    fixture: { type: "string", default: "repeated" },
    gateway: { type: "string" },
    dir: { type: "string" },
    mb: { type: "string", default: "312" },
    keys: { type: "string", default: "10000" },
    record: { type: "string", default: "1000" },
    conversations: { type: "string", default: "2700" },
    serve: { type: "string" },
  },
});

// ----------------------------------------------------------- blob server

if (values.serve) {
  // Child process: a write-once blob store with the Vana storage HTTP shape.
  const root = values.serve;
  const server = createServer((req, res) => {
    const path = decodeURIComponent(
      new URL(req.url ?? "/", "http://x").pathname,
    );
    const file = join(root, path);
    if (req.method === "PUT") {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", async () => {
        const body = Buffer.concat(chunks);
        const existing = await readFile(file).catch(() => null);
        if (existing && !existing.equals(body)) {
          res.statusCode = 409;
          res.end("different bytes");
          return;
        }
        await mkdir(dirname(file), { recursive: true });
        await writeFile(file, body);
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            url: path,
            size: body.length,
            key: path,
            etag: "e",
          }),
        );
      });
      return;
    }
    if (req.method === "GET") {
      readFile(file).then(
        (b) => {
          res.end(b);
        },
        () => {
          res.statusCode = 404;
          res.end("not found");
        },
      );
      return;
    }
    res.statusCode = 405;
    res.end();
  });
  server.listen(0, "127.0.0.1", () => {
    process.send({ port: server.address().port });
  });
  process.on("message", (m) => m === "stop" && process.exit(0));
}

// -------------------------------------------------------------- fixtures

function rng(seed) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const WORDS =
  "the of and to in is that it for as with was on are by this be from or an have not at but they which one you were all can her has there been if more when will would who so no".split(
    " ",
  );

/** Repeated-key stream: `mb` MB of 1 KB records over `keys` distinct keys. */
function* repeatedFixture() {
  const keys = Number(values.keys);
  const pad = "x".repeat(Number(values.record));
  const target = Number(values.mb) * 1e6;
  let bytes = 0;
  let i = 0;
  while (bytes < target) {
    yield {
      stream: "s",
      record: { id: `k${i % keys}`, rev: i, body: pad },
    };
    bytes += Number(values.record) + 40;
    i += 1;
  }
}

/**
 * ChatGPT-shaped run: a `conversations` stream and a `messages` stream, a
 * conversation row followed by its messages, as a connector emits them. Sizes
 * are log-normal: median 8 messages (mean about 20, at most 300) per
 * conversation, median 500 B (mean about 1.6 KB, at most 64 KB) per message.
 */
function* chatgptFixture() {
  const rand = rng(1105);
  const normal = () => {
    const u = Math.max(rand(), 1e-9);
    return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * rand());
  };
  const text = (bytes) => {
    const out = [];
    let n = 0;
    while (n < bytes) {
      const w = WORDS[Math.floor(rand() * WORDS.length)];
      out.push(w);
      n += w.length + 1;
    }
    return out.join(" ");
  };
  const total = Number(values.conversations);
  const base = Date.parse("2025-01-01T00:00:00Z");
  for (let c = 0; c < total; c += 1) {
    const count = Math.min(
      300,
      Math.max(1, Math.round(Math.exp(Math.log(8) + 1.1 * normal()))),
    );
    const convId = `6700a1b2-0000-4000-8000-${c.toString(16).padStart(12, "0")}`;
    const created = new Date(base + c * 3_600_000).toISOString();
    yield {
      stream: "conversations",
      record: {
        id: convId,
        title: text(20 + Math.floor(rand() * 40)),
        create_time: created,
        update_time: new Date(
          base + c * 3_600_000 + count * 60_000,
        ).toISOString(),
        is_archived: false,
        is_starred: null,
        workspace_id: null,
        current_node: `${convId}-m${count - 1}`,
        message_count: count,
      },
    };
    for (let m = 0; m < count; m += 1) {
      const size = Math.min(
        65536,
        Math.max(20, Math.round(Math.exp(Math.log(500) + 1.2 * normal()))),
      );
      yield {
        stream: "messages",
        record: {
          id: `${convId}-m${m}`,
          conversation_id: convId,
          parent_id: m ? `${convId}-m${m - 1}` : null,
          role: m % 2 === 0 ? "user" : "assistant",
          content_type: "text",
          content: text(size),
          create_time: new Date(
            base + c * 3_600_000 + m * 60_000,
          ).toISOString(),
          model: m % 2 === 0 ? null : "gpt-4o",
          on_current_branch: true,
        },
      };
    }
  }
}

const fixtureRecords = () =>
  values.fixture === "chatgpt" ? chatgptFixture() : repeatedFixture();

// ------------------------------------------------------------------ main

async function main() {
  if (!values.mode || !values.gateway || !values.dir)
    throw new Error("--mode, --gateway and --dir are required");
  const OWNER_KEY =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
  const account = privateKeyToAccount(OWNER_KEY);
  const config = ServerConfigSchema.parse({});
  const root = values.dir;
  await rm(root, { recursive: true, force: true });
  await mkdir(root, { recursive: true });

  const child = fork(new URL(import.meta.url).pathname, [
    "--serve",
    join(root, "blobs"),
  ]);
  const { port } = await new Promise((resolve) =>
    child.once("message", resolve),
  );
  const storageUrl = `http://127.0.0.1:${port}`;
  const storageAdapter = createVanaSyncStorageAdapter({
    config: ServerConfigSchema.parse({
      storage: { backend: "vana", config: { vana: { apiUrl: storageUrl } } },
    }),
    serverOwner: account.address,
    serverAccount: {
      address: account.address,
      signMessage: (message) => account.signMessage({ message }),
    },
  });
  // The full server signs AddData with its registered server key (Anvil
  // account #2); the gateway must list that address as the owner's server.
  const SERVER_KEY =
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
  const serverAccount = privateKeyToAccount(SERVER_KEY);
  const signer = createServerSigner(
    {
      address: serverAccount.address,
      publicKey: serverAccount.publicKey,
      signTypedData: (p) => serverAccount.signTypedData(p),
      signMessage: (message) => serverAccount.signMessage({ message }),
    },
    { chainId: config.gateway.chainId, contracts: config.gateway.contracts },
  );

  let peakRss = 0;
  let peakHeap = 0;
  const sample = () => {
    peakRss = Math.max(peakRss, process.memoryUsage.rss());
    peakHeap = Math.max(peakHeap, getHeapStatistics().used_heap_size);
  };
  const timer = setInterval(sample, 25);
  const mib = (n) => Math.round(n / 1048576);
  const connector = `bench${Date.now().toString(36)}`;
  const report = { mode: values.mode, fixture: values.fixture };
  const start = Date.now();
  const lap = () => (Date.now() - start) / 1000;

  if (values.mode === "legacy") {
    // The connector's records are collected in memory; the legacy file is one
    // `{records}` body per stream.
    const perStream = new Map();
    let records = 0;
    for (const { stream, record } of fixtureRecords()) {
      if (!perStream.has(stream)) perStream.set(stream, []);
      perStream.get(stream).push(record);
      records += 1;
    }
    sample();
    report.records = records;
    report.collectSeconds = lap();
    const collectedAt = new Date().toISOString();
    const masterKey = new Uint8Array(32).fill(7);
    const gateway = createGatewayClient(values.gateway);
    let version = 1n;
    let writeSeconds = 0;
    let publishSeconds = 0;
    let wireBytes = 0;
    for (const [stream, rows] of perStream) {
      const scope = `pdpp.${connector}.${stream}`;
      const envelope = {
        version: "1.0",
        scope,
        collectedAt,
        data: { records: rows },
      };
      let t = Date.now();
      const written = await writeDataFile(
        { dataDir: join(root, "data") },
        envelope,
      );
      writeSeconds += (Date.now() - t) / 1000;
      wireBytes += written.sizeBytes;
      sample();
      t = Date.now();
      await publishVersion({
        ownerAddress: account.address,
        envelope,
        preferredVersion: version,
        masterKey,
        storageAdapter,
        gateway,
        signer,
        readHead: async () => null,
        head: null,
      });
      publishSeconds += (Date.now() - t) / 1000;
      sample();
    }
    report.fileBytesMB = Math.round(wireBytes / 1e6);
    report.writeSeconds = writeSeconds;
    report.publishSeconds = publishSeconds;
  } else {
    // Instrument the host ports so the profile shows where time goes.
    const prof = {};
    const timed = (group, name, fn) =>
      async function (...args) {
        const t = process.hrtime.bigint();
        try {
          return await fn.apply(this, args);
        } finally {
          const e =
            prof[`${group}.${name}`] ??
            (prof[`${group}.${name}`] = { n: 0, ms: 0 });
          e.n += 1;
          e.ms += Number(process.hrtime.bigint() - t) / 1e6;
        }
      };
    const wrap = (group, port) =>
      Object.fromEntries(
        Object.entries(port).map(([k, v]) =>
          typeof v === "function" && !k.startsWith("read" + "Chunks")
            ? [k, timed(group, k, v)]
            : [k, v],
        ),
      );
    const fsFiles = createFsStreamSyncFiles(join(root, "outbox"));
    const files = { ...wrap("files", fsFiles), readChunks: fsFiles.readChunks };
    const blobs = wrap("blobs", createStorageStreamSyncBlobs(storageAdapter));
    const registry = wrap(
      "registry",
      createGatewayStreamSyncRegistry({
        gatewayUrl: values.gateway,
        ownerAddress: account.address,
      }),
    );
    const writer = new StreamSyncWriter({
      ownerAddress: account.address,
      registry,
      blobs,
      files,
      keys: createStreamSyncKeyPorts(
        await account.signMessage({ message: "vana-master-key-v1" }),
      ),
      signer,
    });
    await writer.refreshControls();
    await writer.beginRun({
      runId: "bench-run",
      connector,
      userConnect: false,
      identity: "none",
    });
    const declared = new Set();
    let records = 0;
    let bytes = 0;
    for (const { stream, record } of fixtureRecords()) {
      if (!declared.has(stream)) {
        declared.add(stream);
        await writer.declareStream("bench-run", stream, {
          primaryKey: ["id"],
          profile: { key: null, version: "1.0.0" },
        });
      }
      await writer.append("bench-run", stream, record);
      records += 1;
      bytes += JSON.stringify(record).length + 1;
    }
    sample();
    report.records = records;
    report.inputMB = Math.round(bytes / 1e6);
    report.appendSeconds = lap();
    await writer.finishRun("bench-run", { checkpointCandidate: null });
    sample();
    report.intakeSeconds = lap();
    if (values.mode === "whole") {
      const published = await writer.publishPending();
      sample();
      const run = published.runs[0];
      report.outcome = run?.outcome?.kind;
      report.streams = Object.fromEntries(
        Object.entries(run?.streams ?? {}).map(([k, v]) => [
          k,
          {
            state: v.state,
            complete: v.complete,
            problem: v.problem,
            detail: v.detail,
          },
        ]),
      );
      report.publishSeconds = lap() - report.intakeSeconds;
    }
    report.profile = Object.fromEntries(
      Object.entries(prof).map(([k, v]) => [
        k,
        { n: v.n, seconds: Math.round(v.ms) / 1000 },
      ]),
    );
  }

  report.seconds = lap();
  report.recordsPerSecond = Math.round(report.records / report.seconds);
  clearInterval(timer);
  sample();
  report.peakRssMiB = mib(peakRss);
  report.peakHeapMiB = mib(peakHeap);
  report.maxRssMiB = mib(process.resourceUsage().maxRSS * 1024);
  console.log(JSON.stringify(report));
  child.kill();
  await rm(root, { recursive: true, force: true });
  process.exit(0);
}

if (!values.serve) await main();
