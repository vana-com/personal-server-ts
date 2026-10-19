/** Local-only reproducible producer proof. Run:
 * node --import tsx scripts/verify-additions-gateway.mjs ../data-gateway [--large]
 * Gateway checkout must be exactly #168 d8ed3c0; npm ci in both repos first.
 * All SQL/HTTP/blob state is disposable. No chain or production calls occur.
 */
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import { spawn, execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { keccak256, stringToHex, encodeAbiParameters } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  createDataFileEnvelope,
  deriveScopeKey,
  encryptWithPassword,
  buildWeb3SignedHeader,
} from "@opendatalabs/vana-sdk/browser";
import { createDurableAdditions } from "../packages/core/src/additions/durable.ts";
import { AdditionsBudget } from "../packages/core/src/additions/budget.ts";
import { createVersionInventoryClient } from "../packages/core/src/additions/version-inventory.ts";

const gatewayRoot = resolve(process.argv[2] ?? "../data-gateway");
assert.equal(
  execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: gatewayRoot,
    encoding: "utf8",
  }).trim(),
  "d8ed3c09952a4151ab94df30aa905423eca6a29d",
);
const requireGateway = createRequire(join(gatewayRoot, "package.json"));
const { default: EmbeddedPostgres } = await import(
  pathToFileURL(requireGateway.resolve("embedded-postgres"))
);
const root = await mkdtemp(join(tmpdir(), "ps-gateway-additions-"));
const large = process.argv.includes("--large");
const account = privateKeyToAccount(`0x${"11".repeat(32)}`);
const masterKey = new Uint8Array(32).fill(17);
const source = "test.conversations";
const keyPassword = (scope) =>
  Buffer.from(deriveScopeKey(masterKey, scope)).toString("hex");
const idFor = (scope) =>
  keccak256(
    encodeAbiParameters(
      [{ type: "address" }, { type: "string" }],
      [account.address, scope],
    ),
  );
const blobPath = (key) => join(root, encodeURIComponent(key));
let versionsHandler, listingHandler;
let inventoryCalls = 0,
  blobBytes = 0;
const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, "http://localhost");
    if (url.pathname.startsWith("/blob/")) {
      const bytes = await readFile(
        blobPath(decodeURIComponent(url.pathname.slice(6))),
      );
      response.end(bytes);
      return;
    }
    const query = Object.fromEntries(url.searchParams);
    const match = url.pathname.match(/^\/v1\/data\/(0x[a-f0-9]+)\/versions$/);
    const handler = match ? versionsHandler : listingHandler;
    if (match) {
      query.dataPointId = match[1];
      inventoryCalls++;
    }
    const req = { method: request.method, headers: request.headers, query };
    const res = {
      status(code) {
        response.statusCode = code;
        return this;
      },
      setHeader(name, value) {
        response.setHeader(name, value);
      },
      json(body) {
        response.setHeader("content-type", "application/json");
        response.end(JSON.stringify(body));
        return this;
      },
      end() {
        response.end();
      },
    };
    await handler(req, res);
  } catch (error) {
    response.statusCode = 500;
    response.end(String(error));
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const portProbe = createServer();
await new Promise((resolve) => portProbe.listen(0, "127.0.0.1", resolve));
const pgPort = portProbe.address().port;
await new Promise((resolve) => portProbe.close(resolve));
const pg = new EmbeddedPostgres({
  databaseDir: join(root, "pg"),
  port: pgPort,
  user: "gateway",
  password: "gateway",
  persistent: false,
  initdbFlags: ["--encoding=UTF8"],
  onLog() {},
  onError() {},
});
const run = (command, args, env) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: gatewayRoot,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout.on("data", (chunk) => (output += chunk));
    child.stderr.on("data", (chunk) => (output += chunk));
    child.on("error", reject);
    child.on("exit", (code) =>
      code === 0 ? resolve() : reject(new Error(output)),
    );
  });
let db, schema;
try {
  await pg.initialise();
  await pg.start();
  await pg.createDatabase("gateway");
  Object.assign(process.env, {
    NEON_URL: `postgres://gateway:gateway@127.0.0.1:${pgPort}/gateway`,
    USE_LOCAL_DB: "1",
    GATEWAY_PUBLIC_ORIGIN: origin,
    CHAIN_ID: "14800",
    DATA_REGISTRY_CONTRACT: "0x8C8788f98385F6ba1adD4234e551ABba0f82Cb7C",
    GATEWAY_PRIVATE_KEY: `0x${"33".repeat(32)}`,
  });
  await run("npm", ["run", "db:push", "--", "--force"], process.env);
  const load = (file) => import(pathToFileURL(join(gatewayRoot, file)));
  ({ db, schema } = await load("db/index.ts"));
  ({ default: versionsHandler } = await load(
    "api/v1/data/[dataPointId]/versions.ts",
  ));
  ({ default: listingHandler } = await load("api/v1/data.ts"));
  const storage = {
    urlForKey: (key) => `${origin}/blob/${encodeURIComponent(key)}`,
    async upload(key, bytes) {
      await writeFile(blobPath(key), bytes);
      return this.urlForKey(key);
    },
    async download(url) {
      assert.equal(new URL(url).origin, origin);
      const response = await fetch(url);
      assert.equal(response.status, 200);
      return new Uint8Array(await response.arrayBuffer());
    },
    async delete() {
      return false;
    },
    async exists() {
      return true;
    },
  };
  // Confirmed SQL fixtures model retained chain-settled rows. Checkpoint writes
  // use this same test registry, not POST AddData/chain settlement authority.
  async function register(params) {
    const id = idFor(params.scope);
    const row = {
      id,
      expectedVersion: String(params.expectedVersion),
      dataHash: params.dataHash,
      metadataHash: params.metadataHash,
      signature: params.signature,
      signerAddress: account.address,
      status: "confirmed",
      addedAt: new Date(),
    };
    await db
      .insert(schema.dataPointVersions)
      .values(row)
      .onConflictDoUpdate({
        target: [
          schema.dataPointVersions.id,
          schema.dataPointVersions.expectedVersion,
        ],
        set: row,
      });
    const head = {
      ...row,
      ownerAddress: account.address,
      scope: params.scope,
      chainState: "active",
    };
    await db
      .insert(schema.dataPoints)
      .values(head)
      .onConflictDoUpdate({ target: schema.dataPoints.id, set: head });
    return { success: true };
  }
  const count = large ? 90 : 102;
  for (let version = 1; version <= count; version++) {
    const collectedAt = new Date(
      Date.UTC(2026, 9, 1, 12, 0, version),
    ).toISOString();
    const data = {
      conversations: [
        { id: "old" },
        ...(version === count ? [{ id: "new" }] : []),
      ],
    };
    if (large) data.padding = randomBytes(3 * 1024 * 1024).toString("base64");
    const envelope = createDataFileEnvelope(source, collectedAt, data);
    const plain = new TextEncoder().encode(JSON.stringify(envelope));
    const encrypted = await encryptWithPassword(plain, keyPassword(source));
    blobBytes += encrypted.byteLength;
    await storage.upload(`${source}/${version}`, encrypted);
    await register({
      scope: source,
      expectedVersion: String(version),
      dataHash: keccak256(plain),
      metadataHash: keccak256(
        stringToHex(
          JSON.stringify({
            scope: source,
            collectedAt,
            sizeBytes: encrypted.byteLength,
          }),
        ),
      ),
      signature: "local-settled-fixture",
    });
  }
  const client = createVersionInventoryClient({
    gatewayUrl: origin,
    ownerAddress: account.address,
    ownerSigner: {
      signRequest: (params) =>
        buildWeb3SignedHeader({
          ...params,
          signMessage: (message) => account.signMessage({ message }),
        }),
    },
  });
  const page = await client.page(source, { limit: 2 });
  assert.equal(page.pagination.hasMore, true);
  assert.equal(page.pagination.nextAfter, "2");
  const budgeted = createVersionInventoryClient({
    gatewayUrl: origin,
    ownerAddress: account.address,
    ownerSigner: {
      signRequest: async () => {
        throw new Error("Must use bounded signer");
      },
    },
    boundedOwnerSigner: async (params, signal) => {
      signal?.throwIfAborted();
      const proof = await buildWeb3SignedHeader({
        ...params,
        signMessage: (message) => account.signMessage({ message }),
      });
      signal?.throwIfAborted();
      return proof;
    },
  });
  await assert.rejects(
    budgeted.list(source, { budget: new AdditionsBudget(256, 1000) }),
    /budget/,
  );
  let capturedProof;
  const replay = createVersionInventoryClient({
    gatewayUrl: origin,
    ownerAddress: account.address,
    ownerSigner: {
      signRequest: async (params) =>
        (capturedProof ??= await buildWeb3SignedHeader({
          ...params,
          signMessage: (message) => account.signMessage({ message }),
        })),
    },
  });
  await replay.page(source, { limit: 2 });
  await assert.rejects(replay.page(source, { limit: 2 }), /401/);
  const denied = createVersionInventoryClient({
    gatewayUrl: origin,
    ownerAddress: account.address,
    ownerSigner: { signRequest: async () => "invalid" },
  });
  await assert.rejects(denied.list(source), /401/);
  const options = {
    ownerAddress: account.address,
    network: `local:${origin}`,
    masterKey,
    inventory: client,
    storageAdapter: storage,
    signer: { signAddData: async () => `0x${"00".repeat(65)}` },
    gateway: { registerDataPoint: register },
  };
  const query = {
    timezone: "Asia/Kathmandu",
    days: 7,
    now: new Date("2026-10-04T00:00:00Z"),
  };
  const summary = await createDurableAdditions(options).summarize(query);
  assert.equal(summary.coverage, "complete");
  assert.equal(summary.total, 2);
  assert.equal(summary.through[source], String(count));
  assert.equal(
    summary.days.reduce((sum, row) => sum + row.added, 0),
    2,
  );
  // Original ciphertext can disappear after a verified permanent checkpoint.
  for (let version = 1; version <= count; version++)
    await rm(blobPath(`${source}/${version}`));
  const restarted = await createDurableAdditions(options).summarize(query);
  assert.equal(restarted.coverage, "complete");
  assert.deepEqual(restarted.days, summary.days);
  assert.equal(restarted.total, 2);
  if (large)
    assert.ok(
      blobBytes > 256 * 1024 * 1024,
      `only ${blobBytes} ciphertext bytes`,
    );
  console.log(
    JSON.stringify({
      result: "PASS",
      gatewayHead: "d8ed3c09952a4151ab94df30aa905423eca6a29d",
      versions: count,
      ciphertextBytes: blobBytes,
      inventoryCalls,
      boundedInventoryRejected: true,
      replayRejected: true,
      coverage: summary.coverage,
      total: summary.total,
      restartAfterPruning: true,
      peakRssBytes: process.resourceUsage().maxRSS * 1024,
      limitations:
        "SQL-seeded confirmed registrations, no AddData POST/chain or production storage proof",
    }),
  );
} finally {
  await new Promise((resolve) => {
    server.closeAllConnections();
    server.close(resolve);
  });
  if (db) await db.$client.end();
  await pg.stop();
  await rm(root, { recursive: true, force: true });
}
