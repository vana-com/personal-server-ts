// Runs one fixed sequence of real operations against a tree's compiled
// packages and writes a RAW capture. compare.mjs normalizes the capture
// (normalize.mjs) and runs it against a baseline and a candidate tree in
// separate processes.
//
//   node scenario.mjs --tree <repo root> --work <empty dir> [--inject-journal-failure]
//
// Output, in <work>: raw-transcript.json, the capture; nothing here normalizes
// it. The tree must be built (`tsc --build packages/core packages/server`).
// Only the tree's own modules run: bare imports resolve from the tree.
//
// The fake world is a faithful, in-memory counterpart of the remote services:
//   - storage keeps every uploaded ciphertext, serves it back, and 404s the
//     rest. Each upload is decrypted at capture time with the tree's own
//     derived scope key, so payload and metadata identity are compared, not
//     ciphertext (random) or length alone.
//   - the registry remembers every registration and lists every data point,
//     including a REMOTE point this scenario seeds, so downloads, replica
//     commits and missing-file repair run through the real download worker.
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { join, relative } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { treeIdentity } from "./tree-identity.mjs";

const { values: args } = parseArgs({
  options: {
    tree: { type: "string" },
    work: { type: "string" },
    "inject-journal-failure": { type: "boolean", default: false },
    // Harness self-tests only: simulate a regression that rewrites an existing
    // timestamp, so compare.mjs can prove the preservation guards detect it.
    "self-test": { type: "string" },
  },
});
if (!args.tree || !args.work) {
  console.error(
    "usage: scenario.mjs --tree <repo> --work <dir> [--inject-journal-failure]",
  );
  process.exit(2);
}
const tree = args.tree;
const work = args.work;
const load = (path) => import(pathToFileURL(join(tree, path)).href);
const requireFromTree = createRequire(join(tree, "package.json"));
const Database = requireFromTree("better-sqlite3");
const sdk = requireFromTree("@opendatalabs/vana-sdk/node");
const { keccak256, stringToHex } = requireFromTree("viem");

// Volatility controls, identical for every tree. The clock moves only between
// operations, so timestamps depend on the sequence, not on code paths. Its
// base is far from any real date, so a wall-clock value (SQLite's own
// defaults) can never be mistaken for a scenario-clock value.
const RealDate = Date;
const wallStart = RealDate.now();
const CLOCK_BASE = "2031-01-01T00:00:00.000Z";
let clock = RealDate.parse(CLOCK_BASE);
globalThis.Date = class extends RealDate {
  constructor(...input) {
    if (input.length === 0) super(clock);
    else super(...input);
  }
  static now() {
    return clock;
  }
};
const tick = () => (clock += 1000);
const clockIso = () => new Date(clock).toISOString();

const transcript = { operations: [], gateway: [], storage: [] };
const record = (name, value) => transcript.operations.push({ name, value });
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");

process.env.VANA_MASTER_KEY_SIGNATURE =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";
const token = "differential-owner-token";
process.env.PS_ACCESS_TOKEN = token;
for (const name of ["CLOUD_MODE", "PERSONAL_SERVER_ROOT_PATH"])
  delete process.env[name];

const masterKey = sdk.deriveMasterKey(process.env.VANA_MASTER_KEY_SIGNATURE);
const serverOwner = await sdk.recoverServerOwner(
  process.env.VANA_MASTER_KEY_SIGNATURE,
);
const scopeKeyHex = (scope) =>
  Array.from(sdk.deriveScopeKey(masterKey, scope), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
const scopeKeys = new Map();
const noteScopeKey = (scope) => {
  const key = scopeKeyHex(scope);
  scopeKeys.set(scope, sha(key));
  return key;
};

const { createServer } = await load("packages/server/dist/bootstrap.js");
const { initializeDatabase } = await load(
  "packages/server/dist/storage/index-schema.js",
);
const { createNodeDataStorage } = await load(
  "packages/server/dist/storage/node-data-storage.js",
);
const { ServerConfigSchema } = await load(
  "packages/core/dist/schemas/server-config.js",
);
const { buildDataFilePath } = await load(
  "packages/core/dist/storage/hierarchy/index.js",
);
const { computeDataPointId } = await load(
  "packages/core/dist/sync/data-point-id.js",
);

const STORAGE = "https://storage.differential.invalid";
const config = ServerConfigSchema.parse({
  tunnel: { enabled: false },
  payment: { enabled: false },
  pdpp: { enabled: false },
  devUi: { enabled: false },
  sync: { enabled: true },
  storage: { backend: "vana", config: { vana: { apiUrl: STORAGE } } },
});
const blobPath = (scope, version) =>
  `/v1/chains/${config.gateway.chainId}/blobs/${serverOwner.toLowerCase()}/${scope}/${version}`;

// --- storage: a real blob store, decrypting every upload for the capture ---
const blobs = new Map();
const commitmentChecks = [];
async function describeCiphertext(path, bytes) {
  const [, , , , , , rawScope, version] = path.split("/");
  const scope = decodeURIComponent(rawScope);
  try {
    const clear = await sdk.decryptWithPassword(bytes, noteScopeKey(scope));
    const envelope = JSON.parse(new TextDecoder().decode(clear));
    commitmentChecks.push({
      scope,
      version,
      dataHash: keccak256(clear),
      metadataHash: keccak256(
        stringToHex(
          JSON.stringify({
            scope,
            collectedAt: envelope.collectedAt,
            sizeBytes: bytes.byteLength,
          }),
        ),
      ),
    });
    return { plaintextSha256: sha(clear), envelope };
  } catch (error) {
    return { decryptError: error.message };
  }
}
globalThis.fetch = async (input, init = {}) => {
  const url = new URL(typeof input === "string" ? input : input.url);
  const method = init.method ?? "GET";
  if (url.origin === STORAGE) {
    const headers = new Headers(init.headers);
    const entry = {
      method,
      path: url.pathname,
      // Scheme only: the signature embeds a clock and a nonce.
      authorization: headers.get("authorization")?.split(" ")[0] ?? null,
      contentType: headers.get("content-type"),
    };
    transcript.storage.push(entry);
    if (method === "PUT") {
      const body = new Uint8Array(init.body);
      entry.cipherBytes = body.byteLength;
      entry.overwrote = blobs.has(url.pathname);
      blobs.set(url.pathname, body);
      Object.assign(entry, await describeCiphertext(url.pathname, body));
      return Response.json({
        url: url.href,
        size: body.byteLength,
        key: url.pathname,
        etag: "differential",
      });
    }
    if (method === "DELETE") {
      entry.existed = blobs.delete(url.pathname);
      return Response.json({});
    }
    const body = blobs.get(url.pathname);
    entry.status = body ? 200 : 404;
    if (body) entry.cipherBytes = body.byteLength;
    return body
      ? new Response(body.slice())
      : new Response("not found", { status: 404 });
  }
  transcript.storage.push({ method, unexpected: url.href });
  return new Response("not available", { status: 404 });
};

const json = (value) =>
  JSON.parse(
    JSON.stringify(value, (_key, item) =>
      typeof item === "bigint" ? `${item}n` : item,
    ),
  );

// --- gateway registry: remembers registrations, lists everything ---
const registry = new Map();
const registryRecord = (request) => ({
  id: computeDataPointId(request.ownerAddress, request.scope),
  scope: request.scope,
  ownerAddress: request.ownerAddress,
  expectedVersion: String(request.expectedVersion),
  dataHash: request.dataHash,
  metadataHash: request.metadataHash,
  addedAt: new Date().toISOString(),
  deletedAt: null,
});
const responses = {
  getServer: async () => ({ id: `0x${"5e".repeat(32)}` }),
  getBuilder: async (address) => ({ id: `0x${"b1".repeat(32)}`, address }),
  isRegisteredBuilder: async () => true,
  createGrant: async () => ({ grantId: `0x${"9a".repeat(32)}` }),
  registerDataPoint: async (request) => {
    const row = registryRecord(request);
    registry.set(request.scope, row);
    return { dataPointId: row.id };
  },
  getDataPoint: async (id) =>
    [...registry.values()].find((row) => row.id === id) ?? null,
};
const gatewayClient = new Proxy(
  {},
  {
    get(_target, property) {
      if (property === "then") return undefined;
      return async (...input) => {
        transcript.gateway.push({
          method: String(property),
          args: json(input),
        });
        return (responses[property] ?? (async () => null))(...input);
      };
    },
  },
);
const dataPointFeed = {
  async listDataPointsByOwner(_owner, cursor) {
    transcript.gateway.push({ method: "feed.list", args: json([cursor]) });
    return { dataPoints: [...registry.values()], cursor: null };
  },
  async getDataPoint(input) {
    transcript.gateway.push({
      method: "feed.getDataPoint",
      args: json([input.scope]),
    });
    return registry.get(input.scope) ?? null;
  },
};

const root = join(work, "root");
const dataDir = join(root, "data");
mkdirSync(root, { recursive: true });
// A fixed server key (a test key, not a secret) so signatures compare.
writeFileSync(
  join(root, "key.json"),
  JSON.stringify({
    address: "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
    publicKey:
      "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
    privateKey:
      "0x0000000000000000000000000000000000000000000000000000000000000001",
  }),
);

// Every run opens the root once first, so the injected run differs only by
// its triggers. The off journal must be irrelevant: a failing one cannot
// affect any operation.
{
  const db = initializeDatabase(join(root, "index.db"));
  const tables = args["inject-journal-failure"]
    ? ["legacy_publication_issuance", "legacy_publication_holds"]
    : [];
  for (const table of tables)
    if (
      db
        .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?")
        .get(table)
    )
      db.exec(
        `CREATE TRIGGER differential_${table}_failure BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT, 'injected journal failure'); END`,
      );
  db.close();
}

async function boot() {
  const ctx = await createServer(config, {
    rootPath: root,
    gatewayClient,
    dataPointFeed,
  });
  // No background cycle: the scenario triggers each one.
  await ctx.syncManager?.stop();
  return ctx;
}
async function restart(ctx) {
  await ctx.cleanup();
  return boot();
}

async function http(ctx, name, method, path, body, headers = {}) {
  tick();
  const response = await ctx.app.request(`http://localhost${path}`, {
    method,
    body,
    headers: { authorization: `Bearer ${token}`, ...headers },
  });
  const text = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = text;
  }
  record(name, {
    status: response.status,
    headers: Object.fromEntries([...response.headers].sort()),
    body: parsed,
  });
  return parsed;
}

async function sync(ctx, name) {
  tick();
  await ctx.syncManager?.trigger();
  const status = ctx.syncManager?.getStatus();
  record(name, {
    errors: (status?.errors ?? []).map((error) => error.message),
    blocked: status?.blocked ?? null,
    pendingFiles: status?.pendingFiles ?? null,
  });
}

const queue = (ctx) =>
  ctx.indexManager.findUnsynced().map((entry) => ({
    path: entry.path,
    producer: entry.producer,
    version: entry.version,
  }));
const identityOf = (entry) =>
  entry
    ? {
        id: entry.id,
        path: entry.path,
        scope: entry.scope,
        collectedAt: entry.collectedAt,
        sizeBytes: entry.sizeBytes,
        version: entry.version,
        dataPointId: entry.dataPointId,
        producer: entry.producer ?? null,
      }
    : null;
const bytesOf = (path) => (existsSync(path) ? readFileSync(path) : null);

// Existing rows must keep their SQLite-defaulted `created_at`, and existing
// receipts their bytes. Both are wall-clock volatile, so only equality across
// a phase is recorded, never the values. `created_at` has one-second
// resolution: the guard waits past a second boundary first, so a rewrite
// cannot hide in the same second.
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function createdAtRows() {
  const reader = new Database(join(root, "index.db"), { readonly: true });
  try {
    return new Map(
      reader
        .prepare("SELECT id, created_at FROM data_files")
        .all()
        .map((row) => [row.id, row.created_at]),
    );
  } finally {
    reader.close();
  }
}
function receiptFiles() {
  const dir = join(dataDir, ".scope-imports", "receipts");
  return new Map(
    existsSync(dir)
      ? readdirSync(dir).map((name) => [
          name,
          readFileSync(join(dir, name), "utf8"),
        ])
      : [],
  );
}
async function startPreservationGuard() {
  const guard = { rows: createdAtRows(), receipts: receiptFiles() };
  await sleep(1100);
  return guard;
}
function endPreservationGuard(name, guard) {
  const rows = createdAtRows();
  const receipts = receiptFiles();
  record(name, {
    rowsChecked: guard.rows.size,
    createdAtRemoved: [...guard.rows.keys()].filter((id) => !rows.has(id)),
    createdAtRewritten: [...guard.rows]
      .filter(([id, value]) => rows.has(id) && rows.get(id) !== value)
      .map(([id]) => id),
    receiptsChecked: guard.receipts.size,
    receiptsRemoved: [...guard.receipts.keys()].filter(
      (file) => !receipts.has(file),
    ).length,
    receiptsRewritten: [...guard.receipts].filter(
      ([file, text]) => receipts.has(file) && receipts.get(file) !== text,
    ).length,
  });
}

let ctx = await boot();
record("boot", {
  syncManager: !!ctx.syncManager,
  signer: !!ctx.serverSigner,
});

// HTTP JSON, binary and chunked writes.
await http(
  ctx,
  "ingest-json",
  "POST",
  "/v1/data/spotify.profile",
  JSON.stringify({ profile: { name: "json" } }),
  { "content-type": "application/json" },
);
await http(
  ctx,
  "ingest-binary",
  "POST",
  "/v1/data/files.document",
  new Uint8Array([0, 1, 2, 3, 250]),
  { "content-type": "application/octet-stream", "x-filename": "a.bin" },
);
const chunk = Buffer.from('{"conversations":[{"id":"c1"}]}');
const begin = await http(
  ctx,
  "chunk-begin",
  "POST",
  "/v1/data/chatgpt.conversations/imports",
  JSON.stringify({
    totalBytes: chunk.byteLength,
    totalChunks: 1,
    sha256: sha(chunk),
  }),
  { "content-type": "application/json" },
);
await http(
  ctx,
  "chunk-upload",
  "PUT",
  `/v1/data/chatgpt.conversations/imports/${begin.importId}/chunks/0`,
  chunk,
  { "content-type": "application/octet-stream", "x-chunk-sha256": sha(chunk) },
);
await http(
  ctx,
  "chunk-finalize",
  "POST",
  `/v1/data/chatgpt.conversations/imports/${begin.importId}/finalize`,
);
// A durable owner import uses the prepare/publish journal.
await http(
  ctx,
  "owner-import",
  "PUT",
  `/v1/data/spotify.history/imports/${"0a".repeat(32)}`,
  JSON.stringify({ plays: [1, 2] }),
  { "content-type": "application/json" },
);
// Local grant signing and registration.
await http(
  ctx,
  "grant",
  "POST",
  "/v1/grants",
  JSON.stringify({
    granteeAddress: "0x00000000000000000000000000000000000000b1",
    scopes: ["spotify.profile"],
  }),
  { "content-type": "application/json" },
);
await http(
  ctx,
  "policy-api",
  "GET",
  "/v1/legacy-publication-policy/spotify.profile",
);
record("queue-before-sync", queue(ctx));
await sync(ctx, "sync-outbound");
record("queue-after-sync", queue(ctx));

// --- Incoming replica sync and missing-file repair, through the real
// download worker, registry feed and storage. A REMOTE writer registered a
// data point this server never had: valid owner, scope, version key and
// commitments over the real ciphertext.
const REMOTE_SCOPE = "spotify.library";
const remoteData = { tracks: [{ id: "t1" }, { id: "t2" }] };
const remoteCollectedAt = new Date(clock - 5000).toISOString();
const remoteEnvelope = {
  version: "1.0",
  scope: REMOTE_SCOPE,
  collectedAt: remoteCollectedAt,
  data: remoteData,
};
/** Register the remote envelope as `version`: a fresh ciphertext at its key. */
async function publishRemote(version) {
  const plaintext = new TextEncoder().encode(JSON.stringify(remoteEnvelope));
  const ciphertext = await sdk.encryptWithPassword(
    plaintext,
    noteScopeKey(REMOTE_SCOPE),
  );
  blobs.set(blobPath(REMOTE_SCOPE, version), ciphertext);
  registry.set(REMOTE_SCOPE, {
    id: computeDataPointId(serverOwner, REMOTE_SCOPE),
    scope: REMOTE_SCOPE,
    ownerAddress: serverOwner,
    expectedVersion: String(version),
    dataHash: keccak256(plaintext),
    metadataHash: keccak256(
      stringToHex(
        JSON.stringify({
          scope: REMOTE_SCOPE,
          collectedAt: remoteCollectedAt,
          sizeBytes: ciphertext.byteLength,
        }),
      ),
    ),
    addedAt: remoteCollectedAt,
    deletedAt: null,
  });
}
await publishRemote(1);
const remoteGets = (version) =>
  transcript.storage.filter(
    (entry) =>
      entry.method === "GET" && entry.path === blobPath(REMOTE_SCOPE, version),
  ).length;
const remoteFile = (entry) => (entry ? join(dataDir, entry.path) : null);
await sync(ctx, "sync-replica-ingest");
const ingested = ctx.indexManager.findLatestByScope(REMOTE_SCOPE);
const ingestedBytes = bytesOf(remoteFile(ingested));
record("replica-ingest", {
  entry: identityOf(ingested),
  file: ingestedBytes && JSON.parse(ingestedBytes.toString("utf8")),
  storageGets: remoteGets(1),
  expectedDataPointId: computeDataPointId(serverOwner, REMOTE_SCOPE),
  queued: queue(ctx).some((entry) => entry.path === ingested?.path),
});
// The data file and its block sidecars are lost; the index row stays. A
// replica at the SAME registered version is not re-fetched: this records
// that characterization, so a candidate cannot change it silently.
const repairGuard = await startPreservationGuard();
await ctx.cleanup();
const blocksDir = join(
  dataDir,
  "blocks",
  ...REMOTE_SCOPE.split("."),
  ingested.collectedAt,
);
const lostBlocks = existsSync(blocksDir);
rmSync(remoteFile(ingested));
rmSync(blocksDir, { recursive: true, force: true });
ctx = await boot();
await sync(ctx, "sync-replica-same-version");
record("replica-same-version-loss", {
  lostBlocks,
  fileStillMissing: !existsSync(remoteFile(ingested)),
  entry: identityOf(ctx.indexManager.findLatestByScope(REMOTE_SCOPE)),
  storageGets: remoteGets(1),
});
// Repair: a remote writer re-registers the same envelope at version 2. The
// older local version no longer hides it, the replica commit rewrites the
// lost file, and the index row adopts the registered version.
await publishRemote(2);
await sync(ctx, "sync-replica-repair");
if (args["self-test"] === "rewrite-created-at") {
  const writer = new Database(join(root, "index.db"));
  writer
    .prepare(
      "UPDATE data_files SET created_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now') WHERE scope = ?",
    )
    .run(REMOTE_SCOPE);
  writer.close();
}
const repaired = ctx.indexManager.findLatestByScope(REMOTE_SCOPE);
const repairedBytes = bytesOf(remoteFile(repaired));
record("replica-repair", {
  lostBlocks,
  restoredFile: repairedBytes !== null,
  bytesUnchanged: repairedBytes !== null && ingestedBytes.equals(repairedBytes),
  restoredBlocks: existsSync(blocksDir),
  indexIdentityUnchanged:
    JSON.stringify({ ...identityOf(repaired), version: 0 }) ===
    JSON.stringify({ ...identityOf(ingested), version: 0 }),
  adoptedVersion: repaired?.version ?? null,
  entryCount: ctx.indexManager.findByScope({ scope: REMOTE_SCOPE }).length,
  storageGets: remoteGets(2),
  entry: identityOf(repaired),
  file: repairedBytes && JSON.parse(repairedBytes.toString("utf8")),
});
endPreservationGuard("preservation-replica-repair", repairGuard);

// --- Interrupted chunked import: restart before the chunk, after it, and
// after a finalize that failed in the index transaction; then complete, and
// replay the finalize over HTTP. One operation, one receipt, one version.
const RESTART_SCOPE = "notes.restart";
const payload = Buffer.from(
  `{"notes":[${Array.from({ length: 40 }, (_, i) => `{"n":${i}}`).join(",")}]}`,
);
const importsBase = `/v1/data/${RESTART_SCOPE}/imports`;
const versionsOfScope = () => ({
  entries: ctx.indexManager
    .findByScope({ scope: RESTART_SCOPE })
    .map(identityOf),
  files: existsSync(join(dataDir, "notes"))
    ? readdirSync(join(dataDir, "notes", "restart")).sort()
    : [],
});
const restartGuard = await startPreservationGuard();
const restartBegin = await http(
  ctx,
  "restart-begin",
  "POST",
  importsBase,
  JSON.stringify({
    totalBytes: payload.byteLength,
    totalChunks: 1,
    sha256: sha(payload),
  }),
  { "content-type": "application/json" },
);
ctx = await restart(ctx);
const chunkHeaders = {
  "content-type": "application/octet-stream",
  "x-chunk-sha256": sha(payload),
};
const chunkPath = `${importsBase}/${restartBegin.importId}/chunks/0`;
await http(ctx, "restart-chunk", "PUT", chunkPath, payload, chunkHeaders);
await http(
  ctx,
  "restart-chunk-replay",
  "PUT",
  chunkPath,
  payload,
  chunkHeaders,
);
ctx = await restart(ctx);
{
  // The index transaction of the first finalize fails, as after a crash
  // between staging and indexing. The import stays resumable.
  const db = new Database(join(root, "index.db"));
  db.exec(
    `CREATE TRIGGER differential_finalize_failure BEFORE INSERT ON data_files WHEN NEW.scope = '${RESTART_SCOPE}' BEGIN SELECT RAISE(ABORT, 'injected finalize failure'); END`,
  );
  db.close();
}
const finalizePath = `${importsBase}/${restartBegin.importId}/finalize`;
await http(ctx, "restart-finalize-failed", "POST", finalizePath);
record("restart-after-failed-finalize", versionsOfScope());
ctx = await restart(ctx);
{
  const db = new Database(join(root, "index.db"));
  db.exec("DROP TRIGGER differential_finalize_failure");
  db.close();
}
await http(ctx, "restart-finalize", "POST", finalizePath);
// From here the finalized version's row and the receipt must not be rewritten
// by replays, restarts or the sync that publishes it.
const finalizedGuard = await startPreservationGuard();
await http(ctx, "restart-finalize-replay", "POST", finalizePath);
ctx = await restart(ctx);
await http(ctx, "restart-finalize-replay-after-restart", "POST", finalizePath);
if (args["self-test"] === "rewrite-receipt") {
  const dir = join(dataDir, ".scope-imports", "receipts");
  for (const name of readdirSync(dir)) {
    const file = join(dir, name);
    const text = readFileSync(file, "utf8");
    if (text.includes(RESTART_SCOPE))
      writeFileSync(
        file,
        text.replace('"completedAt":"2031', '"completedAt":"2032'),
      );
  }
}
record("restart-versions", versionsOfScope());
await sync(ctx, "sync-after-restart-import");
endPreservationGuard("preservation-restart-import", restartGuard);
endPreservationGuard("preservation-finalized-import", finalizedGuard);

// Direct storage under canonical authority: producer and history-only facts.
const recoveryGuard = await startPreservationGuard();
const db = new Database(join(root, "index.db"));
db.exec(
  "INSERT OR IGNORE INTO legacy_scope_canonical_authority (scope) VALUES ('spotify.playlists')",
);
// An explicit timestamp in a column SQLite would otherwise fill with its own
// clock must come through untouched.
db.exec(
  "INSERT OR IGNORE INTO legacy_scope_canonical_authority (scope, established_at) VALUES ('notes.explicit-clock', '2030-12-31T23:59:59.000Z')",
);
const storage = createNodeDataStorage({
  indexManager: ctx.indexManager,
  hierarchyOptions: { dataDir },
});
for (const [index, producer] of [
  [1, "pdpp-projector"],
  [2, undefined],
]) {
  tick();
  const envelope = {
    version: "1.0",
    scope: "spotify.playlists",
    collectedAt: new Date().toISOString(),
    data: { playlist: index },
    ...(producer ? { producer } : {}),
  };
  const result = await storage.commitVersion({
    kind: "append",
    envelope,
    metadata: {},
  });
  record(`direct-append-${index}`, {
    kind: result.kind,
    producer: result.entry?.producer ?? null,
  });
}
// A crash after prepare: boot recovery publishes the journaled bytes.
tick();
const preparedAt = new Date().toISOString();
const preparedEnvelope = {
  version: "1.0",
  scope: "spotify.playlists",
  collectedAt: preparedAt,
  data: { playlist: "prepared" },
  producer: "pdpp-projector",
};
db.prepare(
  `INSERT INTO owner_import_operations (authority, owner, scope, operation, body_sha256, state, collected_at, path, envelope_bytes, metadata_json)
  VALUES ('differential', '0xowner', 'spotify.playlists', 'prepared-op', ?, 'prepared', ?, ?, ?, '{}')`,
).run(
  sha(JSON.stringify(preparedEnvelope.data)),
  preparedAt,
  relative(
    dataDir,
    buildDataFilePath(dataDir, preparedEnvelope.scope, preparedAt),
  ),
  Buffer.from(JSON.stringify(preparedEnvelope, null, 2)),
);
db.close();
await ctx.cleanup();

// Restart: boot recovery (prepared journal, then a stage for a lost file).
ctx = await boot();
const playlists = ctx.indexManager.findByScope({ scope: "spotify.playlists" });
record(
  "recovered-playlists",
  playlists.map((entry) => ({
    path: entry.path,
    producer: entry.producer,
    historyOnly: ctx.indexManager.isHistoryOnly(entry.scope, entry.path),
  })),
);
record("queue-after-recovery", queue(ctx));
const lost = ctx.indexManager.findLatestByScope("spotify.profile");
await ctx.cleanup();
const lostFile = join(dataDir, lost.path);
const original = JSON.parse(readFileSync(lostFile, "utf8"));
rmSync(lostFile);
writeFileSync(
  `${lostFile}.pending.differential`,
  JSON.stringify({ ...original, data: { replaced: true } }, null, 2),
);
ctx = await boot();
record("stage-recovery", {
  finalExists: existsSync(lostFile),
  finalData: existsSync(lostFile)
    ? JSON.parse(readFileSync(lostFile, "utf8")).data
    : null,
  stageExists: existsSync(`${lostFile}.pending.differential`),
});
await sync(ctx, "sync-final");
endPreservationGuard("preservation-recovery", recoveryGuard);
record("queue-final", queue(ctx));
await ctx.cleanup();

// Durable state, captured RAW. normalize.mjs decides what is volatile; this
// file only records which columns SQLite defaults to its own wall clock.
const inspect = new Database(join(root, "index.db"), { readonly: true });
const objects = inspect
  .prepare(
    "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
  )
  .all();
const gate = (name) =>
  /^(idx_)?legacy_publication_/.test(name) || name.startsWith("differential_");
const tables = {};
const gateRows = {};
for (const { type, name } of objects) {
  if (type !== "table") continue;
  const rows = inspect.prepare(`SELECT * FROM "${name}" ORDER BY rowid`).all();
  if (gate(name)) {
    gateRows[name] = rows.length;
    continue;
  }
  tables[name] = {
    sqliteClockColumns: inspect
      .prepare(`PRAGMA table_info("${name}")`)
      .all()
      .filter((column) => /strftime|CURRENT_/i.test(column.dflt_value ?? ""))
      .map((column) => column.name),
    rows: rows.map((row) =>
      Object.fromEntries(
        Object.entries(row).map(([column, value]) => [
          column,
          // Latin-1 round-trips every byte, so the normalizer can map ids
          // inside the blob before it hashes.
          Buffer.isBuffer(value) ? { $blob: value.toString("latin1") } : value,
        ]),
      ),
    ),
  };
}
transcript.schema = {
  userVersion: inspect.pragma("user_version", { simple: true }),
  objects: objects.filter((object) => !gate(object.name)),
};
transcript.gateRows = gateRows;
transcript.tables = tables;
inspect.close();

const files = [];
const walk = (dir) => {
  for (const name of readdirSync(dir).sort()) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path);
    else {
      const bytes = readFileSync(path);
      files.push({
        path: relative(root, path),
        size: bytes.byteLength,
        text: bytes.toString("latin1"),
      });
    }
  }
};
walk(dataDir);
transcript.files = files;
transcript.config = JSON.parse(readFileSync(join(root, "config.json"), "utf8"));
transcript.commitments = commitmentChecks.map((check) => {
  const registrations = transcript.gateway.filter(
    (call) =>
      call.method === "registerDataPoint" &&
      call.args[0].scope === check.scope &&
      String(call.args[0].expectedVersion).replace(/n$/, "") === check.version,
  );
  return {
    scope: check.scope,
    version: check.version,
    registrations: registrations.length,
    dataHashMatches: registrations.every(
      (call) =>
        call.args[0].dataHash.toLowerCase() === check.dataHash.toLowerCase(),
    ),
    metadataHashMatches: registrations.every(
      (call) =>
        call.args[0].metadataHash.toLowerCase() ===
        check.metadataHash.toLowerCase(),
    ),
  };
});
transcript.scopeKeyFingerprints = Object.fromEntries(
  [...scopeKeys].sort(([a], [b]) => a.localeCompare(b)),
);
transcript.meta = {
  wallStartMs: wallStart,
  wallEndMs: RealDate.now(),
  clockBase: CLOCK_BASE,
  tree: treeIdentity(tree),
};
writeFileSync(
  join(work, "raw-transcript.json"),
  `${JSON.stringify(transcript, null, 2)}\n`,
);
process.exit(0);
