// Runs one fixed sequence of real operations against a tree's compiled
// packages and records a normalized JSON transcript. compare.mjs runs it
// against a baseline and a candidate tree in separate processes.
//
//   node scenario.mjs --tree <repo root> --work <empty dir> [--inject-journal-failure]
//
// The transcript is written to <work>/transcript.json.
//
// The tree must be built (`tsc --build packages/core packages/server`).
// Only the tree's own modules run: this file imports nothing by bare name.
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

const { values: args } = parseArgs({
  options: {
    tree: { type: "string" },
    work: { type: "string" },
    "inject-journal-failure": { type: "boolean", default: false },
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

// Volatility controls, identical for every tree. The clock moves only between
// operations, so timestamps depend on the sequence, not on code paths.
const RealDate = Date;
let clock = RealDate.parse("2026-10-24T00:00:00.000Z");
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
const UUID = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

const transcript = { operations: [], gateway: [], storage: [] };
const record = (name, value) => transcript.operations.push({ name, value });

const STORAGE = "https://storage.differential.invalid";
globalThis.fetch = async (input, init = {}) => {
  const url = new URL(typeof input === "string" ? input : input.url);
  const method = init.method ?? "GET";
  if (url.origin === STORAGE) {
    // Ciphertext is random; its key and length are not.
    const body = init.body ? new Uint8Array(init.body) : undefined;
    transcript.storage.push({
      method,
      path: url.pathname,
      bytes: body?.byteLength ?? 0,
    });
    return new Response("{}", { status: 200 });
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
// The registry remembers what was registered, so head checks see it.
const registered = new Map();
const responses = {
  getServer: async () => ({ id: `0x${"5e".repeat(32)}` }),
  getBuilder: async (address) => ({ id: `0x${"b1".repeat(32)}`, address }),
  isRegisteredBuilder: async () => true,
  createGrant: async () => ({ grantId: `0x${"9a".repeat(32)}` }),
  registerDataPoint: async (request) => {
    const id = `dp-${registered.size + 1}`;
    registered.set(request.scope, {
      id,
      scope: request.scope,
      ownerAddress: request.ownerAddress,
      expectedVersion: String(request.expectedVersion),
      dataHash: request.dataHash,
      metadataHash: request.metadataHash,
      addedAt: new Date().toISOString(),
      deletedAt: null,
    });
    return { dataPointId: id };
  },
  getDataPoint: async () => null,
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
  async listDataPointsByOwner(owner, cursor) {
    transcript.gateway.push({ method: "feed.list", args: json([cursor]) });
    return { dataPoints: [], cursor: null };
  },
  async getDataPoint(input) {
    transcript.gateway.push({
      method: "feed.getDataPoint",
      args: json([input.scope]),
    });
    return registered.get(input.scope) ?? null;
  },
};

process.env.VANA_MASTER_KEY_SIGNATURE =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";
const token = "differential-owner-token";
process.env.PS_ACCESS_TOKEN = token;
for (const name of ["CLOUD_MODE", "PERSONAL_SERVER_ROOT_PATH"])
  delete process.env[name];

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
const config = ServerConfigSchema.parse({
  tunnel: { enabled: false },
  payment: { enabled: false },
  pdpp: { enabled: false },
  devUi: { enabled: false },
  sync: { enabled: true },
  storage: { backend: "vana", config: { vana: { apiUrl: STORAGE } } },
});

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
  record(name, { status: response.status, body: parsed });
  return parsed;
}

const queue = (ctx) =>
  ctx.indexManager.findUnsynced().map((entry) => ({
    path: entry.path,
    producer: entry.producer,
    version: entry.version,
  }));

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
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
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
tick();
await ctx.syncManager?.trigger();
record("queue-after-sync", queue(ctx));

// Direct storage under canonical authority: producer and history-only facts.
const db = new Database(join(root, "index.db"));
db.exec(
  "INSERT OR IGNORE INTO legacy_scope_canonical_authority (scope) VALUES ('spotify.playlists')",
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
tick();
await ctx.syncManager?.trigger();
record("queue-final", queue(ctx));
await ctx.cleanup();

// Durable state. Gate tables leave the structural comparison, but their row
// counts stay: an off operation must write none of them.
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
  // Columns SQLite defaults to its own wall clock are volatile.
  const sqliteClock = new Set(
    inspect
      .prepare(`PRAGMA table_info("${name}")`)
      .all()
      .filter((column) => /strftime|CURRENT_/i.test(column.dflt_value ?? ""))
      .map((column) => column.name),
  );
  tables[name] = rows.map((row) =>
    Object.fromEntries(
      Object.entries(row).map(([column, value]) => [
        column,
        sqliteClock.has(column)
          ? "<sqlite-clock>"
          : Buffer.isBuffer(value)
            ? `<blob ${sha(value)}>`
            : value,
      ]),
    ),
  );
}
transcript.schema = {
  // Authorized change: the converged stamp. Reported, compared separately.
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
    else
      files.push({
        path: relative(root, path),
        // Receipts embed random import ids; hash the normalized text.
        sha256: sha(readFileSync(path, "latin1").replace(UUID, "<uuid>")),
      });
  }
};
walk(dataDir);
transcript.files = files;
const configJson = JSON.parse(readFileSync(join(root, "config.json"), "utf8"));
// Authorized change: the new default-off flag key in the rewritten config.
transcript.configFlag = configJson.legacyWriteShutdownEnabled ?? null;
delete configJson.legacyWriteShutdownEnabled;
transcript.config = configJson;

// Random ids: replace each UUID by its order of first appearance.
const ids = new Map();
const text = JSON.stringify(transcript, null, 2).replace(UUID, (id) => {
  if (!ids.has(id)) ids.set(id, `<uuid-${ids.size + 1}>`);
  return ids.get(id);
});
writeFileSync(join(work, "transcript.json"), `${text}\n`);
process.exit(0);
