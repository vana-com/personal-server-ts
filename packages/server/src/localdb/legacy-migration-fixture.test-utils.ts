/**
 * A real legacy store (`index.db` and `data/` files) and a real server booted
 * over it, for the legacy-migration tests. The connector is a registry one the
 * production projection catalogue binds, so nothing here is a test seam: the
 * server's own composition imports and retires the store.
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { privateKeyToAccount } from "viem/accounts";
import { vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import type { ModeRecordStore } from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import { createStreamSyncKeyPorts } from "../../../core/src/stream-sync/crypto.js";
import { createServer, type ServerContext } from "../bootstrap.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { createLegacyStoreRunner } from "./legacy-store-import.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import { openRecordStore } from "../pdpp/records-bootstrap.js";
import { remoteFixture } from "./apply-fixture.js";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type {
  LegacyWriteHold,
  LegacyWriteSeal,
} from "../../../core/src/storage/legacy-write-seal.js";

export const SOURCE_ID = "https://registry.pdpp.dev/connectors/github";
export const CONNECTOR = "github";
/** The connection a connector's identityless control scope names. */
export const CONNECTION_ID = "pdpp.github~";
export const INSTANCE = "github-account-1";

/** Nine streams, grouped as the production catalogue groups them. */
export const SCOPES: Record<string, string[]> = {
  "github.repositories": ["repositories"],
  "github.starred": ["starred"],
  "github.history": ["user", "issues", "pull_requests"],
  "github.profile": [
    "user",
    "user_stats",
    "pinned_repositories",
    "organizations",
  ],
  "github.events": ["events"],
};
export const STREAMS = [...new Set(Object.values(SCOPES).flat())].sort();

export const ORPHAN_SCOPE = "orphan.notes";
export const ROWS_PER_STREAM = 3;

export interface LegacyRow {
  id: string;
  n: number;
  text: string;
}

export const rowsOf = (stream: string, text = "legacy"): LegacyRow[] =>
  Array.from({ length: ROWS_PER_STREAM }, (_, n) => ({
    id: `${stream}-${n}`,
    n,
    text: `${text} ${stream} ${n}`,
  }));

export const signature = () =>
  privateKeyToAccount(`0x${"11".repeat(32)}`).signMessage({
    message: "Disposable Node database fixture",
  });

export async function scratch(prefix: string): Promise<string> {
  const temporary = join(homedir(), ".tmp");
  await mkdir(temporary, { recursive: true });
  return mkdtemp(join(temporary, prefix));
}

/**
 * Writes the legacy store a switched owner is migrating: records for every
 * stream through the real record store, one file per scope, and one file no
 * binding names. A key written twice keeps its earlier version.
 */
export function writeLegacyStore(
  root: string,
  streams: Record<string, LegacyRow[]> = Object.fromEntries(
    STREAMS.map((stream) => [stream, rowsOf(stream)]),
  ),
): { files: string[] } {
  mkdirSync(join(root, "data"), { recursive: true });
  const db = initializeDatabase(join(root, "index.db"));
  try {
    const store = openRecordStore(db, false);
    store.registerConnection({
      instance: INSTANCE,
      sourceId: SOURCE_ID,
      method: CONNECTOR,
      label: "GitHub",
    });
    const emitted = (n: number) =>
      new Date(Date.UTC(2026, 0, 1, 0, 0, n)).toISOString();
    for (const [stream, rows] of Object.entries(streams)) {
      store.ingestBatch(
        rows.map((row, n) => ({
          instance: INSTANCE,
          stream,
          key: row.id,
          data: { ...row, text: `earlier ${row.text}` },
          emitted_at: emitted(n),
        })),
        () => "mutable_state",
        () => ["id"],
        { method: CONNECTOR, generation: 1 },
      );
      store.ingestBatch(
        rows.map((row, n) => ({
          instance: INSTANCE,
          stream,
          key: row.id,
          data: row,
          emitted_at: emitted(100 + n),
        })),
        () => "mutable_state",
        () => ["id"],
        { method: CONNECTOR, generation: 1 },
      );
    }
    const index = createIndexManager(db);
    const files: string[] = [];
    for (const scope of [...Object.keys(SCOPES), ORPHAN_SCOPE]) {
      const path = `${scope}.json`;
      writeFileSync(
        join(root, "data", path),
        JSON.stringify({
          scope,
          collectedAt: "2026-01-01T00:00:00.000Z",
          data: { note: `the old copy of ${scope}` },
        }),
      );
      index.insert({} as LegacyWriteHold, {
        fileId: null,
        path,
        scope,
        collectedAt: "2026-01-01T00:00:00.000Z",
        sizeBytes: 100,
      });
      files.push(join(root, "data", path));
    }
    return { files };
  } finally {
    db.close();
  }
}

/** Every old data file still on disk. The server's own dot directories are not. */
export const filesLeft = (root: string): string[] =>
  existsSync(join(root, "data"))
    ? readdirSync(join(root, "data"))
        .filter((name) => !name.startsWith("."))
        .sort()
    : [];

export function localFile(root: string): string {
  const directory = join(root, "localdb");
  return join(
    directory,
    readdirSync(directory).find((name) => name.endsWith(".sqlite"))!,
  );
}

/** A view of the owner's local database, for assertions. Writable only when a
 * test stages state while the server is stopped. */
export function readLocal<T>(
  root: string,
  read: (db: Database.Database) => T,
  writable = false,
) {
  const db = new Database(localFile(root), { readonly: !writable });
  try {
    return read(db);
  } finally {
    db.close();
  }
}

/** A read-only view of the legacy `index.db`, for assertions. */
export function readIndex<T>(root: string, read: (db: Database.Database) => T) {
  const db = new Database(join(root, "index.db"), { readonly: true });
  try {
    return read(db);
  } finally {
    db.close();
  }
}

const declaredStreams = STREAMS.map((name) => ({
  name,
  fields: ["id", "n", "text"],
  required_fields: ["id"],
  primary_key: ["id"],
}));
export const DECLARATION_JSON = JSON.stringify({
  source_id: SOURCE_ID,
  source_kind: "connector",
  version: "1",
  streams: declaredStreams,
});
export const MANIFEST_JSON = JSON.stringify({
  connector_key: CONNECTOR,
  version: "1",
  streams: STREAMS.map((name) => ({
    name,
    semantics: "mutable_state",
    primary_key: ["id"],
  })),
});
export const DECLARATION_SNAPSHOT: DeclarationSnapshot = {
  source_id: SOURCE_ID,
  source_kind: "connector",
  version: "1",
  digest: "fixture",
  streams: declaredStreams,
};

export interface Declared {
  declarationPath: string;
  manifestPath: string;
  manifestSha256: string;
}

/** The verified declaration and manifest the server's seed route also reads.
 * They live outside the storage root, so they are never an old data file. */
export async function writeDeclared(dir: string): Promise<Declared> {
  await mkdir(dir, { recursive: true });
  const declarationPath = join(dir, "declaration.json");
  const manifestPath = join(dir, "manifest.json");
  await writeFile(declarationPath, DECLARATION_JSON);
  await writeFile(manifestPath, MANIFEST_JSON);
  return {
    declarationPath,
    manifestPath,
    manifestSha256: createHash("sha256").update(MANIFEST_JSON).digest("hex"),
  };
}

export interface BootOptions {
  retireLegacy?: boolean;
  replication?: boolean;
  /** Keeps the answer across a restart when the same store is passed. */
  accountModeStore?: ModeRecordStore;
  /** A data directory other than `<root>/data` turns the import off. */
  dataDir?: string;
  declared?: Declared | null;
}

/** The access token the HTTP assertions send. */
export const HEADERS = { Authorization: "Bearer node-database-fixture" };

export async function boot(
  root: string,
  declared: Declared | null,
  options: BootOptions = {},
) {
  vi.stubEnv("PS_ACCESS_TOKEN", "node-database-fixture");
  vi.stubEnv("VANA_OWNER_PRIVATE_KEY", "");
  const keys = createStreamSyncKeyPorts(await signature());
  const remote = await remoteFixture(keys, CONNECTOR);
  const config = ServerConfigSchema.parse({
    tunnel: { enabled: false },
    sync: { enabled: false },
    logging: { level: "fatal", pretty: false },
    streamSync: { retireLegacy: options.retireLegacy === true },
    replication: { enabled: options.replication === true },
    ...(declared
      ? {
          pdpp: {
            enabled: true,
            declarationPaths: [declared.declarationPath],
            methods: [
              {
                method_id: CONNECTOR,
                declaration_path: declared.declarationPath,
                manifest_path: declared.manifestPath,
                manifest_sha256: declared.manifestSha256,
              },
            ],
          },
        }
      : {}),
  });
  const context = await createServer(config, {
    rootPath: root,
    ownerSignature: await signature(),
    // Default: the file store under the root, so an answer survives a restart.
    ...(options.accountModeStore
      ? { accountModeStore: options.accountModeStore }
      : {}),
    streamSyncRegistry: remote.registry,
    streamSyncBlobs: remote.storage,
    ...(options.dataDir ? { dataDir: options.dataDir } : {}),
  });
  return { context, remote };
}

const FINISHED = [
  "legacy retirement finished",
  "legacy retirement failed; it runs again at the next import run",
  "the legacy import failed; it runs again at the next answer",
];

export interface LogLine {
  level: "info" | "warn";
  message: string;
  obj: Record<string, unknown>;
}

const listeners = new WeakMap<object, Set<(line: LogLine) => void>>();

/** One spy per logger, however many runs a test watches. */
function listen(context: ServerContext, onLine: (line: LogLine) => void) {
  let set = listeners.get(context.logger);
  if (!set) {
    const added = new Set<(line: LogLine) => void>();
    set = added;
    listeners.set(context.logger, added);
    for (const level of ["info", "warn"] as const) {
      const original = context.logger[level].bind(context.logger) as (
        ...args: unknown[]
      ) => void;
      vi.spyOn(context.logger, level).mockImplementation(((
        ...args: unknown[]
      ) => {
        original(...args);
        const message = args.find((a): a is string => typeof a === "string");
        if (!message) return;
        const first = args[0];
        const line: LogLine = {
          level,
          message,
          obj: first && typeof first === "object" ? (first as never) : {},
        };
        for (const listener of added) listener(line);
      }) as never);
    }
  }
  set.add(onLine);
  return () => set.delete(onLine);
}

/**
 * Records the server's log lines and resolves `finished` with the first one
 * that ends a legacy store run, whatever the outcome. Install it before the
 * answer or boot that starts the run.
 */
export function watchRun(context: ServerContext, timeoutMs = 60_000) {
  const lines: LogLine[] = [];
  const finished = new Promise<LogLine>((resolve, reject) => {
    let stopListening = () => {};
    const timer = setTimeout(() => {
      stopListening();
      reject(new Error("the legacy store run did not finish"));
    }, timeoutMs);
    timer.unref();
    stopListening = listen(context, (line) => {
      lines.push(line);
      if (FINISHED.includes(line.message)) {
        clearTimeout(timer);
        stopListening();
        resolve(line);
      }
    });
  });
  return { lines, finished };
}

export const lineOf = (lines: LogLine[], message: string) =>
  lines.find((line) => line.message === message)?.obj;

/** The server's records for one stream, read back through its own database. */
export async function storedRows(context: ServerContext, stream: string) {
  const sync = await context.getLocalSync!();
  const rows = [];
  let cursor: string | undefined;
  for (;;) {
    const page = await sync.query.listRecords({
      connectionId: CONNECTION_ID,
      stream,
      cursor,
      limit: 100,
    });
    for (const record of page.records)
      rows.push({ key: record.recordKey, body: JSON.parse(record.body) });
    if (!page.nextCursor) return rows;
    cursor = page.nextCursor;
  }
}

/** The Account answers On; the run it starts is watched from before it. */
export async function switchOn(context: ServerContext) {
  const run = watchRun(context);
  await context.accountModeAuthority.submitEvidence({
    owner: context.serverOwner!,
    state: "on",
  });
  return run;
}

export interface DirectOptions {
  /** What the seal answers; changes between reads when the test wants. */
  verdict?: () => "switched" | "allow";
  retireLegacy?: boolean;
  /** No verified declaration, method or manifest: the seam is missing. */
  undeclared?: boolean;
  /** Replaces the server's one open database for the owner. */
  getDeps?: (deps: LocalSyncDeps) => Promise<LocalSyncDeps>;
  /** Replaces the borrowed `index.db` handle. */
  index?: Database.Database;
  /** The registry does not answer. */
  registryDown?: boolean;
  /** Sees each log message as the runner writes it. */
  onLog?: (message: string) => void;
}

/**
 * The runner over a real legacy store and a real local database, with every
 * input the server gives it spelled out, so a test can take one away.
 */
export async function direct(
  base: string,
  root: string,
  options: DirectOptions = {},
) {
  const owner = "0xabc";
  const network = "test";
  const index = options.index ?? initializeDatabase(join(root, "index.db"));
  const local = await openLocalDb(
    openBetterSqlite3(join(base, "local.sqlite")),
    {
      owner,
      network,
      deviceId: "device",
    },
  );
  const remote = await remoteFixture(
    createStreamSyncKeyPorts(await signature()),
    CONNECTOR,
  );
  const unexpected = async (): Promise<never> => {
    throw new Error("unexpected external call");
  };
  const lines: LogLine[] = [];
  let op = 0;
  const deps: LocalSyncDeps = {
    db: local,
    queue: connectionQueue(),
    ownerAddress: owner,
    registry: options.registryDown
      ? { ...remote.registry, read: unexpected }
      : remote.registry,
    blobs: remote.storage,
    keys: createStreamSyncKeyPorts(await signature()),
    signer: { signAddData: unexpected },
    logger: {
      info: (obj, message) => {
        lines.push({
          level: "info",
          message: String(message),
          obj: obj as never,
        });
        options.onLog?.(String(message));
      },
      warn: (obj, message) => {
        lines.push({
          level: "warn",
          message: String(message),
          obj: obj as never,
        });
        options.onLog?.(String(message));
      },
    },
    now: () => 1,
    newOp: () => `op-${++op}`,
  };
  const verdict = options.verdict ?? (() => "switched" as const);
  const seal: LegacyWriteSeal = {
    commit: async () => {
      throw new Error("unexpected legacy write");
    },
    remove: async (work) => work(),
    admit: () => null,
    verdict,
  };
  const runner = createLegacyStoreRunner({
    db: index,
    root,
    owner,
    network,
    legacyWriteSeal: seal,
    getDeps: () =>
      options.getDeps ? options.getDeps(deps) : Promise.resolve(deps),
    declarations: () => (options.undeclared ? [] : [DECLARATION_SNAPSHOT]),
    methods: () =>
      options.undeclared ? [] : [{ sourceId: SOURCE_ID, methodId: CONNECTOR }],
    manifests: () => (options.undeclared ? [] : [MANIFEST_JSON]),
    streamSync: () => ({ retireLegacy: options.retireLegacy === true }),
    logger: deps.logger,
  });
  return {
    runner,
    lines,
    local,
    run: (signal: AbortSignal = new AbortController().signal) =>
      runner.run(signal),
    records: (stream: string) =>
      local.query<{ record_key: string }>(
        "SELECT record_key FROM records WHERE connection_id = ? AND stream = ? ORDER BY record_key",
        [CONNECTION_ID, stream],
      ),
    receipts: () =>
      local.query<{ state: string }>("SELECT state FROM import_ledger"),
    async close() {
      await local.close();
      if (!options.index && index.open) index.close();
    },
  };
}
