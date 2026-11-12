import { join } from "node:path";
import { createReadStream } from "node:fs";
import { monitorEventLoopDelay } from "node:perf_hooks";
import { Worker } from "node:worker_threads";
import {
  openLocalDb,
  type LocalDbIdentity,
} from "../../../core/src/localdb/open.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import {
  createImportLedger,
  createLegacyEraseLedger,
} from "../../../core/src/localdb/import-ledger.js";
import { importLegacySource } from "../../../core/src/localdb/legacy-import.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type {
  ImportSource,
  ImportTarget,
} from "../../../core/src/localdb/legacy-import-types.js";
import { initializeDatabase } from "../storage/index-schema.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { openLegacyAccess } from "./legacy-access.js";
import {
  stageLegacyImportUpload,
  acceptLegacyImportUpload,
} from "./import-upload.js";

export interface ImportMemoryFixture {
  root: string;
  rows: number;
  uploadPath: string;
  revision: string;
  bytes: number;
  payloadBytes: number;
  identity: LocalDbIdentity & { owner: `0x${string}` };
  target: ImportTarget;
  sourceId: string;
}

export interface ImportMemoryResult {
  kind: string;
  rows: number;
  receiptRows: number;
  payloadBytes: number;
  retainedRows: number;
  retainedPayloadBytes: number;
  memory: Record<string, NodeJS.MemoryUsage>;
  rssSnapshots: Record<string, NodeJS.MemoryUsage>;
  /** Driver calls the import made; only filled by an attribution run. */
  traffic?: DriverTraffic;
  sqliteVersion: string;
}

/** What crossed the driver boundary, in calls and bytes (attribution only). */
export interface DriverTraffic {
  queries: number;
  batches: number;
  statements: number;
  sqlBytes: number;
  paramBytes: number;
  /** Messages posted to the SQLite worker and the SQL text they carried. */
  wireMessages: number;
  wireSqlBytes: number;
  /** Longest event-loop stall during the import, in milliseconds. */
  maxLoopStallMs?: number;
}

// LOAD_WHOLE negative control: actual source objects stay reachable through
// receipt verification and the oracle's final HWM read, including forced GCs.
const retained: Record<string, unknown>[] = [];

/** Called only by the existing fresh-child oracle, after module warm-up. */
export async function importMemoryWorkload(input: {
  fixture: ImportMemoryFixture;
  path: "node" | "upload";
  loadWhole: boolean;
  /** Fresh mutable workspace; immutable source fixtures are shared. */
  workRoot?: string;
  /** Optional attribution run; acceptance runs leave sampling off. */
  diagnostics?: boolean;
}): Promise<ImportMemoryResult> {
  const { identity, target } = input.fixture;
  const workRoot = input.workRoot ?? input.fixture.root;
  const memory: Record<string, NodeJS.MemoryUsage> = {
    start: process.memoryUsage(),
  };
  const rssSnapshots: Record<string, NodeJS.MemoryUsage> = {};
  const observe = (phase: string) => {
    if (!input.diagnostics) return;
    const sample = process.memoryUsage();
    if (sample.rss > (rssSnapshots[phase]?.rss ?? 0))
      rssSnapshots[phase] = sample;
  };
  let phase = "setup";
  let batches = 0;
  const traffic: DriverTraffic = {
    queries: 0,
    batches: 0,
    statements: 0,
    sqlBytes: 0,
    paramBytes: 0,
    wireMessages: 0,
    wireSqlBytes: 0,
  };
  const loop = monitorEventLoopDelay({ resolution: 10 });
  if (input.diagnostics) {
    loop.enable();
    const post = Worker.prototype.postMessage;
    Worker.prototype.postMessage = function (
      this: Worker,
      message: {
        sql?: string;
        statements?: readonly { sql?: string }[];
      },
      ...rest: []
    ) {
      traffic.wireMessages++;
      traffic.wireSqlBytes += message.sql?.length ?? 0;
      for (const s of message.statements ?? [])
        traffic.wireSqlBytes += s.sql?.length ?? 0;
      return post.call(this, message, ...rest);
    } as typeof post;
  }
  const count = (sql: string, params: readonly unknown[] = []) => {
    traffic.statements++;
    traffic.sqlBytes += sql.length;
    for (const v of params)
      traffic.paramBytes +=
        typeof v === "string" || v instanceof Uint8Array ? v.length : 8;
  };
  const driver = openBetterSqlite3(
    join(workRoot, `${input.path}-${input.loadWhole}.sqlite`),
  );
  const db = await openLocalDb(
    input.diagnostics
      ? {
          ...driver,
          async query(sql, params) {
            traffic.queries++;
            count(sql, params);
            return driver.query(sql, params);
          },
          async batch(statements) {
            traffic.batches++;
            for (const s of statements) count(s.sql, s.params);
            const result = await driver.batch(statements);
            // Bounded diagnostic snapshots, not a second acceptance oracle. Only
            // the existing child's kernel HWM determines the test's peak/bound.
            if (++batches % 64 === 0) observe(phase);
            return result;
          },
        }
      : driver,
    identity,
  );
  const nativeRoot = join(input.fixture.root, "native");
  const native =
    input.path === "node"
      ? initializeDatabase(join(nativeRoot, "index.db"))
      : undefined;
  let access: Awaited<ReturnType<typeof openLegacyAccess>> | undefined;
  try {
    await db.batch([
      {
        sql: "INSERT INTO connections (connection_id, connector, ns, generation, control_state) VALUES (?, ?, 'known', 1, 'active')",
        params: [target.connectionId, target.connector],
      },
    ]);
    const unused = async (): Promise<never> => {
      throw new Error("memory_workload_unexpected_network_or_erase");
    };
    let op = 0;
    const deps: LocalSyncDeps = {
      db,
      queue: connectionQueue(),
      ownerAddress: identity.owner,
      registry: {
        read: unused,
        post: unused,
        listControlRows: unused,
        listStreamRows: unused,
      },
      blobs: { get: unused, put: unused },
      keys: {
        namespaceHmac: unused,
        encrypt: unused,
        encryptPart: unused,
        decrypt: unused,
      },
      signer: { signAddData: unused },
      logger: { info() {}, warn() {} },
      now: () => 123,
      newOp: () => `memory-op-${++op}`,
    };
    let source: ImportSource;
    memory.beforeSource = process.memoryUsage();
    if (native) {
      access = await openLegacyAccess({
        importProjection: {
          bindings: new Map([
            [
              "memory.items",
              { connector: target.connector, streams: [target.stream] },
            ],
          ]),
        },
        db: native,
        root: nativeRoot,
        owner: identity.owner,
        network: identity.network,
        eraseLedger: createLegacyEraseLedger(db, () => 123),
        resolveTarget: async () => target,
        verifyBinding: async () => true,
        isSwitched: async () => true,
        isQuiescent: async () => true,
        legacyWriteSeal: {
          commit: unused,
          remove: unused,
          admit: () => null,
          verdict: () => "switched",
        },
        declarations: [
          {
            source_id: input.fixture.sourceId,
            source_kind: "connector",
            version: "1",
            digest: "memory-artifact",
            streams: [
              {
                name: target.stream,
                primary_key: [...target.primaryKey],
                fields: ["id", "text"],
                required_fields: ["id"],
              },
            ],
          },
        ],
      });
      const inventory = access.sources()[Symbol.asyncIterator]();
      const first = await inventory.next();
      if (first.done || "kind" in first.value || !(await inventory.next()).done)
        throw new Error("memory_source_inventory_mismatch");
      source = first.value;
    } else {
      phase = "upload-staging";
      async function* uploadBody() {
        for await (const chunk of createReadStream(input.fixture.uploadPath, {
          highWaterMark: 64 * 1024,
        })) {
          observe(phase);
          yield chunk as Uint8Array;
        }
      }
      source = await stageLegacyImportUpload({
        owner: identity.owner,
        network: identity.network,
        stagingRoot: join(workRoot, `staging-${input.loadWhole}`),
        upload: {
          source: "memory-install",
          revision: input.fixture.revision,
          artifactDigest: "memory-artifact",
          stream: target.stream,
          body: input.diagnostics
            ? uploadBody()
            : createReadStream(input.fixture.uploadPath, {
                highWaterMark: 64 * 1024,
              }),
        },
        resolveArtifact: async (digest) =>
          digest === "memory-artifact"
            ? {
                connector: target.connector,
                version: "1",
                streams: [
                  {
                    name: target.stream,
                    primaryKey: [...target.primaryKey],
                    semantics: target.semantics,
                  },
                ],
              }
            : null,
        resolveTarget: async () => target,
      });
    }
    memory.afterSource = process.memoryUsage();
    if (input.loadWhole) {
      for await (const record of source.records()) retained.push(record);
      source = {
        ...source,
        async *records() {
          yield* retained;
        },
      };
    }
    memory.afterRetain = process.memoryUsage();
    // Diagnostics locate growth without replacing the kernel HWM oracle.
    // Keep only fixed-size summaries, never bodies or per-row measurements.
    const reader = source;
    let pass = 0;
    source = {
      ...source,
      async *records() {
        const current = ++pass;
        phase = current === 1 ? "snapshot-staging" : "snapshot-verification";
        memory[`sourcePass${current}Start`] = process.memoryUsage();
        let rows = 0;
        for await (const record of reader.records()) {
          if (++rows % 64 === 0) observe(phase);
          yield record;
        }
        memory[`sourcePass${current}`] = process.memoryUsage();
        phase = current === 1 ? "merge" : "receipt";
      },
    };
    const imported =
      input.path === "node"
        ? await importLegacySource(deps, createImportLedger(db), source)
        : await acceptLegacyImportUpload(deps, source);
    if (imported.kind === "refused") throw new Error(imported.reason);
    memory.afterImport = process.memoryUsage();
    const [stored] = await db.query<{ rows: number; payloadBytes: number }>(
      "SELECT count(*) AS rows, sum(length(CAST(json_extract(body, '$.text') AS BLOB))) AS payloadBytes FROM records",
    );
    return {
      kind: imported.kind,
      receiptRows: imported.receipt.rows,
      rows: stored!.rows,
      payloadBytes: stored!.payloadBytes,
      retainedRows: retained.length,
      retainedPayloadBytes: retained.reduce(
        (sum, record) => sum + Buffer.byteLength(record.text as string),
        0,
      ),
      memory,
      rssSnapshots,
      traffic: input.diagnostics
        ? { ...traffic, maxLoopStallMs: Math.round(loop.max / 1e6) }
        : undefined,
      sqliteVersion: db.info.sqliteVersion,
    };
  } finally {
    await access?.close();
    native?.close();
    await db.close();
  }
}
