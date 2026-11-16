// Bench of one Desktop seed handoff on the Personal Server side: the body of
// `PUT /v1/stream-sync/seed/<connector>/<stream>` (a descriptor line, then one
// record per line) is staged to disk, then imported into the local database.
// Real SQLite, real staging files, real importer; no network.
//
//   npx tsx packages/server/src/localdb/seed-handoff.workload.ts \
//     --dir ~/.tmp/<dir> --rows 198000 --row-bytes 2150 [--profile]
//
// Prints one JSON object: the milliseconds each phase took (`stageMs`,
// `importMs`), the bytes staged, and with `--profile` the time spent in each
// SQL statement shape. No personal data: rows are filler.
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import {
  connectionQueue,
  createLocalSeed,
  createLocalSync,
  createSeedIntake,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import {
  createMemoryStreamSyncBlobs,
  createMemoryStreamSyncRegistry,
} from "../../../core/src/stream-sync/index.js";
import { createSeedStaging } from "../../../core/src/stream-sync/seed-staging.js";
import { pkHash } from "@opendatalabs/personal-server-ts-stream-sync";
import { sha256 } from "@noble/hashes/sha2";
import { createFsStreamSyncFiles } from "../stream-sync/fs-files.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const owner = `0x${"11".repeat(20)}` as const;
const CONNECTOR = "handoff-source";
const STREAM = "items";

const manifest = JSON.stringify({
  connector_key: CONNECTOR,
  version: "1",
  streams: [STREAM].map((name) => ({
    name,
    primary_key: ["id"],
    semantics: "mutable_state",
  })),
});

/** The request body Desktop sends: chunks of about `chunkBytes`, like a socket's reads. */
async function* body(
  rows: number,
  rowBytes: number,
  chunkBytes = 65_536,
  sorted = false,
) {
  const encoder = new TextEncoder();
  const lines: string[] = [
    JSON.stringify({
      primaryKey: ["id"],
      profile: { key: null, version: "1" },
      records: rows,
    }),
  ];
  let pending = 0;
  const flush = function* () {
    if (lines.length === 0) return;
    yield encoder.encode(lines.join("\n") + "\n");
    lines.length = 0;
    pending = 0;
  };
  let order = Array.from({ length: rows }, (_, i) => i);
  if (sorted) {
    const keyed = await Promise.all(
      order.map(
        async (i) =>
          [
            await pkHash(async (b) => sha256(b), { id: `row-${i}` }, ["id"]),
            i,
          ] as const,
      ),
    );
    keyed.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    order = keyed.map(([, i]) => i);
  }
  for (const i of order) {
    const line = JSON.stringify({
      id: `row-${i}`,
      text: `${i}:`.padEnd(rowBytes, "x"),
    });
    lines.push(line);
    pending += line.length + 1;
    if (pending >= chunkBytes) yield* flush();
  }
  yield* flush();
}

const shapeOf = (sql: string) => sql.replace(/\s+/g, " ").trim().slice(0, 90);

export interface HandoffBenchResult {
  readonly rows: number;
  readonly bytes: number;
  readonly stageMs: number;
  readonly importMs: number;
  readonly totalMs: number;
  readonly state: string;
  readonly sql?: readonly { shape: string; n: number; ms: number }[];
}

export async function benchHandoff(options: {
  readonly dir: string;
  readonly rows: number;
  readonly rowBytes: number;
  readonly profile?: boolean;
  readonly sorted?: boolean;
}): Promise<HandoffBenchResult> {
  mkdirSync(options.dir, { recursive: true });
  const driver = openBetterSqlite3(join(options.dir, "handoff.sqlite"));
  const sql = new Map<string, { n: number; ms: number }>();
  const note = (shape: string, started: number) => {
    const entry = sql.get(shape) ?? { n: 0, ms: 0 };
    entry.n += 1;
    entry.ms += performance.now() - started;
    sql.set(shape, entry);
  };
  const profiled: SqlDriver = options.profile
    ? {
        info: driver.info,
        reads: driver.reads,
        ...(driver.snapshot ? { snapshot: driver.snapshot.bind(driver) } : {}),
        close: () => driver.close(),
        query: async (text, params) => {
          const started = performance.now();
          try {
            return await driver.query(text, params);
          } finally {
            note(shapeOf(text), started);
          }
        },
        batch: async (statements) => {
          const started = performance.now();
          try {
            return await driver.batch(statements);
          } finally {
            note(`BATCH: ${shapeOf(statements[0]?.sql ?? "(empty)")}`, started);
          }
        },
      }
    : driver;
  const db = await openLocalDb(profiled, {
    owner,
    network: "test",
    deviceId: "handoff",
  });
  const registry = createMemoryStreamSyncRegistry();
  const blobs = createMemoryStreamSyncBlobs();
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
    registry,
    blobs,
    ownerAddress: owner,
    keys: {
      namespaceHmac: async () => new Uint8Array(32),
      encrypt: async (_s, b) => b,
      encryptPart: async (_s, b) => b,
      decrypt: async (_s, b) => b,
    },
    signer: { signAddData: async () => "0x00" },
    logger: { info: () => {}, warn: () => {} },
    now: () => 1_000,
    newOp: () => `handoff-${++op}`,
  };
  try {
    createLocalSync(deps, {
      resolveArtifact: () => ({
        connector: CONNECTOR,
        version: "1",
        streams: [
          {
            name: STREAM,
            semantics: "mutable_state" as const,
            primaryKey: ["id"],
            coverageStrategy: "full_inventory" as const,
          },
        ],
      }),
      declaredStreams: () => [STREAM],
    });
    const staging = createSeedStaging(
      createFsStreamSyncFiles(join(options.dir, "staging")),
    );
    const intake = createSeedIntake(
      createLocalSeed({
        getDeps: async () => deps,
        manifests: () => [manifest],
        staging,
      }),
    );
    // The target connection exists once the first status read has synced it.
    await intake.status(CONNECTOR);
    // Split the PUT in its two steps by timing the staging write alone.
    const started = performance.now();
    let bytes = 0;
    const counted = async function* () {
      for await (const chunk of body(
        options.rows,
        options.rowBytes,
        65_536,
        options.sorted,
      )) {
        bytes += chunk.byteLength;
        yield chunk;
      }
    };
    let stagedAt = 0;
    const seed = createLocalSeed({
      getDeps: async () => deps,
      manifests: () => [manifest],
      staging: {
        ...staging,
        stage: async (c, s, b, check) => {
          const staged = await staging.stage(c, s, b, check);
          stagedAt = performance.now();
          return staged;
        },
      },
    });
    const result = await createSeedIntake(seed).put(
      CONNECTOR,
      STREAM,
      counted(),
    );
    const done = performance.now();
    return {
      rows: options.rows,
      bytes,
      stageMs: Math.round(stagedAt - started),
      importMs: Math.round(done - stagedAt),
      totalMs: Math.round(done - started),
      state: result.state,
      ...(options.profile
        ? {
            sql: [...sql.entries()]
              .map(([shape, v]) => ({ shape, n: v.n, ms: Math.round(v.ms) }))
              .sort((a, b) => b.ms - a.ms)
              .slice(0, 20),
          }
        : {}),
    };
  } finally {
    await db.close();
  }
}

function arg(name: string, fallback?: string): string {
  const i = process.argv.indexOf(`--${name}`);
  const value = i >= 0 ? process.argv[i + 1] : fallback;
  if (value === undefined) throw new Error(`missing --${name}`);
  return value;
}

if (process.argv[1]?.endsWith("seed-handoff.workload.ts")) {
  benchHandoff({
    dir: arg("dir"),
    rows: Number(arg("rows", "198000")),
    rowBytes: Number(arg("row-bytes", "2150")),
    profile: process.argv.includes("--profile"),
    sorted: process.argv.includes("--sorted"),
  })
    .then((result) => console.log(JSON.stringify(result, null, 2)))
    .catch((error: unknown) => {
      console.error(error);
      process.exit(1);
    });
}
