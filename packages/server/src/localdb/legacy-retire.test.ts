import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { retireLegacyCopies } from "../../../core/src/localdb/legacy-retire.js";
import type { LegacyRetireAccess } from "../../../core/src/localdb/legacy-retire.js";
import { createImportLedger } from "../../../core/src/localdb/import-ledger.js";
import type { ImportLedger } from "../../../core/src/localdb/import-ledger.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import { MIGRATIONS } from "../../../core/src/localdb/schema.js";
import type {
  ImportReadback,
  ImportReceipt,
  LegacyCopy,
  LegacyRetireFileReport,
} from "../../../core/src/localdb/legacy-import-types.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

vi.mock("../../../core/src/localdb/import-ledger.js", () => ({
  createImportLedger: vi.fn(),
}));

const databases: SqlDriver[] = [];
beforeEach(() => {
  vi.mocked(createImportLedger).mockReset();
});
afterEach(async () => {
  vi.restoreAllMocks();
  for (const db of databases.splice(0)) await db.close();
});

const identity = (source: LegacyCopy["sources"][number]) =>
  JSON.stringify([source.source, source.connectionId, source.stream]);

async function fixture(
  sources: LegacyCopy["sources"] = [
    { source: "source-a", connectionId: "connection-a", stream: "stream-a" },
  ],
) {
  // In-memory SQL leaves no test-created files or system-temp scratch.
  const db = openBetterSqlite3(":memory:");
  databases.push(db);
  await db.batch(
    MIGRATIONS.flatMap((migration) => migration.map((sql) => ({ sql }))),
  );
  await db.batch([
    {
      sql: `CREATE TABLE fixture_receipts (
      source TEXT NOT NULL, connection_id TEXT NOT NULL, stream TEXT NOT NULL,
      state TEXT NOT NULL, at INTEGER NOT NULL,
      PRIMARY KEY (source, connection_id, stream))`,
    },
  ]);
  for (const connectionId of new Set(sources.map((s) => s.connectionId))) {
    await db.batch([
      {
        sql: "INSERT INTO connections (connection_id, connector, ns, generation, control_state) VALUES (?, ?, '', 1, 'active')",
        params: [connectionId, "fixture-declaration"],
      },
    ]);
  }
  const receipts = new Map<string, ImportReceipt>();
  for (const source of sources) {
    await db.batch([
      {
        sql: `INSERT OR IGNORE INTO stream_state
          (connection_id, stream, primary_key, semantics, incremental, publish_watermark)
          VALUES (?, ?, '["id"]', 'mutable_state', 1, 10)`,
        params: [source.connectionId, source.stream],
      },
      {
        sql: "INSERT INTO fixture_receipts VALUES (?, ?, ?, 'imported', 10)",
        params: [source.source, source.connectionId, source.stream],
      },
    ]);
    receipts.set(identity(source), {
      ...source,
      revision: "revision-1",
      generation: 1,
      rows: 1,
      fingerprint: "fingerprint",
      highestSeq: 10,
      state: "imported",
      reason: null,
      at: 10,
    });
  }
  const ledger: ImportLedger = {
    get: vi.fn(async (source, connectionId, stream) => {
      const receipt = receipts.get(identity({ source, connectionId, stream }));
      const [stored] = await db.query<{ state: string; at: number }>(
        "SELECT state, at FROM fixture_receipts WHERE source = ? AND connection_id = ? AND stream = ?",
        [source, connectionId, stream],
      );
      return receipt && stored
        ? {
            ...receipt,
            state: stored.state as ImportReceipt["state"],
            at: stored.at,
          }
        : null;
    }),
    statements: vi.fn((receipt) => [
      {
        sql: "UPDATE fixture_receipts SET state = ?, at = ? WHERE source = ? AND connection_id = ? AND stream = ?",
        params: [
          receipt.state,
          receipt.at,
          receipt.source,
          receipt.connectionId,
          receipt.stream,
        ],
      },
    ]),
  };
  vi.mocked(createImportLedger).mockReturnValue(ledger);
  const copy: LegacyCopy = {
    id: "copy-id",
    path: "fixture/copy",
    contentHash: "copy-hash",
    revision: "revision-1",
    dataSet: "fixture-data-set",
    sources,
  };
  const deps: LocalSyncDeps = {
    db,
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    registry: {} as LocalSyncDeps["registry"],
    blobs: {} as LocalSyncDeps["blobs"],
    keys: {} as LocalSyncDeps["keys"],
    signer: {} as LocalSyncDeps["signer"],
    logger: { info() {}, warn() {} },
    now: () => 100,
    newOp: () => "fixture-op",
  };
  let present: LegacyCopy | null = copy;
  const reports: LegacyRetireFileReport[] = [];
  const proof = async (): Promise<ImportReadback[]> =>
    Promise.all(
      sources.map(async (source) => {
        const receipt = await ledger.get(
          source.source,
          source.connectionId,
          source.stream,
        );
        if (!receipt) throw new Error("fixture missing receipt");
        return {
          receipt,
          actual: { rows: receipt.rows, fingerprint: receipt.fingerprint },
          pass: true,
          reason: null,
        };
      }),
    );
  const access: LegacyRetireAccess = {
    copies: async function* () {
      if (present) yield present;
    },
    readBack: vi.fn(async () => proof()),
    erase: vi.fn(async (exactCopy) => {
      if (!present || identityCopy(present) !== identityCopy(exactCopy))
        return false;
      present = null;
      return true;
    }),
  };
  const run = (
    options: { streamSync?: { retireLegacy?: boolean }; dryRun?: boolean } = {
      streamSync: { retireLegacy: true },
    },
  ) =>
    retireLegacyCopies(deps, access, {
      ...options,
      reportFile: (report) => reports.push(report),
    });
  const states = async () =>
    db.query<{ state: string }>(
      "SELECT state FROM fixture_receipts ORDER BY source, connection_id, stream",
    );
  return {
    db,
    deps,
    ledger,
    receipts,
    copy,
    access,
    proof,
    reports,
    run,
    states,
    present: () => present,
    replace: (replacement: LegacyCopy | null) => {
      present = replacement;
    },
  };
}

function identityCopy(copy: LegacyCopy): string {
  return JSON.stringify([
    copy.id,
    copy.path,
    copy.contentHash,
    copy.revision,
    copy.dataSet,
    copy.sources.map(identity).sort(),
  ]);
}

it("read-back bugs are reported and do not block enabled replacement", async () => {
  const f = await fixture();
  f.access.readBack = async () => [
    { ...(await f.proof())[0]!, pass: false, reason: "record_mismatch" },
  ];
  expect(await f.run()).toMatchObject({ deleted: 1 });
  expect(f.present()).toBeNull();
});
it("removal stays off by default and dry runs cannot erase", async () => {
  for (const options of [
    {},
    { streamSync: { retireLegacy: false } },
    { dryRun: true, streamSync: { retireLegacy: true } },
  ]) {
    const f = await fixture();
    expect(await f.run(options)).toMatchObject({ ready: 1, deleted: 0 });
    expect(f.access.erase).not.toHaveBeenCalled();
    expect(await f.states()).toEqual([{ state: "imported" }]);
  }
});
it("unimported copies are counted and removed with the rest", async () => {
  const f = await fixture([]);
  expect(await f.run()).toMatchObject({
    deleted: 1,
    unimported: 1,
    readbackFailures: 0,
  });
  expect(f.present()).toBeNull();
});
it("missing import proof is reported without blocking removal", async () => {
  const f = await fixture();
  f.access.readBack = async () => [];
  expect(await f.run()).toMatchObject({ deleted: 1, readbackFailures: 1 });
  expect(f.reports[0]).toMatchObject({
    decision: "retired",
    reason: "missing-import-proof",
  });
});
it("a deleted connection and an unpublished stream do not retain obsolete files", async () => {
  const f = await fixture();
  await f.db.batch([
    { sql: "UPDATE connections SET control_state = 'deleted', deleted_at = 1" },
    { sql: "UPDATE stream_state SET publish_watermark = 0" },
  ]);
  expect(await f.run()).toMatchObject({ deleted: 1 });
  expect(await f.db.query("SELECT control_state FROM connections")).toEqual([
    { control_state: "deleted" },
  ]);
});
it("the exact-copy compare fence preserves a replacement", async () => {
  const f = await fixture();
  f.access.erase = async () => false;
  expect(await f.run()).toMatchObject({ deleted: 0 });
  expect(f.present()).not.toBeNull();
  expect(f.reports[0]).toMatchObject({ decision: "changed" });
});
it("absence is reconciled only by its exact durable intent, without read-back", async () => {
  const f = await fixture();
  f.access.erasedWithIntent = async () => true;
  f.access.finishErase = vi.fn(async () => {});
  f.access.readBack = vi.fn(async () => {
    throw new Error("absent");
  });
  expect(await f.run()).toMatchObject({
    ready: 1,
    deleted: 0,
    readbackFailures: 0,
  });
  expect(f.access.readBack).not.toHaveBeenCalled();
  expect(f.access.erase).not.toHaveBeenCalled();
  expect(f.access.finishErase).toHaveBeenCalledOnce();
  expect(await f.states()).toEqual([{ state: "retired" }]);
});
it("missing files with no content proof are counted without synthesizing intent", async () => {
  const f = await fixture();
  f.replace({ ...f.copy, contentHash: "" });
  expect(await f.run()).toMatchObject({ missing: 1, deleted: 0 });
  expect(f.access.erase).not.toHaveBeenCalled();
  expect(f.reports[0]).toMatchObject({
    decision: "skipped",
    reason: "missing-copy-proof",
  });
});
