import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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
  const proof = async (exactCopy = copy): Promise<ImportReadback[]> =>
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
          copy: exactCopy,
          pass: true,
          reason: null,
          projections: [
            {
              dataSet: copy.dataSet,
              expectedHash: copy.contentHash,
              actualHash: copy.contentHash,
              pass: true,
            },
          ],
        };
      }),
    );
  const access: LegacyRetireAccess = {
    copies: async function* () {
      if (present) yield present;
    },
    readBack: vi.fn(async (exactCopy) => proof(exactCopy)),
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

describe("legacy retirement", () => {
  it.each([
    { name: "below", watermarks: [9, 10], deleted: 0 },
    { name: "equal", watermarks: [10, 10], deleted: 1 },
    { name: "above", watermarks: [11, 12], deleted: 1 },
    { name: "every stream", watermarks: [10, 9], deleted: 0 },
  ])(
    "retire-watermark-covers-import-highest-seq: $name",
    async ({ watermarks, deleted }) => {
      const f = await fixture([
        {
          source: "source-a",
          connectionId: "connection-a",
          stream: "stream-a",
        },
        {
          source: "source-b",
          connectionId: "connection-a",
          stream: "stream-b",
        },
      ]);
      await f.db.batch(
        f.copy.sources.map((source, i) => ({
          sql: "UPDATE stream_state SET publish_watermark = ? WHERE connection_id = ? AND stream = ?",
          params: [watermarks[i]!, source.connectionId, source.stream],
        })),
      );
      expect(await f.run()).toEqual({
        mode: "delete",
        files: 1,
        ready: deleted,
        deleted,
      });
      expect(f.access.erase).toHaveBeenCalledTimes(deleted);
      expect(await f.states()).toEqual([
        { state: deleted ? "retired" : "imported" },
        { state: deleted ? "retired" : "imported" },
      ]);
    },
  );

  it("retire-default-off", async () => {
    for (const options of [
      {},
      { streamSync: {} },
      { streamSync: { retireLegacy: false } },
    ]) {
      const f = await fixture();
      expect(await f.run(options)).toEqual({
        mode: "readback-only",
        files: 1,
        ready: 1,
        deleted: 0,
      });
      expect(f.access.readBack).toHaveBeenCalledTimes(1);
      expect(f.access.erase).not.toHaveBeenCalled();
      expect(f.ledger.statements).not.toHaveBeenCalled();
      expect(await f.states()).toEqual([{ state: "imported" }]);
    }
  });

  it("retire-fresh-proof-only", async () => {
    const f = await fixture();
    await f.db.batch([
      { sql: "UPDATE fixture_receipts SET state = 'verified'" },
    ]);
    expect((await f.run({})).ready).toBe(1);
    vi.mocked(f.access.readBack).mockImplementation(async (copy) =>
      (await f.proof(copy)).map((proof) => ({
        ...proof,
        pass: false,
        reason: "fixture-mismatch",
      })),
    );
    expect((await f.run()).deleted).toBe(0);
    expect(f.access.readBack).toHaveBeenCalledTimes(2);
    expect(f.access.erase).not.toHaveBeenCalled();
    expect(await f.states()).toEqual([{ state: "verified" }]);
  });

  it("retire-changed-copy-kept", async () => {
    for (const change of ["hash", "revision", "path", "replacement"] as const) {
      const f = await fixture();
      vi.mocked(f.access.readBack).mockImplementation(async (copy) => {
        const changed = {
          ...copy,
          ...(change === "path"
            ? { path: "fixture/other" }
            : change === "revision"
              ? { revision: "revision-2" }
              : { contentHash: "replacement-hash" }),
        };
        if (change === "replacement") {
          const proofs = await f.proof(copy);
          f.replace(changed);
          return proofs;
        }
        return f.proof(changed);
      });
      expect((await f.run()).deleted, change).toBe(0);
      expect(f.present(), change).not.toBeNull();
      expect(await f.states(), change).toEqual([{ state: "imported" }]);
      expect(f.reports.at(-1)?.decision, change).toBe(
        change === "replacement" ? "held" : "changed",
      );
    }
  });

  it("retire-excluded-or-empty-held", async () => {
    for (const variant of [
      "excluded",
      "empty",
      "missing-receipt",
      "no-proof",
      "no-sources",
      "duplicate-source",
      "no-projection",
      "fingerprint-mismatch",
    ]) {
      const f = await fixture();
      if (variant === "excluded") {
        await f.db.batch([
          { sql: "UPDATE fixture_receipts SET state = 'excluded'" },
        ]);
      } else if (variant === "empty") {
        const receipt = f.receipts.get(identity(f.copy.sources[0]!))!;
        f.receipts.set(identity(receipt), {
          ...receipt,
          rows: 0,
          highestSeq: 0,
        });
      } else if (variant === "missing-receipt") {
        const proofs = await f.proof();
        vi.mocked(f.access.readBack).mockResolvedValue(proofs);
        vi.mocked(f.ledger.get).mockResolvedValue(null);
      } else if (variant === "no-proof") {
        vi.mocked(f.access.readBack).mockResolvedValue([]);
      } else if (variant === "no-sources" || variant === "duplicate-source") {
        f.access.copies = async function* () {
          yield {
            ...f.copy,
            sources:
              variant === "no-sources"
                ? []
                : [f.copy.sources[0]!, f.copy.sources[0]!],
          };
        };
      } else {
        vi.mocked(f.access.readBack).mockImplementation(async (copy) =>
          (await f.proof(copy)).map((proof) => ({
            ...proof,
            ...(variant === "no-projection"
              ? { projections: [] }
              : {
                  actual: { rows: proof.actual.rows, fingerprint: "different" },
                }),
          })),
        );
      }
      expect((await f.run()).deleted, variant).toBe(0);
      expect(f.access.erase, variant).not.toHaveBeenCalled();
      expect(f.ledger.statements, variant).not.toHaveBeenCalled();
      expect(f.reports.at(-1)?.decision, variant).toBe("held");
    }
  });

  it("retire-delete-race-kept", async () => {
    for (const sql of [
      "INSERT INTO delete_intents SELECT connector, 'delete-id', '{}' FROM connections",
      "UPDATE connections SET control_state = 'deleted'",
      "UPDATE connections SET deleted_at = 123",
      "UPDATE connections SET generation = 2",
      "UPDATE stream_state SET last_delete_version = 1",
      "UPDATE stream_state SET floor_o = 1, floor_r = 'delete', floor_version = '1'",
      "UPDATE stream_state SET publish_watermark = 9",
    ]) {
      const f = await fixture();
      vi.mocked(f.access.readBack).mockImplementation(async (copy) => {
        const proofs = await f.proof(copy);
        await f.db.batch([{ sql }]);
        return proofs;
      });
      expect((await f.run()).deleted).toBe(0);
      expect(f.access.erase).not.toHaveBeenCalled();
      expect(await f.states()).toEqual([{ state: "imported" }]);
      expect(f.reports.at(-1)?.decision).toBe("held");
    }
  });

  it("retire-missing-receipt-holds", async () => {
    const f = await fixture();
    const proofs = await f.proof();
    f.access.readBack = vi.fn(async () =>
      proofs.map((p) => ({ ...p, receipt: null })),
    );
    expect((await f.run()).deleted).toBe(0);
    expect(f.access.erase).not.toHaveBeenCalled();
  });

  it("retire-free-text-reason-is-not-proof-metadata", async () => {
    const f = await fixture();
    for (const r of f.receipts.values())
      f.receipts.set(identity(r), { ...r, reason: "Import complete" });
    expect((await f.run()).deleted).toBe(1);
  });

  it("retire-crash-after-erase", async () => {
    const f = await fixture();
    const batch = vi
      .spyOn(f.db, "batch")
      .mockRejectedValueOnce(new Error("fixture crash after erase"));
    await expect(f.run()).rejects.toThrow("fixture crash after erase");
    expect(f.present()).toBeNull();
    expect(f.access.erase).toHaveBeenCalledTimes(1);
    expect(await f.states()).toEqual([{ state: "imported" }]);
    batch.mockRestore();
    // The failed pre-crash transaction attempted a receipt write. Only new
    // attempts below must refrain from writing retirement state.
    vi.mocked(f.ledger.statements).mockClear();

    // A retained old identity may be replayed, but a replacement at its path
    // is not the erased copy. Even a fresh old-copy proof cannot erase it.
    const replacement = { ...f.copy, contentHash: "replacement-hash" };
    f.replace(replacement);
    f.access.copies = async function* () {
      yield f.copy;
    };
    expect((await f.run()).deleted).toBe(0);
    expect(f.present()).toEqual(replacement);
    expect(f.access.erase).toHaveBeenCalledTimes(2);
    expect(await f.states()).toEqual([{ state: "imported" }]);
    expect(f.reports.at(-1)).toEqual({
      file: f.copy.id,
      decision: "held",
      reason: "erase-not-confirmed",
    });

    // Absence alone is not inferred from the boolean false result.
    f.replace(null);
    expect((await f.run()).deleted).toBe(0);
    expect(await f.states()).toEqual([{ state: "imported" }]);
    expect(f.reports.at(-1)).toEqual({
      file: f.copy.id,
      decision: "held",
      reason: "erase-not-confirmed",
    });
    expect(f.ledger.statements).not.toHaveBeenCalled();
  });

  it("retire-dry-run-flag-on-no-delete", async () => {
    const f = await fixture();
    expect(
      await f.run({ streamSync: { retireLegacy: true }, dryRun: true }),
    ).toEqual({
      mode: "dry-run",
      files: 1,
      ready: 1,
      deleted: 0,
    });
    expect(f.access.readBack).toHaveBeenCalledTimes(1);
    expect(f.access.erase).not.toHaveBeenCalled();
    expect(f.ledger.statements).not.toHaveBeenCalled();
    expect(f.present()).toEqual(f.copy);
    expect(await f.states()).toEqual([{ state: "imported" }]);
    expect(f.reports).toEqual([
      { file: f.copy.id, decision: "ready", reason: null },
    ]);
  });

  it("retire-sorted-queues-held-through-readback-and-erase", async () => {
    const f = await fixture([
      { source: "source-b", connectionId: "connection-b", stream: "stream-b" },
      { source: "source-a", connectionId: "connection-a", stream: "stream-a" },
      { source: "source-c", connectionId: "connection-a", stream: "stream-c" },
    ]);
    const held: string[] = [];
    const acquired: string[] = [];
    const queue: LocalSyncDeps["queue"] = {
      run<T>(
        connectionId: string,
        kind: Parameters<LocalSyncDeps["queue"]["run"]>[1],
        fn: () => Promise<T>,
      ): Promise<T> {
        expect(kind).toBe("end");
        return f.deps.queue.run(connectionId, kind, async () => {
          expect(held).not.toContain(connectionId);
          acquired.push(connectionId);
          held.push(connectionId);
          try {
            return await fn();
          } finally {
            expect(held.pop()).toBe(connectionId);
          }
        });
      },
    };
    vi.mocked(f.access.readBack).mockImplementation(async (copy) => {
      expect(held).toEqual(["connection-a", "connection-b"]);
      return f.proof(copy);
    });
    const erase = f.access.erase;
    f.access.erase = vi.fn(async (copy) => {
      expect(held).toEqual(["connection-a", "connection-b"]);
      return erase(copy);
    });
    const result = await retireLegacyCopies({ ...f.deps, queue }, f.access, {
      streamSync: { retireLegacy: true },
      reportFile: (report) => f.reports.push(report),
    });
    expect(result.deleted).toBe(1);
    expect(acquired).toEqual(["connection-a", "connection-b"]);
    expect(held).toEqual([]);
    expect(await f.states()).toEqual([
      { state: "retired" },
      { state: "retired" },
      { state: "retired" },
    ]);
  });
});
