import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createLocalHistory } from "../../../core/src/localdb/history.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const SCOPE = "pdpp.test-source.events";
const OBSERVED_5 = Date.parse("2025-02-03T04:05:06.000Z");
const OBSERVED_6 = Date.parse("2025-02-02T04:05:06.000Z");
const IMPORTED = Date.parse("2025-03-04T05:06:07.000Z");
const NOW = Date.parse("2025-04-05T06:07:08.000Z");

describe("local history versions", () => {
  const dirs: string[] = [];
  const drivers: SqlDriver[] = [];

  afterEach(async () => {
    for (const driver of drivers.splice(0)) await driver.close();
    for (const dir of dirs.splice(0))
      rmSync(dir, { recursive: true, force: true });
  });

  async function fresh() {
    const dir = mkdtempSync(join(process.cwd(), ".history-versions-"));
    dirs.push(dir);
    const driver = openBetterSqlite3(join(dir, "db.sqlite"));
    drivers.push(driver);
    const db = await openLocalDb(driver, {
      owner: "0xabc",
      network: "test",
      deviceId: "history-test",
    });
    // HIST1 reads the first-seen column supplied by the preceding schema slice.
    const columns = await db.query<{ name: string }>(
      "PRAGMA table_info(records)",
    );
    if (!columns.some((column) => column.name === "first_o")) {
      await db.batch([
        { sql: "ALTER TABLE records ADD COLUMN first_o INTEGER" },
      ]);
    }
    const poison = new Proxy(
      {},
      {
        get() {
          throw new Error("unexpected store or external port access");
        },
      },
    );
    const deps: LocalSyncDeps = {
      db,
      queue: { run: async (_id, _kind, fn) => fn() },
      ownerAddress: "0xabc",
      registry: poison as LocalSyncDeps["registry"],
      blobs: poison as LocalSyncDeps["blobs"],
      keys: poison as LocalSyncDeps["keys"],
      signer: poison as LocalSyncDeps["signer"],
      logger: { info() {}, warn() {} },
      now: () => NOW,
      newOp: () => "history-op",
    };
    return { db, deps, poison };
  }

  async function seed(db: SqlDriver) {
    await db.batch([
      {
        sql: "INSERT INTO connections(connection_id, connector, ns, generation, control_state) VALUES ('c1', 'test-source', '', 2, 'active')",
      },
      {
        sql: "INSERT INTO stream_state(connection_id, stream, primary_key, semantics, incremental, head_version, head_generation, head_blob) VALUES ('c1', 'events', '[]', 'mutable_state', 0, 6, 2, 'blob-6')",
      },
      {
        sql: "INSERT INTO import_ledger(source, connection_id, stream, state, rows, fingerprint, at) VALUES ('fixture', 'c1', 'events', 'imported', 0, 'fixture', ?)",
        params: [IMPORTED],
      },
      ...(
        [
          [5, 2, "published", OBSERVED_5],
          [6, 2, "applied", OBSERVED_6],
          [7, 2, "delete", OBSERVED_5 + 1],
          [99, 1, "published", OBSERVED_5 + 2],
        ] as const
      ).map(([version, generation, kind, observed]) => ({
        sql: "INSERT INTO stream_versions(connection_id, stream, version, generation, head_blob, head_format, record_count, observed_at, complete, kind) VALUES ('c1', 'events', ?, ?, ?, 1, 0, ?, 1, ?)",
        params: [version, generation, "blob-" + version, observed, kind],
      })),
    ]);
  }

  const item = (version: number, observed: number) => ({
    fileId: "blob-" + version,
    schemaId: null,
    collectedAt: new Date(observed).toISOString(),
    version,
    producer: null,
    producer_provenance: null,
  });

  it("versions-six-fields-from-stream-versions", async () => {
    const { db, deps } = await fresh();
    await seed(db);
    const history = createLocalHistory(deps, { olderVersionReads: () => true });
    await expect(
      history.versions({ scope: SCOPE, limit: 20, offset: 0 }),
    ).resolves.toEqual({
      ok: true,
      value: {
        scope: SCOPE,
        versions: [item(6, OBSERVED_6), item(5, OBSERVED_5)],
        total: 2,
        limit: 20,
        offset: 0,
      },
    });
    await expect(
      history.versions({ scope: SCOPE, limit: 1, offset: 1 }),
    ).resolves.toEqual({
      ok: true,
      value: {
        scope: SCOPE,
        versions: [item(5, OBSERVED_5)],
        total: 2,
        limit: 1,
        offset: 1,
      },
    });
    await expect(
      history.versions({ scope: SCOPE, limit: 1, offset: 2 }),
    ).resolves.toEqual({
      ok: true,
      value: { scope: SCOPE, versions: [], total: 2, limit: 1, offset: 2 },
    });
  });

  it("versions-flag-off-lists-current-only", async () => {
    const { db, deps } = await fresh();
    await seed(db);
    let enabled = true;
    const history = createLocalHistory(deps, {
      olderVersionReads: () => enabled,
    });
    const before = await history.versions({
      scope: SCOPE,
      limit: 20,
      offset: 0,
    });
    expect(before.ok && before.value.total).toBe(2);
    enabled = false;
    await expect(
      history.versions({ scope: SCOPE, limit: 20, offset: 0 }),
    ).resolves.toEqual({
      ok: true,
      value: {
        scope: SCOPE,
        versions: [item(6, OBSERVED_6)],
        total: 1,
        limit: 20,
        offset: 0,
      },
    });
    await expect(
      history.versions({ scope: SCOPE, limit: 20, offset: 1 }),
    ).resolves.toEqual({
      ok: true,
      value: { scope: SCOPE, versions: [], total: 1, limit: 20, offset: 1 },
    });
  });

  it("lineage-root-answer-and-404-410", async () => {
    const { db, deps } = await fresh();
    await seed(db);
    const history = createLocalHistory(deps, { olderVersionReads: () => true });
    // GatewayProof requires userSignature and gatewaySignature. The local
    // database cannot attest them, so root proof is explicitly null.
    await expect(history.lineage({ scope: SCOPE })).resolves.toEqual({
      ok: true,
      value: { scope: SCOPE, version: 6, sources: [], proof: null },
    });
    await expect(
      history.lineage({ scope: SCOPE, version: 5 }),
    ).resolves.toEqual({
      ok: true,
      value: { scope: SCOPE, version: 5, sources: [], proof: null },
    });
    for (const scope of ["pdpp.missing.events", "pdpp.test-source.missing"]) {
      await expect(
        history.versions({ scope, limit: 20, offset: 0 }),
      ).resolves.toEqual({
        ok: false,
        reason: "not_found",
      });
      await expect(history.lineage({ scope })).resolves.toEqual({
        ok: false,
        reason: "not_found",
      });
    }
    await expect(
      history.lineage({ scope: SCOPE, version: 99 }),
    ).resolves.toEqual({
      ok: false,
      reason: "not_found",
    });
    await expect(
      history.lineage({ scope: SCOPE, version: 7 }),
    ).resolves.toEqual({
      ok: false,
      reason: "not_found",
    });
    await db.batch([
      {
        sql: "UPDATE connections SET control_state = 'deleted' WHERE connection_id = 'c1'",
      },
      { sql: "DELETE FROM stream_state WHERE connection_id = 'c1'" },
      { sql: "DELETE FROM stream_versions WHERE connection_id = 'c1'" },
    ]);
    await expect(
      history.versions({ scope: SCOPE, limit: 20, offset: 0 }),
    ).resolves.toEqual({
      ok: false,
      reason: "deleted",
    });
    await expect(
      history.lineage({ scope: SCOPE, version: 5 }),
    ).resolves.toEqual({
      ok: false,
      reason: "deleted",
    });
  });

  it("history-never-reads-legacy", async () => {
    const { db, deps, poison } = await fresh();
    await seed(db);
    // No legacy port is in LocalSyncDeps. Adjacent, structurally extra
    // options are poisoned to detect an accidental fallback.
    const options = {
      olderVersionReads: () => true,
      storage: poison,
      legacyStore: poison,
      projection: poison,
    };
    const history = createLocalHistory(deps, options);
    await expect(
      history.additions({ timezone: "UTC", days: 1 }),
    ).resolves.toMatchObject({
      total: 0,
      partial: false,
    });
    await expect(
      history.versions({ scope: SCOPE, limit: 20, offset: 0 }),
    ).resolves.toMatchObject({
      ok: true,
      value: { total: 2 },
    });
    await expect(history.lineage({ scope: SCOPE })).resolves.toMatchObject({
      ok: true,
      value: { sources: [], proof: null },
    });
    const source = readFileSync(
      new URL("../../../core/src/localdb/history.ts", import.meta.url),
      "utf8",
    );
    const imports = [
      ...source.matchAll(
        /(?:\bfrom\s*|\bimport\s*(?:\(\s*)?)["']([^"']+)["']/g,
      ),
    ].map((match) => match[1]);
    expect(imports).toContain("./deps.js");
    expect(
      imports.filter((specifier) =>
        /storage|legacy|projection|ledger-store/.test(specifier!),
      ),
    ).toEqual([]);
  });
});
