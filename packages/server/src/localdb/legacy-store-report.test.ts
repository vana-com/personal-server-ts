/**
 * What the legacy store import left out, and why, as a count a developer can
 * read from `read-status` to measure the gap. The seed rules are unchanged:
 * these tests only count what the runner already decides.
 */
import { join } from "node:path";
import { rm } from "node:fs/promises";
import { afterEach, describe, expect, it } from "vitest";
import { initializeDatabase } from "../storage/index-schema.js";
import { openRecordStore } from "../pdpp/records-bootstrap.js";
import {
  CONNECTOR,
  SOURCE_ID,
  STREAMS,
  direct,
  rowsOf,
  scratch,
  writeLegacyStore,
} from "./legacy-migration-fixture.test-utils.js";

const closers: Array<() => Promise<void>> = [];
const directories: string[] = [];
afterEach(async () => {
  for (const close of closers.splice(0)) await close();
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true });
});

/** Instances the production store holds beside the one that wins. */
function addOtherInstances(root: string) {
  const db = initializeDatabase(join(root, "index.db"));
  try {
    const store = openRecordStore(db, false);
    const ingest = (
      instance: string,
      method: string,
      emittedAt: string,
      rows: number,
    ) =>
      store.ingestBatch(
        rowsOf("repositories")
          .slice(0, rows)
          .map((row) => ({
            instance,
            stream: "repositories",
            key: row.id,
            data: row,
            emitted_at: emittedAt,
          })),
        () => "mutable_state",
        () => ["id"],
        { method, generation: 1 },
      );
    // An older export of the same upstream account: a live instance with
    // activity before the winner's.
    store.registerConnection({
      instance: "github-archive",
      sourceId: SOURCE_ID,
      method: CONNECTOR,
      label: "GitHub export",
    });
    ingest("github-archive", CONNECTOR, "2024-01-01T00:00:00.000Z", 2);
    // A source no verified declaration names.
    store.registerConnection({
      instance: "unknown-account",
      sourceId: "https://registry.pdpp.dev/connectors/unknown",
      method: "unknown",
      label: "Unknown",
    });
    ingest("unknown-account", "unknown", "2026-01-01T00:00:00.000Z", 3);
  } finally {
    db.close();
  }
}

describe("legacy store import report", () => {
  it("is null before any run", async () => {
    const base = await scratch("legacy-report-");
    directories.push(base);
    const root = join(base, "root");
    writeLegacyStore(root);
    const h = await direct(base, root);
    closers.push(h.close);
    expect(h.runner.report()).toBeNull();
  }, 60_000);

  it("counts, by reason, what a seeded fixture left out", async () => {
    const base = await scratch("legacy-report-");
    directories.push(base);
    const root = join(base, "root");
    writeLegacyStore(root);
    addOtherInstances(root);
    const h = await direct(base, root);
    closers.push(h.close);

    // First run: the winner's nine streams import.
    await h.run();
    const first = h.runner.report()!;
    expect(first).toMatchObject({
      stopped: false,
      imported: STREAMS.length,
      alreadyImported: 0,
      refused: [],
    });
    // Every row of the newest instance is imported; the older instance's rows
    // are excluded whole and counted, never merged.
    expect(first.rows.imported).toBeGreaterThan(0);
    expect(first.rows.legacy).toBe(first.rows.imported);
    expect(first.rows.quarantined).toEqual({});
    expect(first.excluded).toEqual([
      { reason: "older_instance", streams: 1, rows: 2 },
      { reason: "undeclared_source", streams: 1, rows: 3 },
    ]);
    // Six data files; the one no binding names is a file-only scope.
    expect(first.files).toEqual({ total: 6, unimported: 1 });

    // A real write now owns one stream and its receipt is gone: the next run
    // imports that stream again, and the seed only fills, so no row changes.
    await h.local.batch([
      {
        sql: "UPDATE stream_state SET floor_o = 1 WHERE connection_id = 'pdpp.github~' AND stream = 'repositories'",
      },
      {
        sql: "DELETE FROM import_ledger WHERE stream = 'repositories'",
      },
    ]);
    await h.run();
    const second = h.runner.report()!;
    expect(second).toMatchObject({
      stopped: false,
      imported: 1,
      alreadyImported: STREAMS.length - 1,
      refused: [],
    });
    expect(second.excluded).toEqual(first.excluded);
    expect(second.files).toEqual(first.files);
  }, 120_000);

  it("accounts for the rows of a refused stream: every old row is imported, left out, or refused", async () => {
    const base = await scratch("legacy-report-");
    directories.push(base);
    const root = join(base, "root");
    writeLegacyStore(root);
    addOtherInstances(root);
    const h = await direct(base, root);
    closers.push(h.close);
    await h.run();
    // The stream's declaration changed under the receipt: the next run
    // refuses it whole, and its rows are neither imported nor quarantined.
    await h.local.batch([
      {
        sql: "UPDATE stream_state SET primary_key = '[\"other\"]' WHERE connection_id = 'pdpp.github~' AND stream = 'repositories'",
      },
      { sql: "DELETE FROM import_ledger WHERE stream = 'repositories'" },
    ]);
    await h.run();
    const report = h.runner.report()!;
    expect(report.refused).toEqual([
      { reason: "invalid_record", streams: 1, rows: 3 },
    ]);
    const left = Object.values(report.rows.quarantined).reduce(
      (a, b) => a + b,
      0,
    );
    expect(report.rows.refused).toBe(3);
    expect(report.rows.legacy).toBe(
      report.rows.imported + left + report.rows.refused!,
    );
  }, 120_000);

  it("reports a row the fill-only rules keep out as blocked, not imported, and keeps the count across a restart", async () => {
    const base = await scratch("legacy-report-");
    directories.push(base);
    const root = join(base, "root");
    writeLegacyStore(root);
    addOtherInstances(root);
    const h = await direct(base, root);
    closers.push(h.close);
    await h.run();
    // One key is now deleted on this device (a tombstone, no row), and the
    // stream's receipt is gone: the next run stages it again, and the rules
    // keep it out.
    await h.local.batch([
      {
        sql: `INSERT INTO log_tombstones (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, rank)
              SELECT connection_id, stream, pk_hash, record_key, 1, 'z', 2 FROM records
               WHERE connection_id = 'pdpp.github~' AND stream = 'repositories' LIMIT 1`,
      },
      {
        sql: `DELETE FROM records WHERE rowid IN (SELECT rowid FROM records
               WHERE connection_id = 'pdpp.github~' AND stream = 'repositories' LIMIT 1)`,
      },
      { sql: "DELETE FROM import_ledger WHERE stream = 'repositories'" },
    ]);
    await h.run();
    const report = h.runner.report()!;
    const left = Object.values(report.rows.quarantined).reduce(
      (a, b) => a + b,
      0,
    );
    expect(report.rows.blocked).toBe(1);
    expect(report.rows.legacy).toBe(
      report.rows.imported + report.rows.blocked + left + report.rows.refused!,
    );
    // The receipt carries the count: a run that imports nothing new says the same.
    await h.run();
    expect(h.runner.report()!.rows).toEqual(report.rows);
  }, 120_000);

  it("publishes one report per run, after retirement: files are never null beside a finished report", async () => {
    const base = await scratch("legacy-report-");
    directories.push(base);
    const root = join(base, "root");
    writeLegacyStore(root);
    const seen: Array<{ at: string; report: unknown }> = [];
    const watch: { read?: () => unknown } = {};
    const h = await direct(base, root, {
      onLog: (message) => {
        if (message.startsWith("legacy"))
          seen.push({ at: message, report: watch.read?.() ?? null });
      },
    });
    watch.read = () => h.runner.report();
    closers.push(h.close);
    await h.run();
    // Import finished and every file was retired before anything was published.
    expect(seen.length).toBeGreaterThan(1);
    expect(seen.map((s) => s.report)).toEqual(seen.map(() => null));
    expect(h.runner.report()?.files).not.toBeNull();
  }, 120_000);

  it("keeps the previous report when a run is stopped while it retires", async () => {
    const base = await scratch("legacy-report-");
    directories.push(base);
    const root = join(base, "root");
    writeLegacyStore(root);
    const stop = new AbortController();
    const h = await direct(base, root, {
      onLog: (message) => {
        if (message === "legacy file retirement") stop.abort();
      },
    });
    closers.push(h.close);
    await h.run(stop.signal);
    expect(h.runner.report()).toBeNull();
  }, 120_000);

  it("keeps the last finished report when a later run stops early", async () => {
    const base = await scratch("legacy-report-");
    directories.push(base);
    const root = join(base, "root");
    writeLegacyStore(root);
    const h = await direct(base, root);
    closers.push(h.close);
    await h.run();
    const done = h.runner.report()!;
    const stopped = new AbortController();
    stopped.abort();
    await h.run(stopped.signal);
    expect(h.runner.report()).toBe(done);
  }, 120_000);
});
