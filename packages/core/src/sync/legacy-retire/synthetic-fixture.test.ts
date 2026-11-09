/**
 * End to end on a synthetic real-shaped legacy store: import, readback, then a
 * dry run. All data is made up. The dry run must delete nothing; the per-file
 * report must match the outcome each scope was built for.
 */

import { OWNER } from "./retire-rig.js";
import { describe, expect, it } from "vitest";
import { createMemoryStreamSyncFiles } from "../../stream-sync/memory-files.js";
import type { ImportStream, LegacyImportSink } from "./import.js";
import { LegacyImporter } from "./import.js";
import { createMemoryImportAuthority } from "./import-authority.js";
import { RetireLedger } from "./ledger.js";
import { createRetireHost } from "./host.js";
import { retireLegacyFiles } from "./retire.js";
import {
  buildSyntheticFixture,
  LARGE_SCOPE_RECORDS,
} from "./synthetic-fixture.js";

const listing = (storage: {
  entries: readonly { id: number; scope: string; path: string }[];
}) => storage.entries.map((e) => `${e.id}|${e.scope}|${e.path}`).sort();

async function run(fullRun: boolean) {
  const fx = await buildSyntheticFixture();
  const ledger = new RetireLedger(
    createMemoryStreamSyncFiles(),
    OWNER,
    createMemoryImportAuthority(),
  );
  const staged: Record<string, number> = {};
  const sink: LegacyImportSink = {
    async stage(connector: string, stream: ImportStream, rows) {
      let count = 0;
      for await (const _ of rows) count += 1;
      staged[`${connector}/${stream.stream}`] = count;
      return count;
    },
  };
  const importer = new LegacyImporter({
    source: fx.source,
    sink,
    ledger,
    owner: OWNER,
    mode: () => "switched" as const,
  });
  const host = createRetireHost({
    reader: fx.reader,
    writer: { fullRunSince: async () => fullRun },
    ledger,
  });
  const before = listing(fx.storage);
  const imported = await importer.run();
  const report = await retireLegacyFiles({
    storage: fx.storage,
    host,
    ledger,
    deleteEnabled: true, // dry run wins over an enabled delete
    dryRun: true,
  });
  const after = listing(fx.storage);
  return { fx, ledger, staged, imported, report, before, after };
}

describe("dry run on a synthetic legacy store", () => {
  it("imports, reads back and reports per file, deleting nothing", async () => {
    const { fx, ledger, staged, imported, report, before, after } =
      await run(true);

    expect(imported).toEqual({ ran: true, connectorsStaged: 4, failed: 0 });
    expect(staged["chatgpt/memories"]).toBe(LARGE_SCOPE_RECORDS);
    expect(Object.keys(staged)).toHaveLength(6);

    expect(report.mode).toBe("dry-run");
    expect(report.deleted).toBe(0);
    expect(after).toEqual(before);
    expect(after).toHaveLength(fx.scopes.length);

    const byScope = new Map(report.files.map((f) => [f.scope, f]));
    const stored = (await ledger.read()).readbacks;
    const record = (scope: string) =>
      Object.values(stored).find((r) => r.scope === scope)!;

    for (const s of fx.scopes) {
      const file = byScope.get(s.scope)!;
      const rb = record(s.scope);
      expect(file.importDone).toBe(true);
      switch (s.expect) {
        case "pass":
          expect(file.readback).toBe("pass");
          expect(file.wouldDelete).toBe(true);
          // Every entity matched. A body's uncovered scalars (a fetch
          // time, a window) are compared too and count as entities.
          expect(rb.counts.local).toBeGreaterThanOrEqual(s.localEntities);
          expect(rb.counts).toEqual({
            local: rb.counts.local,
            matched: rb.counts.local,
            missing: 0,
            changed: 0,
          });
          expect(rb.fenced).toBe(0);
          break;
        case "fenced":
          // The fence dropped records; the stream was deleted and the
          // device re-collected it, so the file may go.
          expect(file.readback).toBe("pass");
          expect(rb.fenced).toBeGreaterThan(0);
          expect(rb.counts.changed).toBe(0);
          expect(file.wouldDelete).toBe(true);
          break;
        case "tampered":
          expect(file.readback).toBe("fail");
          expect(file.readbackReason).toBe("mismatch");
          expect(rb.counts.changed).toBe(1);
          expect(rb.counts.missing).toBe(0);
          expect(file.wouldDelete).toBe(false);
          break;
        case "empty":
          expect(file.readback).toBe("fail");
          expect(file.readbackReason).toBe("empty");
          expect(file.wouldDelete).toBe(false);
          break;
      }
    }

    const rows = fx.scopes.map((s) => {
      const file = byScope.get(s.scope)!;
      const rb = record(s.scope);
      return {
        scope: s.scope,
        local: rb.counts.local,
        matched: rb.counts.matched,
        missing: rb.counts.missing,
        changed: rb.counts.changed,
        fenced: rb.fenced,
        hash: rb.aggregate.slice(0, 8),
        readback: file.readback,
        decision: file.decision,
        wouldDelete: file.wouldDelete ? "yes" : "no",
      };
    });
    process.stderr.write(`DRY-RUN REPORT\n${table(rows)}\n`);
  });

  it("keeps the fenced file until the device re-collected the stream", async () => {
    const { report, after, before } = await run(false);
    const file = report.files.find((f) => f.scope === "instagram.following")!;
    expect(file.readback).toBe("pass");
    expect(file.decision).toBe("fence_not_recollected");
    expect(file.wouldDelete).toBe(false);
    expect(after).toEqual(before);
  });
});

function table(rows: Record<string, string | number | boolean>[]): string {
  const keys = Object.keys(rows[0]!);
  const width = keys.map((k) =>
    Math.max(k.length, ...rows.map((r) => String(r[k]).length)),
  );
  const line = (cells: string[]) =>
    cells.map((c, i) => c.padEnd(width[i]!)).join("  ");
  return [
    line(keys),
    line(width.map((w) => "-".repeat(w))),
    ...rows.map((r) => line(keys.map((k) => String(r[k])))),
  ].join("\n");
}
