/**
 * The delete gates, on the synthetic store (see `synthetic-fixture.ts`):
 * five legacy scopes; three should go (large, small, fenced), one is tampered
 * and one is empty. Every test runs the production `retireLegacyFiles`.
 */

import { OWNER } from "./retire-rig.js";
import { describe, expect, it } from "vitest";
import { createMemoryStreamSyncFiles } from "../../stream-sync/memory-files.js";
import { createRetireHost } from "./host.js";
import { LegacyImporter } from "./import.js";
import { createMemoryImportAuthority } from "./import-authority.js";
import { RetireLedger } from "./ledger.js";
import { readbackVersion } from "./readback.js";
import { retireLegacyFiles } from "./retire.js";
import { buildSyntheticFixture } from "./synthetic-fixture.js";

async function setup(
  options: { importFirst?: boolean; fullRun?: boolean } = {},
) {
  const fx = await buildSyntheticFixture();
  const ledger = new RetireLedger(
    createMemoryStreamSyncFiles(),
    OWNER,
    createMemoryImportAuthority(),
  );
  const host = createRetireHost({
    reader: fx.reader,
    writer: { fullRunSince: async () => options.fullRun ?? true },
    ledger,
  });
  if (options.importFirst !== false) {
    await new LegacyImporter({
      source: fx.source,
      sink: { stage: async (_c, _s, rows) => (await drain(rows)).length },
      ledger,
      owner: OWNER,
      switched: () => true,
    }).run();
  }
  const scopesLeft = () => fx.storage.entries.map((e) => e.scope).sort();
  return { fx, ledger, host, scopesLeft };
}

async function drain(rows: AsyncIterable<unknown>) {
  const out: unknown[] = [];
  for await (const row of rows) out.push(row);
  return out;
}

describe("retire gates", () => {
  it("deletes exactly the files whose readback passed (RETIRE_WITHOUT_READBACK, READBACK_COUNT_ONLY, VACUOUS_RETIRE)", async () => {
    const { fx, ledger, host, scopesLeft } = await setup();
    const report = await retireLegacyFiles({
      storage: fx.storage,
      host,
      ledger,
      deleteEnabled: true,
    });
    expect(report.mode).toBe("delete");
    expect(report.deleted).toBe(3);
    // Kept: the file whose stream copy differs in one record body (a count
    // alone would pass it) and the file that holds nothing (never covered).
    expect(scopesLeft()).toEqual([
      "chatgpt.conversations",
      "icloud_notes.folders",
    ]);
  });

  it("deletes nothing while the delete flag is off, whatever the readback says (RETIRE_FLAG_IGNORED)", async () => {
    const { fx, ledger, host, scopesLeft } = await setup();
    const before = scopesLeft();
    const report = await retireLegacyFiles({
      storage: fx.storage,
      host,
      ledger,
      deleteEnabled: false,
    });
    expect(report.mode).toBe("readback-only");
    expect(report.deleted).toBe(0);
    expect(scopesLeft()).toEqual(before);
    // The readbacks still ran and were stored.
    expect(report.files.filter((f) => f.readback === "pass")).toHaveLength(3);
    expect(Object.keys((await ledger.read()).readbacks)).toHaveLength(5);
  });

  it("a dry run deletes nothing even with the flag on, and reports the same decisions (DRYRUN_DELETES)", async () => {
    const dry = await setup();
    const live = await setup();
    const before = dry.scopesLeft();
    const dryReport = await retireLegacyFiles({
      storage: dry.fx.storage,
      host: dry.host,
      ledger: dry.ledger,
      deleteEnabled: true,
      dryRun: true,
    });
    const liveReport = await retireLegacyFiles({
      storage: live.fx.storage,
      host: live.host,
      ledger: live.ledger,
      deleteEnabled: true,
    });
    expect(dryReport.mode).toBe("dry-run");
    expect(dryReport.deleted).toBe(0);
    expect(dry.scopesLeft()).toEqual(before);
    expect(dryReport.files).toEqual(liveReport.files);
  });

  it("keeps every file until this device's import ran, even with a passing stored readback (RETIRE_BEFORE_IMPORT)", async () => {
    const { fx, ledger, host, scopesLeft } = await setup({
      importFirst: false,
    });
    // A readback proved earlier for every file (as if a previous process ran
    // it); the import marker is the only thing missing.
    for (const row of fx.storage.entries.slice()) {
      await readbackVersion(
        { storage: fx.storage, view: host, ledger },
        row.scope,
        row,
      );
    }
    const before = scopesLeft();
    const report = await retireLegacyFiles({
      storage: fx.storage,
      host,
      ledger,
      deleteEnabled: true,
    });
    expect(report.deleted).toBe(0);
    expect(scopesLeft()).toEqual(before);
    expect(new Set(report.files.map((f) => f.decision))).toEqual(
      new Set(["no_import"]),
    );
  });

  it("does not read a file back before the import (a readback then would fail for a reason the import fixes)", async () => {
    const { fx, ledger, host } = await setup({ importFirst: false });
    await retireLegacyFiles({
      storage: fx.storage,
      host,
      ledger,
      deleteEnabled: true,
    });
    expect((await ledger.read()).readbacks).toEqual({});
  });

  it("keeps a fenced file until a full run re-collected the stream (DEVICE_ONLY_RETIRED_EARLY)", async () => {
    const { fx, ledger, host, scopesLeft } = await setup({ fullRun: false });
    const report = await retireLegacyFiles({
      storage: fx.storage,
      host,
      ledger,
      deleteEnabled: true,
    });
    const fenced = report.files.find((f) => f.scope === "instagram.following")!;
    expect(fenced.readback).toBe("pass");
    expect(fenced.decision).toBe("fence_not_recollected");
    expect(scopesLeft()).toContain("instagram.following");
    expect(report.deleted).toBe(2);
  });

  it("names the exact version it read back in every delete (UNFENCED_DELETE)", async () => {
    const { fx, ledger, host } = await setup();
    const calls: {
      scope: string;
      fence: { id: number; path: string; contentHash?: string } | undefined;
    }[] = [];
    const rows = new Map(fx.storage.entries.map((e) => [e.scope, e]));
    const storage = {
      ...fx.storage,
      deleteVersion: (
        scope: string,
        at: string,
        fence?: { id: number; path: string; contentHash?: string },
      ) => {
        calls.push({ scope, fence });
        return fx.storage.deleteVersion(scope, at, fence);
      },
    } as typeof fx.storage;
    await retireLegacyFiles({ storage, host, ledger, deleteEnabled: true });
    expect(calls).toHaveLength(3);
    for (const call of calls) {
      const row = rows.get(call.scope)!;
      expect(call.fence).toEqual({
        id: row.id,
        path: row.path,
        contentHash: expect.stringMatching(/^[0-9a-f]{64}$/),
      });
    }
  });
});
