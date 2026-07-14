import type Database from "better-sqlite3";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { initializeDatabase } from "../storage/index-schema.js";
import { createIndexManager } from "../storage/index-manager.js";
import type { IndexManager } from "../storage/index-manager.js";
import {
  findStuckScopes,
  detectStuckVersionLedger,
} from "./detect-stuck-version-ledger.js";

function countRows(db: Database.Database, scope: string): number {
  return (
    db
      .prepare("SELECT COUNT(*) AS c FROM data_files WHERE scope = ?")
      .get(scope) as { c: number }
  ).c;
}

describe("detect-stuck-version-ledger", () => {
  let db: Database.Database;
  let index: IndexManager;
  let path = 0;

  function add(
    scope: string,
    opts: { version: number; dataPointId?: string | null },
  ): void {
    path += 1;
    index.insert({
      fileId: null,
      path: `${scope}/${path}.json`,
      scope,
      collectedAt: `2026-07-13T00:00:${String(path).padStart(2, "0")}Z`,
      sizeBytes: 10,
      version: opts.version,
      dataPointId: opts.dataPointId ?? null,
    });
  }

  beforeEach(() => {
    db = initializeDatabase(":memory:");
    index = createIndexManager(db);
    path = 0;
  });

  it("reports scopes with more than one pending row, with their pending counts", () => {
    add("spotify.savedTracks", { version: 3 });
    add("spotify.savedTracks", { version: 4 });
    add("spotify.savedTracks", { version: 5 });
    add("spotify.profile", { version: 1 }); // single pending — not stuck

    expect(findStuckScopes(db)).toEqual([
      { scope: "spotify.savedTracks", pendingRows: 3 },
    ]);
  });

  it("ignores a scope with a single pending row and synced history", () => {
    add("instagram.profile", { version: 1, dataPointId: "dp-1" });
    add("instagram.profile", { version: 2, dataPointId: "dp-2" });
    add("instagram.profile", { version: 3 }); // one in-flight pending row
    expect(findStuckScopes(db)).toEqual([]);
  });

  it("ignores a fully-synced scope (no pending rows)", () => {
    add("spotify.playlists", { version: 1, dataPointId: "dp-1" });
    add("spotify.playlists", { version: 2, dataPointId: "dp-2" });
    expect(findStuckScopes(db)).toEqual([]);
  });

  it("is strictly non-destructive: detection never mutates data_files", () => {
    add("a.stuck", { version: 4 });
    add("a.stuck", { version: 5 });
    add("b.ok", { version: 1, dataPointId: "dp-b" });

    const ctx = {
      db,
      storageRoot: "/tmp/unused",
      logger: { info: vi.fn(), warn: vi.fn() },
    };
    expect(detectStuckVersionLedger.check(ctx)).toBe(true);
    const result = detectStuckVersionLedger.run(ctx);

    // Nothing deleted, nothing renumbered.
    expect(countRows(db, "a.stuck")).toBe(2);
    expect(countRows(db, "b.ok")).toBe(1);
    expect(result.changed).toBe(false);
    expect(result.detail).toMatch(/detected 1 scope\(s\) with 2/);
    expect(ctx.logger.warn).toHaveBeenCalledTimes(1);
  });

  it("check() is false when nothing is stuck", () => {
    add("spotify.profile", { version: 1 });
    expect(
      detectStuckVersionLedger.check({ db, storageRoot: "/tmp/unused" }),
    ).toBe(false);
    expect(detectStuckVersionLedger.everyBoot).toBe(true);
  });
});
