import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import { createScopeDeletionTracker } from "@opendatalabs/personal-server-ts-core/sync";
import { resolveReadDeletion } from "@opendatalabs/personal-server-ts-core/api";
import { createScopeDeletionHistory } from "./scope-deletion-history.js";

const SCOPE = "oura.activity";
const TOMB = { deletedAt: "2026-09-11T00:00:00Z", version: null };

describe("durable scope deletion history", () => {
  it("retries a locked observation after a live feed and retains refusal on the same database restart", async () => {
    const dir = mkdtempSync(join(tmpdir(), "scope-deletion-history-busy-"));
    const path = join(dir, "index.db");
    const writer = new Database(path);
    writer.pragma("journal_mode = WAL");
    writer.pragma("busy_timeout = 0");
    const blocker = new Database(path);
    let reopened: Database.Database | undefined;
    try {
      const owner = `0x${"ab".repeat(20)}`;
      const history = createScopeDeletionHistory(writer, owner);
      let now = 0;
      const tracker = createScopeDeletionTracker({
        deletionHistory: history,
        serverOwner: owner,
        now: () => new Date(now),
        maxStalenessMs: 1,
        feed: {
          getDataPoint: async () => null,
          listDataPointsByOwner: async () => ({ dataPoints: [], cursor: null }),
        },
      });
      const deps = { scopeDeletions: tracker, serverOwner: owner };
      tracker.markLive(SCOPE);
      blocker.exec("BEGIN IMMEDIATE");
      expect(() => tracker.markDeleted(SCOPE, TOMB)).toThrow(
        expect.objectContaining({ code: "SQLITE_BUSY" }),
      );
      expect(tracker.knownDeletion(SCOPE)).toEqual(TOMB);
      // The retry is a real write attempt, and the failed fact stays pending.
      expect(() => tracker.noteFeedSynced()).toThrow(
        expect.objectContaining({ code: "SQLITE_BUSY" }),
      );
      expect(tracker.feedAgeMs()).toBeNull();
      expect(history.get(SCOPE)).toBeNull();
      expect(
        await resolveReadDeletion(deps, SCOPE, undefined, "canonical"),
      ).toMatchObject({ deletedAt: TOMB.deletedAt });

      tracker.markLive(SCOPE);
      now = 2;
      // A live gateway response also clears only current file state.
      expect(await tracker.resolve(SCOPE)).toMatchObject({ deleted: false });
      expect(
        await resolveReadDeletion(deps, SCOPE, undefined, "file"),
      ).toBeNull();
      expect(
        await resolveReadDeletion(deps, SCOPE, undefined, "canonical"),
      ).not.toBeNull();
      blocker.exec("ROLLBACK");
      tracker.noteFeedSynced(undefined, { full: true });
      expect(history.get(SCOPE)).toEqual(TOMB);
      writer.close();
      reopened = new Database(path);
      const restarted = createScopeDeletionTracker({
        deletionHistory: createScopeDeletionHistory(reopened, owner),
      });
      restarted.markLive(SCOPE);
      expect(
        await resolveReadDeletion(
          { scopeDeletions: restarted, serverOwner: owner },
          SCOPE,
          undefined,
          "canonical",
        ),
      ).toMatchObject({ deletedAt: TOMB.deletedAt });
    } finally {
      if (blocker.inTransaction) blocker.exec("ROLLBACK");
      blocker.close();
      if (writer.open) writer.close();
      reopened?.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("retains unknown-version observations across live state and a WAL database reopen", async () => {
    const dir = mkdtempSync(join(tmpdir(), "scope-deletion-history-"));
    const path = join(dir, "index.db");
    const writer = new Database(path);
    writer.pragma("journal_mode = WAL");
    const reader = new Database(path);
    try {
      const history = createScopeDeletionHistory(writer, "0xAbCd");
      const readHistory = createScopeDeletionHistory(reader, "0xabcd");
      const tracker = createScopeDeletionTracker({ deletionHistory: history });
      // A reader's existing snapshot stays coherent while another connection
      // records the deletion. The next transaction sees the durable fact.
      reader.transaction(() => {
        expect(readHistory.get(SCOPE)).toBeNull();
        tracker.markDeleted(SCOPE, TOMB);
        tracker.markLive(SCOPE);
        expect(readHistory.get(SCOPE)).toBeNull();
      })();
      expect(tracker.knownDeletion(SCOPE)).toBeNull();
      await expect(tracker.resolve(SCOPE)).resolves.toMatchObject({
        deleted: false,
      });
      expect(readHistory.get(SCOPE)).toEqual(TOMB);
      reader.close();
      writer.close();
      const reopened = new Database(path);
      try {
        const restarted = createScopeDeletionTracker({
          deletionHistory: createScopeDeletionHistory(reopened, "0xABCD"),
        });
        expect(restarted.deletionHistory?.get(SCOPE)).toEqual(TOMB);
      } finally {
        reopened.close();
      }
    } finally {
      if (reader.open) reader.close();
      if (writer.open) writer.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("partitions facts by owner, exact scope and database root", () => {
    const db = new Database(":memory:");
    const otherRoot = new Database(":memory:");
    try {
      const owner = createScopeDeletionHistory(db, "0xAbCd");
      owner.remember(SCOPE, TOMB);
      expect(createScopeDeletionHistory(db, "0xabcd").get(SCOPE)).toEqual(TOMB);
      expect(createScopeDeletionHistory(db, "0xother").get(SCOPE)).toBeNull();
      expect(owner.get("github.activity")).toBeNull();
      expect(owner.get("oura.readiness")).toBeNull();
      expect(
        createScopeDeletionHistory(otherRoot, "0xabcd").get(SCOPE),
      ).toBeNull();
    } finally {
      db.close();
      otherRoot.close();
    }
  });
});

it("durable deletion observations retain the exact maximum registry version across handles", () => {
  const db = new Database(":memory:");
  try {
    const a = createScopeDeletionHistory(db, "owner");
    const b = createScopeDeletionHistory(db, "owner");
    a.remember(SCOPE, {
      deletedAt: TOMB.deletedAt,
      version: "9007199254740995",
    });
    b.remember(SCOPE, {
      deletedAt: TOMB.deletedAt,
      version: "9007199254740993",
    });
    expect(a.get(SCOPE)?.version).toBe("9007199254740995");
    b.remember(SCOPE, TOMB);
    a.remember(SCOPE, {
      deletedAt: TOMB.deletedAt,
      version: "9007199254740997",
    });
    expect(a.get(SCOPE)?.version).toBeNull();
  } finally {
    db.close();
  }
});
