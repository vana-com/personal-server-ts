import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import { createScopeDeletionTracker } from "@opendatalabs/personal-server-ts-core/sync";
import { createScopeDeletionHistory } from "./scope-deletion-history.js";

const SCOPE = "oura.activity";
const TOMB = { deletedAt: "2026-09-11T00:00:00Z", version: null };

describe("durable scope deletion history", () => {
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
