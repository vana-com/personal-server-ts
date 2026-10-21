import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import {
  createMemoryRecordStore,
  createPdppSyncSessionService,
  type PdppRecordStore,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createTestBoundRecordStore } from "../__fixtures__/bound-record-store.js";

// Store work for one list or sync page must follow what the page needs, and
// time order must follow instants, not timestamp text.
for (const backend of ["memory", "sqlite"])
  describe(`${backend} record order and sync work`, () => {
    const create = (): PdppRecordStore =>
      backend === "memory"
        ? createMemoryRecordStore()
        : createTestBoundRecordStore(new Database(":memory:"));
    const put = (store: PdppRecordStore, key: string, emittedAt: string) =>
      expect(
        store.ingestBatch(
          [
            {
              instance: "inst_1",
              stream: "events",
              key,
              data: { id: key, v: emittedAt },
              emitted_at: emittedAt,
            },
          ],
          () => "mutable_state",
          () => ["id"],
        ).accepted,
      ).toBe(1);

    /** Counts the changes a store window hands the session service. */
    function counted(store: PdppRecordStore) {
      let yielded = 0;
      const spy: PdppRecordStore = {
        ...store,
        readSyncWindow: (stream, request, read) =>
          store.readSyncWindow(stream, request, (window) =>
            read({
              ...window,
              changes: (direction, after) => {
                const source = window.changes(direction, after);
                return (function* () {
                  for (const change of source) {
                    yielded += 1;
                    yield change;
                  }
                })();
              },
            }),
          ),
      };
      return {
        sync: createPdppSyncSessionService(spy),
        take: () => {
          const n = yielded;
          yielded = 0;
          return n;
        },
      };
    }

    // Chronological: c (23:30Z), d (23:45Z), a (00:00Z), b (00:00.1Z).
    const MIXED: Record<string, string> = {
      a: "2026-01-01T00:00:00Z",
      b: "2026-01-01T00:00:00.1Z",
      c: "2026-01-01T00:30:00+01:00",
      d: "2025-12-31T23:45:00Z",
    };

    it.each(["asc", "desc"] as const)(
      "F4 lists by instant across precision and offsets, page by page (%s)",
      (order) => {
        const store = create();
        try {
          for (const [key, at] of Object.entries(MIXED)) put(store, key, at);
          const seen: string[] = [];
          let cursor: string | undefined;
          do {
            const page = store.listRecords("events", {
              instanceIds: ["inst_1"],
              limit: 1,
              order,
              cursor,
            });
            seen.push(...page.data.map((row) => row.recordKey));
            cursor = page.nextCursor;
          } while (cursor);
          const chronological = ["c", "d", "a", "b"];
          expect(seen).toEqual(
            order === "asc" ? chronological : chronological.reverse(),
          );
        } finally {
          store.close();
        }
      },
    );

    it("F4 reports the latest instant as a stream's last update", () => {
      const store = create();
      try {
        for (const [key, at] of Object.entries(MIXED)) put(store, key, at);
        expect(store.listStreams(["inst_1"])).toEqual([
          { stream: "events", recordCount: 4, lastUpdated: MIXED.b },
        ]);
      } finally {
        store.close();
      }
    });

    it("F6 a quiet poll and a sparse change read only what changed", () => {
      const store = create();
      try {
        for (let n = 0; n < 200; n++)
          put(store, `k${String(n).padStart(3, "0")}`, "2026-01-01T00:00:00Z");
        const { sync, take } = counted(store);
        const base = { stream: "events", instanceIds: ["inst_1"] };
        let checkpoint: string | undefined;
        let cursor: string | undefined;
        do {
          const page = sync.read({ ...base, limit: 50, cursor });
          // A page pulls at most its items plus one look-ahead.
          expect(take()).toBeLessThanOrEqual(51);
          cursor = page.nextCursor;
          checkpoint = page.nextChangesSince ?? checkpoint;
        } while (cursor);
        const quiet = sync.read({
          ...base,
          limit: 50,
          changesSince: checkpoint,
        });
        expect(quiet.data).toEqual([]);
        expect(take()).toBe(0);
        put(store, "k100", "2026-01-02T00:00:00Z");
        const sparse = sync.read({
          ...base,
          limit: 50,
          changesSince: quiet.nextChangesSince,
        });
        expect(sparse.data.map((row) => row.recordKey)).toEqual(["k100"]);
        expect(take()).toBe(1);
      } finally {
        store.close();
      }
    });

    it("F6 the session budget bounds the changes one page examines", () => {
      const store = create();
      try {
        for (let n = 0; n < 20; n++)
          put(store, `k${String(n).padStart(2, "0")}`, "2026-01-01T00:00:00Z");
        const { take } = counted(store);
        const sync = createPdppSyncSessionService(store, {
          maxExaminedPerRequest: 4,
        });
        const hidden = {
          stream: "events",
          instanceIds: ["inst_1"],
          limit: 10,
          access: { canSeeKey: () => false, canSeeRecord: () => false },
        };
        let pages = 0;
        let cursor: string | undefined;
        do {
          const page = sync.read({ ...hidden, cursor });
          expect(page.data).toEqual([]);
          pages += 1;
          cursor = page.nextCursor;
        } while (cursor);
        // Four examined per page. The fifth page reaches the budget before it
        // can see the end, so a sixth, empty page ends the session.
        expect(pages).toBe(6);
        take();
      } finally {
        store.close();
      }
    });
  });

describe("sqlite sync session state", () => {
  it("keeps a candidate checkpoint usable across a store restart", async () => {
    const { mkdtemp, rm } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const { tmpdir } = await import("node:os");
    const dir = await mkdtemp(join(tmpdir(), "pdpp-sync-state-"));
    const path = join(dir, "records.db");
    const request = {
      stream: "events",
      owner: "owner-a",
      instanceIds: ["inst_1"],
      limit: 10,
      candidate: { binding: "grant-1", order: "asc" as const },
    };
    try {
      const first = createTestBoundRecordStore(new Database(path));
      first.ingestBatch(
        [
          {
            instance: "inst_1",
            stream: "events",
            key: "a",
            data: { id: "a" },
            emitted_at: "2026-01-01T00:00:00Z",
          },
        ],
        () => "mutable_state",
        () => ["id"],
      );
      const checkpoint =
        createPdppSyncSessionService(first).read(request).nextChangesSince!;
      first.close();

      const second = createTestBoundRecordStore(new Database(path));
      try {
        const next = createPdppSyncSessionService(second).read({
          ...request,
          changesSince: checkpoint,
        });
        expect(next.data).toEqual([]);
        expect(next.nextChangesSince).toHaveLength(checkpoint.length);
      } finally {
        second.close();
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
