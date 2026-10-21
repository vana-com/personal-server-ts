import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import {
  createMemoryRecordStore,
  createPdppSyncSessionService,
  SyncRetryLaterError,
  type PdppRecordStore,
  type PdppSyncSessionService,
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
              next: (direction, after, budget) => {
                const id = window.next(direction, after, budget);
                if (id) yielded += 1;
                return id;
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
        // Four units per page: 20 history rows to prepare and 20 identities
        // to walk, one unit each, take at least ten pages, every one empty.
        expect(pages).toBeGreaterThanOrEqual(10);
        take();
      } finally {
        store.close();
      }
    });
  });

for (const backend of ["memory", "sqlite"])
  describe(`${backend} candidate sync session state`, () => {
    const create = (): PdppRecordStore =>
      backend === "memory"
        ? createMemoryRecordStore()
        : createTestBoundRecordStore(new Database(":memory:"));
    const fill = (store: PdppRecordStore, keys: string[]) =>
      store.ingestBatch(
        keys.map((key) => ({
          instance: "inst_1",
          stream: "events",
          key,
          data: { id: key },
          emitted_at: "2026-01-01T00:00:00Z",
        })),
        () => "mutable_state",
        () => ["id"],
      );
    const request = {
      stream: "events",
      owner: "owner-a",
      instanceIds: ["inst_1"],
      candidate: { binding: "grant-1", order: "asc" as const },
    };
    /** Retries a request through SyncRetryLaterError. */
    function served(read: () => ReturnType<PdppSyncSessionService["read"]>) {
      for (let attempt = 0; attempt < 50; attempt++) {
        try {
          return read();
        } catch (err) {
          if (!(err instanceof SyncRetryLaterError)) throw err;
        }
      }
      throw new Error("never served");
    }

    it("writes session state only after the store's read has ended", () => {
      const store = create();
      try {
        fill(store, ["a", "b", "c"]);
        let reading = false;
        const states = store.syncStates();
        const guarded: PdppRecordStore = {
          ...store,
          readSyncWindow: (stream, window, read) =>
            store.readSyncWindow(stream, window, (w) => {
              reading = true;
              try {
                return read(w);
              } finally {
                reading = false;
              }
            }),
          syncStates: () => ({
            ...states,
            put: (entry) => {
              expect(reading).toBe(false);
              return states.put(entry);
            },
            delete: (id, expected) => {
              expect(reading).toBe(false);
              return states.delete(id, expected);
            },
          }),
        };
        const sync = createPdppSyncSessionService(guarded, {
          maxExaminedPerRequest: 1,
        });
        const first = served(() => sync.read({ ...request, limit: 1 }));
        const rest = served(() =>
          sync.read({ ...request, limit: 5, cursor: first.nextCursor }),
        );
        expect([...first.data, ...rest.data].map((r) => r.recordKey)).toEqual([
          "a",
          "b",
          "c",
        ]);
      } finally {
        store.close();
      }
    });

    it("makes progress on every retry even when its time budget is already spent", () => {
      const store = create();
      try {
        fill(store, ["a", "b", "c", "d"]);
        let now = 0;
        // Every clock read is ten seconds later: the deadline has always passed.
        const sync = createPdppSyncSessionService(store, {
          maxScanMillis: 1000,
          now: () => (now += 10_000),
        });
        const page = served(() => sync.read({ ...request, limit: 10 }));
        expect(page.data.map((r) => r.recordKey)).toEqual(["a", "b", "c", "d"]);
      } finally {
        store.close();
      }
    });

    it("lets no stale request overwrite newer scan progress or revive a finished scan", () => {
      const store = create();
      try {
        fill(store, ["a", "b", "c", "d", "e", "f"]);
        const states = store.syncStates();
        const writes: boolean[] = [];
        let interleave: (() => void) | undefined;
        const racing: PdppRecordStore = {
          ...store,
          readSyncWindow: (stream, window, read) =>
            store.readSyncWindow(stream, window, (w) => {
              // A second request runs to completion while this one reads.
              const other = interleave;
              interleave = undefined;
              other?.();
              return read(w);
            }),
          syncStates: () => ({
            ...states,
            put: (entry) => {
              const written = states.put(entry);
              if (entry.id.startsWith("scan:")) writes.push(written);
              return written;
            },
          }),
        };
        const sync = createPdppSyncSessionService(racing, {
          maxExaminedPerRequest: 2,
        });
        const limit = { ...request, limit: 10 };
        // Request 0 prepares all six keys, walks one and pauses.
        expect(() =>
          createPdppSyncSessionService(racing, {
            maxExaminedPerRequest: 8,
          }).read(limit),
        ).toThrow(SyncRetryLaterError);
        // Request A resumes it; meanwhile request B resumes the same scan and
        // finishes the session with a larger budget.
        const finisher = createPdppSyncSessionService(racing, {
          maxExaminedPerRequest: 100,
        });
        interleave = () => {
          expect(finisher.read(limit).data).toHaveLength(6);
        };
        expect(() => sync.read(limit)).toThrow(SyncRetryLaterError);
        // A's pause found the scan finished and wrote nothing.
        expect(writes).toEqual([true, false]);
        // So the next identical request starts a new session from the start.
        expect(finisher.read(limit).data.map((r) => r.recordKey)).toEqual([
          "a",
          "b",
          "c",
          "d",
          "e",
          "f",
        ]);
      } finally {
        store.close();
      }
    });
  });

describe("sqlite sync session state", () => {
  it("rejects a stale pause across two connections to one database", async () => {
    const { mkdtemp, rm } = await import("node:fs/promises");
    const { join } = await import("node:path");
    const { tmpdir } = await import("node:os");
    const dir = await mkdtemp(join(tmpdir(), "pdpp-sync-race-"));
    const path = join(dir, "records.db");
    const request = {
      stream: "events",
      owner: "owner-a",
      instanceIds: ["inst_1"],
      limit: 10,
      candidate: { binding: "grant-1", order: "asc" as const },
    };
    const one = createTestBoundRecordStore(new Database(path));
    const two = createTestBoundRecordStore(new Database(path));
    try {
      one.ingestBatch(
        ["a", "b", "c", "d", "e", "f"].map((key) => ({
          instance: "inst_1",
          stream: "events",
          key,
          data: { id: key },
          emitted_at: "2026-01-01T00:00:00Z",
        })),
        () => "mutable_state",
        () => ["id"],
      );
      let interleave: (() => void) | undefined;
      const racing: PdppRecordStore = {
        ...one,
        readSyncWindow: (stream, window, read) =>
          one.readSyncWindow(stream, window, (w) => {
            const other = interleave;
            interleave = undefined;
            other?.();
            return read(w);
          }),
      };
      const slow = createPdppSyncSessionService(racing, {
        maxExaminedPerRequest: 2,
      });
      const other = createPdppSyncSessionService(two, {
        maxExaminedPerRequest: 100,
      });
      // Request 0 prepares all six keys, walks one and pauses.
      expect(() =>
        createPdppSyncSessionService(one, {
          maxExaminedPerRequest: 8,
        }).read(request),
      ).toThrow(SyncRetryLaterError);
      // While connection one resumes the paused scan, connection two resumes
      // the same scan from the shared table and finishes the session.
      interleave = () => expect(other.read(request).data).toHaveLength(6);
      expect(() => slow.read(request)).toThrow(SyncRetryLaterError);
      // The stale pause wrote nothing: no paused scan is left to resume.
      const left = new Database(path, { readonly: true });
      try {
        expect(
          left
            .prepare(
              "SELECT COUNT(*) AS n FROM pdpp_sync_state WHERE id LIKE 'scan:%'",
            )
            .get(),
        ).toEqual({ n: 0 });
      } finally {
        left.close();
      }

      const fresh = createPdppSyncSessionService(two, {
        maxExaminedPerRequest: 100,
      });
      expect(fresh.read(request).data.map((r) => r.recordKey)).toEqual([
        "a",
        "b",
        "c",
        "d",
        "e",
        "f",
      ]);
    } finally {
      one.close();
      two.close();
      await rm(dir, { recursive: true, force: true });
    }
  });

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
