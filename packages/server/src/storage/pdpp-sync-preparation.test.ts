/**
 * A sync request does bounded store work, however large the session's window.
 * An incremental session prepares its changed keys in bounded chunks into a
 * per-session candidate set, answers 429 until that set is ready, and then
 * pages through it. Preparations expire and are capped per owner.
 */
import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import {
  createMemoryRecordStore,
  createPdppSyncSessionService,
  SyncRetryLaterError,
  CursorExpiredError,
  type PdppRecordStore,
  type PdppSyncSessionService,
  type SyncSessionOptions,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createTestBoundRecordStore } from "../__fixtures__/bound-record-store.js";

type Inspectable = PdppRecordStore & {
  inspectSyncState(): {
    states: number;
    preparations: number;
    candidates: number;
  };
};

/** SQLite with every statement's returned rows and SQL recorded. */
function countingSqlite() {
  const db = new Database(":memory:");
  const work = { rows: 0, statements: 0, sql: new Set<string>() };
  const prepare = db.prepare.bind(db);
  db.prepare = ((sql: string) => {
    const statement = prepare(sql);
    const count = <T>(value: T): T => {
      work.statements += 1;
      work.sql.add(sql);
      if (Array.isArray(value)) work.rows += value.length;
      else if (value !== undefined) work.rows += 1;
      return value;
    };
    const get = statement.get.bind(statement);
    const all = statement.all.bind(statement);
    const iterate = statement.iterate.bind(statement);
    return Object.assign(statement, {
      get: (...args: unknown[]) => count(get(...args)),
      all: (...args: unknown[]) => count(all(...args)),
      iterate: function* (...args: unknown[]) {
        work.statements += 1;
        work.sql.add(sql);
        for (const row of iterate(...args)) {
          work.rows += 1;
          yield row;
        }
      },
    });
  }) as typeof db.prepare;
  const store = createTestBoundRecordStore(db) as unknown as Inspectable;
  return { db, store, work };
}

const request = (binding = "grant-1", owner = "owner-a") => ({
  stream: "events",
  owner,
  instanceIds: ["inst_1"],
  candidate: { binding, order: "asc" as const },
});

function put(store: PdppRecordStore, keys: string[], v: string) {
  store.ingestBatch(
    keys.map((key) => ({
      instance: "inst_1",
      stream: "events",
      key,
      data: { id: key, v },
      emitted_at: "2026-01-01T00:00:00Z",
    })),
    () => "mutable_state",
    () => ["id"],
  );
}

const keys = (n: number, prefix = "k") =>
  Array.from({ length: n }, (_, i) => `${prefix}${String(i).padStart(5, "0")}`);

/** Every page of one session, retrying 429s; counts the retries. */
function drain(
  sync: PdppSyncSessionService,
  base: ReturnType<typeof request> & { limit: number; changesSince?: string },
  between: () => void = () => {},
) {
  const seen: string[] = [];
  let retries = 0;
  let cursor: string | undefined;
  for (let n = 0; n < 10_000; n++) {
    between();
    try {
      const page = sync.read({ ...base, cursor });
      seen.push(...page.data.map((r) => `${r.recordKey}=${r.data?.v}`));
      if (!page.nextCursor)
        return { seen, retries, checkpoint: page.nextChangesSince! };
      cursor = page.nextCursor;
    } catch (err) {
      if (!(err instanceof SyncRetryLaterError)) throw err;
      retries += 1;
    }
  }
  throw new Error("never finished");
}

describe("sqlite bounded sync work", () => {
  it("never does unbounded store work in one request, for a first sync or a large backlog", () => {
    const { store, work } = countingSqlite();
    try {
      put(store, keys(2000), "1");
      // One key with thousands of versions.
      for (let n = 0; n < 50; n++) put(store, ["hot"], String(n));
      const options: SyncSessionOptions = { maxExaminedPerRequest: 100 };
      const sync = createPdppSyncSessionService(store, options);
      const perRequest: number[] = [];
      const first = drain(sync, { ...request(), limit: 1000 }, () => {
        perRequest.push(work.rows);
        work.rows = 0;
      });
      expect(first.seen).toHaveLength(2001);
      // A backlog: every key changes after the checkpoint.
      put(store, keys(2000), "2");
      for (let n = 0; n < 50; n++) put(store, ["hot"], `b${n}`);
      const next = drain(
        sync,
        { ...request(), limit: 1000, changesSince: first.checkpoint },
        () => {
          perRequest.push(work.rows);
          work.rows = 0;
        },
      );
      expect(next.seen).toHaveLength(2001);
      expect(next.retries).toBeGreaterThan(10);
      // Rows the store read per request stay within a small multiple of the
      // budget, whatever the window holds.
      expect(Math.max(...perRequest)).toBeLessThanOrEqual(5 * 100 + 50);
    } finally {
      store.close();
    }
  });

  it("plans every sync read as an index search, without a temporary sort", () => {
    const { db, store, work } = countingSqlite();
    try {
      put(store, keys(50), "1");
      const sync = createPdppSyncSessionService(store, {
        maxExaminedPerRequest: 10,
      });
      const first = drain(sync, { ...request(), limit: 5 });
      put(store, keys(50), "2");
      work.sql.clear();
      drain(sync, { ...request(), limit: 5, changesSince: first.checkpoint });
      const reads = [...work.sql].filter(
        (sql) =>
          /^\s*SELECT/i.test(sql) &&
          /pdpp_sync_candidate|pdpp_record_changes/.test(sql),
      );
      expect(reads.length).toBeGreaterThan(0);
      for (const sql of reads) {
        const args = (sql.match(/\?/g) ?? []).map(() => "x");
        const plan = (
          db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all(...args) as {
            detail: string;
          }[]
        )
          .map((row) => row.detail)
          .join("\n");
        expect(plan, sql).not.toMatch(/TEMP B-TREE/);
        expect(plan, sql).not.toMatch(
          /^SCAN (pdpp_record_changes|pdpp_sync_candidate)\b/m,
        );
      }
    } finally {
      store.close();
    }
  });
});

for (const backend of ["memory", "sqlite"])
  describe(`${backend} resumable sync preparation`, () => {
    const create = (): Inspectable =>
      (backend === "memory"
        ? createMemoryRecordStore()
        : createTestBoundRecordStore(
            new Database(":memory:"),
          )) as unknown as Inspectable;

    it("prepares a large backlog in bounded chunks and resumes it across requests", () => {
      const store = create();
      try {
        put(store, keys(500), "1");
        const unbounded = createPdppSyncSessionService(store);
        const first = drain(unbounded, { ...request(), limit: 1000 });
        put(store, keys(500), "2");
        const growth: number[] = [];
        let last = 0;
        const bounded = createPdppSyncSessionService(store, {
          maxExaminedPerRequest: 50,
        });
        const resumed = drain(
          bounded,
          { ...request(), limit: 1000, changesSince: first.checkpoint },
          () => {
            const now = store.inspectSyncState().candidates;
            growth.push(now - last);
            last = now;
          },
        );
        // Each request adds at most its budget of candidates.
        expect(Math.max(...growth)).toBeLessThanOrEqual(50);
        expect(resumed.retries).toBeGreaterThanOrEqual(10);
        // The result equals an unbudgeted session over the same window.
        const reference = drain(unbounded, {
          ...request("grant-ref", "owner-ref"),
          limit: 1000,
          changesSince: first.checkpoint,
        });
        expect(resumed.seen).toEqual(reference.seen);
        expect(resumed.seen).toHaveLength(500);
      } finally {
        store.close();
      }
    });

    it("expires a preparation abandoned mid-way and cleans up its paused scan and candidates", () => {
      const store = create();
      try {
        put(store, keys(300), "1");
        let now = 1_000_000;
        const sync = createPdppSyncSessionService(store, {
          maxExaminedPerRequest: 50,
          now: () => now,
        });
        const first = drain(sync, { ...request(), limit: 1000 });
        put(store, keys(300), "2");
        const session = {
          ...request(),
          limit: 1000,
          changesSince: first.checkpoint,
        };
        expect(() => sync.read(session)).toThrow(SyncRetryLaterError);
        expect(store.inspectSyncState().candidates).toBeGreaterThan(0);
        // The client walks away; every state it left behind expires.
        now += 24 * 3_600_000;
        // Other sessions' writes sweep expired state in bounded steps.
        const other = createPdppSyncSessionService(store, { now: () => now });
        for (let n = 0; n < 20; n++)
          drain(other, { ...request(`other-${n}`, "owner-b"), limit: 1000 });
        expect(store.inspectSyncState()).toMatchObject({ candidates: 0 });
        // Only owner-b's live checkpoints remain; the paused scan is gone.
        expect(store.inspectSyncState().states).toBeLessThanOrEqual(20);
        // A retry of the abandoned request starts afresh and still completes.
        const retried = drain(sync, session);
        expect(retried.seen).toHaveLength(300);
      } finally {
        store.close();
      }
    });

    it("keeps two concurrent sessions' preparations apart", () => {
      const store = create();
      try {
        put(store, keys(200, "a"), "1");
        const sync = createPdppSyncSessionService(store, {
          maxExaminedPerRequest: 30,
        });
        const one = drain(sync, { ...request("g1", "owner-a"), limit: 1000 });
        const two = drain(sync, { ...request("g2", "owner-b"), limit: 1000 });
        put(store, keys(200, "a"), "2");
        // Interleave the two incremental sessions request by request.
        const sessions = [
          {
            base: {
              ...request("g1", "owner-a"),
              limit: 1000,
              changesSince: one.checkpoint,
            },
            seen: [] as string[],
            cursor: undefined as string | undefined,
            done: false,
          },
          {
            base: {
              ...request("g2", "owner-b"),
              limit: 1000,
              changesSince: two.checkpoint,
            },
            seen: [] as string[],
            cursor: undefined as string | undefined,
            done: false,
          },
        ];
        for (let n = 0; n < 1000 && sessions.some((s) => !s.done); n++) {
          for (const s of sessions) {
            if (s.done) continue;
            try {
              const page = sync.read({ ...s.base, cursor: s.cursor });
              s.seen.push(
                ...page.data.map((r) => `${r.recordKey}=${r.data?.v}`),
              );
              s.cursor = page.nextCursor;
              s.done = !page.nextCursor;
            } catch (err) {
              if (!(err instanceof SyncRetryLaterError)) throw err;
            }
          }
        }
        const expected = keys(200, "a").map((k) => `${k}=2`);
        for (const s of sessions) {
          expect(s.done).toBe(true);
          expect(s.seen).toEqual(expected);
        }
      } finally {
        store.close();
      }
    });

    it("refuses a preparation over the owner's row cap; the client restarts from beginning", () => {
      const store = create();
      try {
        put(store, keys(100), "1");
        const sync = createPdppSyncSessionService(store, {
          maxPreparedRowsPerOwner: 50,
        });
        const first = drain(sync, { ...request(), limit: 1000 });
        put(store, keys(100), "2");
        expect(() =>
          sync.read({
            ...request(),
            limit: 1000,
            changesSince: first.checkpoint,
          }),
        ).toThrow(CursorExpiredError);
        // A restart from beginning needs no prepared set.
        expect(drain(sync, { ...request(), limit: 1000 }).seen).toHaveLength(
          100,
        );
      } finally {
        store.close();
      }
    });
  });
