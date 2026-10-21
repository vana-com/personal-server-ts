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

/** SQLite with every statement's returned rows, writes and SQL recorded. */
function countingSqlite(db = new Database(":memory:")) {
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
    const run = statement.run.bind(statement);
    const iterate = statement.iterate.bind(statement);
    return Object.assign(statement, {
      get: (...args: unknown[]) => count(get(...args)),
      run: (...args: unknown[]) => {
        const result = run(...args);
        work.statements += 1;
        work.sql.add(sql);
        work.rows += result.changes;
        return result;
      },
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
  for (let n = 0; n < 2_000; n++) {
    between();
    try {
      const page = sync.read({ ...base, cursor });
      seen.push(...page.data.map((r) => `${r.recordKey}=${r.data?.v}`));
      if (!page.nextCursor) {
        // Measures the last request too.
        between();
        return { seen, retries, checkpoint: page.nextChangesSince! };
      }
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
      // Rows read before each request belong to the request before it.
      work.rows = 0;
      const first = drain(sync, { ...request(), limit: 100 }, () => {
        perRequest.push(work.rows);
        work.rows = 0;
      });
      expect(first.seen).toHaveLength(2001);
      // A backlog: every key changes after the checkpoint.
      put(store, keys(2000), "2");
      for (let n = 0; n < 50; n++) put(store, ["hot"], `b${n}`);
      work.rows = 0;
      const next = drain(
        sync,
        { ...request(), limit: 100, changesSince: first.checkpoint },
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
        const first = drain(unbounded, { ...request(), limit: 100 });
        put(store, keys(500), "2");
        const growth: number[] = [];
        let last = 0;
        const bounded = createPdppSyncSessionService(store, {
          maxExaminedPerRequest: 50,
        });
        const resumed = drain(
          bounded,
          { ...request(), limit: 100, changesSince: first.checkpoint },
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
          ...request(),
          limit: 100,
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
        const first = drain(sync, { ...request(), limit: 100 });
        put(store, keys(300), "2");
        const session = {
          ...request(),
          limit: 100,
          changesSince: first.checkpoint,
        };
        expect(() => sync.read(session)).toThrow(SyncRetryLaterError);
        expect(store.inspectSyncState().candidates).toBeGreaterThan(0);
        // The client walks away; every state it left behind expires.
        now += 24 * 3_600_000;
        // Other sessions' writes sweep expired state in bounded steps.
        const other = createPdppSyncSessionService(store, { now: () => now });
        for (let n = 0; n < 20; n++)
          drain(other, { ...request(`other-${n}`, "owner-b"), limit: 100 });
        expect(store.inspectSyncState()).toMatchObject({ candidates: 0 });
        // Left: owner-b's 20 sessions of three pages (two live page handles
        // and a checkpoint each) and owner-a's first checkpoint, which lives
        // 30 days. The paused scan (it would make 62) and its preparation are
        // gone.
        expect(store.inspectSyncState()).toMatchObject({
          states: 61,
          preparations: 0,
        });
        // A retry of the abandoned request starts afresh and still completes.
        const retried = drain(sync, session);
        expect(retried.seen).toHaveLength(300);
      } finally {
        store.close();
      }
    });

    it("sweeps an orphaned paused scan once it expires", () => {
      const store = create();
      try {
        put(store, keys(50), "1");
        let now = 1_000_000;
        const sync = createPdppSyncSessionService(store, {
          maxExaminedPerRequest: 5,
          now: () => now,
        });
        // A first sync pauses and its client never retries.
        expect(() => sync.read({ ...request(), limit: 100 })).toThrow(
          SyncRetryLaterError,
        );
        expect(store.inspectSyncState().states).toBe(1);
        now += 11 * 60_000; // past the 10-minute paused-scan lifetime
        // Another session's write sweeps it.
        const other = createPdppSyncSessionService(store, { now: () => now });
        drain(other, { ...request("g2", "owner-b"), limit: 100 });
        // Only owner-b's checkpoint remains.
        expect(store.inspectSyncState().states).toBe(1);
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
        const one = drain(sync, { ...request("g1", "owner-a"), limit: 100 });
        const two = drain(sync, { ...request("g2", "owner-b"), limit: 100 });
        put(store, keys(200, "a"), "2");
        // Interleave the two incremental sessions request by request.
        const sessions = [
          {
            base: {
              ...request("g1", "owner-a"),
              limit: 100,
              changesSince: one.checkpoint,
            },
            seen: [] as string[],
            cursor: undefined as string | undefined,
            done: false,
          },
          {
            base: {
              ...request("g2", "owner-b"),
              limit: 100,
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
        const first = drain(sync, { ...request(), limit: 100 });
        put(store, keys(100), "2");
        expect(() =>
          sync.read({
            ...request(),
            limit: 100,
            changesSince: first.checkpoint,
          }),
        ).toThrow(CursorExpiredError);
        // A restart from beginning needs no prepared set.
        expect(drain(sync, { ...request(), limit: 100 }).seen).toHaveLength(
          100,
        );
      } finally {
        store.close();
      }
    });
  });

/** CPU time one call takes, in microseconds. */
function cpu(fn: () => void): number {
  const start = process.cpuUsage();
  fn();
  const used = process.cpuUsage(start);
  return used.user + used.system;
}

describe("sqlite physical sync work", () => {
  it("costs the same per request whatever one key's version count", () => {
    const perRequest = (versions: number) => {
      const store = createTestBoundRecordStore(
        new Database(":memory:"),
      ) as unknown as Inspectable;
      try {
        put(store, ["a"], "1");
        for (let n = 0; n < versions; n++) put(store, ["hot"], String(n));
        put(store, ["z"], "1");
        const sync = createPdppSyncSessionService(store, {
          maxExaminedPerRequest: 20,
        });
        const costs: number[] = [];
        let cursor: string | undefined;
        for (let n = 0; n < 10_000; n++) {
          let page;
          const used = cpu(() => {
            try {
              page = sync.read({ ...request(), limit: 1, cursor });
            } catch (err) {
              if (!(err instanceof SyncRetryLaterError)) throw err;
            }
          });
          costs.push(used);
          if (page) {
            cursor = (page as { nextCursor?: string }).nextCursor;
            if (!cursor) break;
          }
        }
        // The costliest request after the first, which also prepares the
        // store's statements: the one that walks past the hot key.
        return Math.max(...costs.slice(1));
      } finally {
        store.close();
      }
    };
    const few = perRequest(200);
    const many = perRequest(50_000);
    // 250 times the versions; a bounded request costs about the same.
    expect(many).toBeLessThan(few * 3);
  }, 120_000);
});

for (const backend of ["memory", "sqlite"])
  describe(`${backend} sync progress past what a grant does not read`, () => {
    const create = (): Inspectable =>
      (backend === "memory"
        ? createMemoryRecordStore()
        : createTestBoundRecordStore(
            new Database(":memory:"),
          )) as unknown as Inspectable;
    const write = (store: PdppRecordStore, instance: string, key: string) =>
      store.ingestBatch(
        [
          {
            instance,
            stream: "events",
            key,
            data: { id: key, v: "1" },
            emitted_at: "2026-01-01T00:00:00Z",
          },
        ],
        () => "mutable_state",
        () => ["id"],
      );

    for (const candidate of [false, true])
      it.each(["asc", "desc"] as const)(
        `finishes past long runs of another instance's keys (%s, ${candidate ? "candidate" : "current"})`,
        (order) => {
          const store = create();
          try {
            // Ten ungranted keys before, between and after the granted ones.
            for (const [prefix, granted] of [
              ["a", false],
              ["b", true],
              ["c", false],
              ["d", true],
              ["e", false],
            ] as const)
              for (let n = 0; n < 10; n++)
                write(
                  store,
                  granted ? "inst_1" : "inst_other",
                  `${prefix}${n}`,
                );
            const sync = createPdppSyncSessionService(store, {
              maxExaminedPerRequest: 2,
            });
            const base = {
              stream: "events",
              owner: "owner-a",
              instanceIds: ["inst_1"],
              limit: 100,
              ...(candidate && { candidate: { binding: "g", order } }),
            };
            const { seen } = drain(sync, base as never);
            expect(seen).toHaveLength(20);
          } finally {
            store.close();
          }
        },
      );

    it("charges the one-record-per-key check across many instances to the budget", () => {
      if (backend === "memory") return;
      const { store, work } = countingSqlite();
      try {
        const instances = Array.from({ length: 30 }, (_, i) => `inst_${i}`);
        for (const instance of instances)
          for (let n = 0; n < 5; n++)
            store.ingestBatch(
              [
                {
                  instance,
                  stream: "events",
                  key: `${instance}-k${n}`,
                  data: { id: `${instance}-k${n}` },
                  emitted_at: "2026-01-01T00:00:00Z",
                },
              ],
              () => "mutable_state",
              () => ["id"],
            );
        const sync = createPdppSyncSessionService(store, {
          maxExaminedPerRequest: 10,
        });
        // A probe that finds nothing returns no row: count statements.
        const perRequest: number[] = [];
        work.statements = 0;
        drain(
          sync,
          {
            stream: "events",
            owner: "o",
            instanceIds: instances,
            limit: 100,
            oneRecordPerKey: true,
          } as never,
          () => {
            perRequest.push(work.statements);
            work.statements = 0;
          },
        );
        expect(Math.max(...perRequest)).toBeLessThanOrEqual(5 * 10 + 60);
      } finally {
        store.close();
      }
    });

    it("refuses a finished preparation once it expires, even while a paused scan lives", () => {
      const store = create();
      try {
        put(store, keys(30), "1");
        const first = drain(createPdppSyncSessionService(store), {
          ...request(),
          limit: 100,
        });
        put(store, keys(30), "2");
        let now = 1_000_000;
        const sync = createPdppSyncSessionService(store, {
          now: () => now,
          pageTtlMs: 1_000,
          scanTtlMs: 600_000,
          maxExaminedPerRequest: 40,
        });
        const session = {
          ...request(),
          limit: 100,
          changesSince: first.checkpoint,
        };
        // Preparation finishes; the walk pauses with its scan saved.
        expect(() => sync.read(session)).toThrow(SyncRetryLaterError);
        now += 2_000; // the preparation has expired; the paused scan has not
        expect(() => sync.read(session)).toThrow(CursorExpiredError);
      } finally {
        store.close();
      }
    });
  });
