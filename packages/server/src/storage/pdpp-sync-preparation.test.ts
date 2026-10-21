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
  // micros: time spent inside SQLite statements, which excludes JavaScript
  // garbage collection and so tracks the store's own work.
  const work = { rows: 0, statements: 0, micros: 0, sql: new Set<string>() };
  const timed = <T>(fn: () => T): T => {
    const start = process.hrtime.bigint();
    try {
      return fn();
    } finally {
      work.micros += Number(process.hrtime.bigint() - start) / 1000;
    }
  };
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
      get: (...args: unknown[]) => count(timed(() => get(...args))),
      run: (...args: unknown[]) => {
        const result = timed(() => run(...args));
        work.statements += 1;
        work.sql.add(sql);
        work.rows += result.changes;
        return result;
      },
      all: (...args: unknown[]) => count(timed(() => all(...args))),
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
  for (let n = 0; n < 20_000; n++) {
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
    /** The most rows SQLite read or wrote in one request of each session. */
    const worst = (size: number) => {
      const { store, work } = countingSqlite();
      try {
        put(store, keys(size), "1");
        // One key with many versions.
        for (let n = 0; n < size / 20; n++) put(store, ["hot"], String(n));
        const sync = createPdppSyncSessionService(store, {
          maxExaminedPerRequest: 100,
        });
        const measure = (perRequest: number[]) => () => {
          perRequest.push(work.rows);
          work.rows = 0;
        };
        const firstSync: number[] = [];
        work.rows = 0;
        const first = drain(
          sync,
          { ...request(), limit: 100 },
          measure(firstSync),
        );
        expect(first.seen).toHaveLength(size + 1);
        // A backlog: every key changes after the checkpoint.
        put(store, keys(size), "2");
        for (let n = 0; n < size / 20; n++) put(store, ["hot"], `b${n}`);
        const backlog: number[] = [];
        work.rows = 0;
        const next = drain(
          sync,
          { ...request(), limit: 100, changesSince: first.checkpoint },
          measure(backlog),
        );
        expect(next.seen).toHaveLength(size + 1);
        expect(next.retries).toBeGreaterThan(size / 200);
        return {
          firstSync: Math.max(...firstSync),
          backlog: Math.max(...backlog),
        };
      } finally {
        store.close();
      }
    };
    const small = worst(1000);
    const large = worst(4000);
    // Four times the data; the costliest request stays the same size.
    expect(large.firstSync).toBeLessThanOrEqual(small.firstSync * 1.1 + 50);
    expect(large.backlog).toBeLessThanOrEqual(small.backlog * 1.1 + 50);
    // And within a fixed multiple of the budget plus one re-read page.
    expect(Math.max(large.firstSync, large.backlog)).toBeLessThanOrEqual(
      8 * 100 + 4 * 101,
    );
  }, 120_000);

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
        let last = store.inspectSyncState().candidates;
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
        // Left: owner-b's 20 sessions of three pages (two live page handles
        // and a checkpoint each) and owner-a's first checkpoint, which lives
        // 30 days; and owner-b's 20 live preparations of 300 keys each. The
        // abandoned paused scan (it would make 62 states) and its preparation
        // (21) are gone, with their candidates.
        expect(store.inspectSyncState()).toEqual({
          states: 61,
          preparations: 20,
          candidates: 20 * 300,
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

    it("refuses a session that would take the owner over its prepared-row cap, until older preparations expire", () => {
      const store = create();
      try {
        put(store, keys(100), "1");
        let now = 1_000_000;
        const sync = createPdppSyncSessionService(store, {
          maxPreparedRowsPerOwner: 150,
          now: () => now,
        });
        // The first sync holds 100 candidate rows for its page lifetime.
        const first = drain(sync, { ...request(), limit: 100 });
        put(store, keys(100), "2");
        const next = {
          ...request(),
          limit: 100,
          changesSince: first.checkpoint,
        };
        // 100 more would make 200: refused.
        expect(() => sync.read(next)).toThrow(CursorExpiredError);
        // Once the first sync's preparation expires, the owner has room.
        now += 2 * 3_600_000;
        expect(drain(sync, next).seen).toHaveLength(100);
      } finally {
        store.close();
      }
    });
  });

describe("sqlite physical sync work", () => {
  it("spends the same SQLite time per request whatever the keys' version counts", () => {
    /** Median SQLite time per request of one first sync. */
    const median = (versions: number) => {
      const { store, work } = countingSqlite();
      try {
        const hot = keys(100, "hot");
        put(store, hot, "0");
        for (let n = 1; n < versions; n++) put(store, hot, String(n));
        const sync = createPdppSyncSessionService(store, {
          maxExaminedPerRequest: 20,
        });
        const perRequest: number[] = [];
        work.micros = 0;
        drain(sync, { ...request(), limit: 100 }, () => {
          perRequest.push(work.micros);
          work.micros = 0;
        });
        // The median is immune to the rare scheduling or cache spike; a cost
        // that grows with version count shows in most requests.
        perRequest.sort((x, y) => x - y);
        return perRequest[Math.floor(perRequest.length / 2)]!;
      } finally {
        store.close();
      }
    };
    const few = median(2);
    const many = median(300);
    // 150 times the versions per key; a bounded request costs about the same.
    expect(many).toBeLessThan(few * 3 + 100);
  }, 180_000);
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

for (const backend of ["memory", "sqlite"])
  describe(`${backend} recovery after a preparation dies`, () => {
    const create = (): Inspectable =>
      (backend === "memory"
        ? createMemoryRecordStore()
        : createTestBoundRecordStore(
            new Database(":memory:"),
          )) as unknown as Inspectable;

    it("retires a paused scan whose preparation went over the row cap, so a restart starts fresh", () => {
      const store = create();
      try {
        put(store, keys(2, "x"), "1");
        let now = 1_000_000;
        const options = {
          maxPreparedRowsPerOwner: 3,
          pageTtlMs: 1_000,
          scanTtlMs: 600_000,
          now: () => now,
        };
        // Session X holds two candidate rows for its page lifetime.
        drain(createPdppSyncSessionService(store, options), {
          ...request("x"),
          limit: 100,
        });
        // Session A prepares one row (three in all) and pauses.
        const slow = createPdppSyncSessionService(store, {
          ...options,
          maxExaminedPerRequest: 1,
        });
        const a = { ...request("a"), limit: 100 };
        expect(() => slow.read(a)).toThrow(SyncRetryLaterError);
        // Its next row makes four: over the cap.
        expect(() => slow.read(a)).toThrow(CursorExpiredError);
        // X's preparation expires and frees its rows; A restarts from beginning.
        now += 2_000;
        expect(
          drain(createPdppSyncSessionService(store, options), a).seen,
        ).toHaveLength(2);
      } finally {
        store.close();
      }
    });
  });

describe("sync request scope", () => {
  it("refuses a request over more instances than one sync request serves", () => {
    const store = createMemoryRecordStore();
    try {
      const sync = createPdppSyncSessionService(store);
      expect(() =>
        sync.read({
          ...request(),
          instanceIds: Array.from({ length: 65 }, (_, i) => `inst_${i}`),
          limit: 10,
        }),
      ).toThrow(RangeError);
      // A candidate record carries its instance; the one-record-per-key
      // check belongs to the current profile alone.
      expect(() =>
        sync.read({ ...request(), limit: 10, oneRecordPerKey: true }),
      ).toThrow(RangeError);
    } finally {
      store.close();
    }
  });
});

describe("sqlite deterministic work per request", () => {
  /** The most rows plus statements one request of a first sync needs. */
  const worst = (
    fill: (store: PdppRecordStore) => void,
    instanceIds: string[],
  ) => {
    const { store, work } = countingSqlite();
    try {
      fill(store);
      const sync = createPdppSyncSessionService(store, {
        maxExaminedPerRequest: 20,
      });
      const perRequest: number[] = [];
      work.rows = 0;
      work.statements = 0;
      drain(
        sync,
        // The current profile: candidate records carry instance_id and
        // need no one-record-per-key check.
        {
          stream: "events",
          owner: "owner-a",
          instanceIds,
          limit: 100,
          oneRecordPerKey: true,
        } as never,
        () => {
          perRequest.push(work.rows + work.statements);
          work.rows = 0;
          work.statements = 0;
        },
      );
      return Math.max(...perRequest);
    } finally {
      store.close();
    }
  };
  const ingest = (
    store: PdppRecordStore,
    instance: string,
    key: string,
    v: string,
  ) =>
    store.ingestBatch(
      [
        {
          instance,
          stream: "events",
          key,
          data: { id: key, v },
          emitted_at: "2026-01-01T00:00:00Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
    );

  it("does not grow with one key's version count", () => {
    const versions = (n: number) => (store: PdppRecordStore) => {
      ingest(store, "inst_1", "a", "1");
      for (let i = 0; i < n; i++) ingest(store, "inst_1", "hot", String(i));
      ingest(store, "inst_1", "z", "1");
    };
    const few = worst(versions(10), ["inst_1"]);
    const many = worst(versions(20_000), ["inst_1"]);
    expect(many).toBeLessThanOrEqual(few + 10);
  }, 180_000);

  it("stays within the budget plus a fixed overhead as the instance scope grows", () => {
    const scope = (n: number) => {
      const instances = Array.from({ length: n }, (_, i) => `inst_${i}`);
      return {
        instances,
        fill: (store: PdppRecordStore) => {
          for (const instance of instances)
            for (let k = 0; k < 3; k++)
              ingest(store, instance, `${instance}-${k}`, "1");
        },
      };
    };
    const small = scope(2);
    const large = scope(64);
    const a = worst(small.fill, small.instances);
    const b = worst(large.fill, large.instances);
    // The budget is 20 units; each sibling probe is one statement. A request
    // may finish one identity past the budget: 64 instances of fixed overhead.
    expect(b).toBeLessThanOrEqual(a + 4 * 64 + 50);
  }, 180_000);
});

describe("sqlite sync scope with repeated instances", () => {
  it("reads a repeated instance once, however often the request names it", () => {
    const { store, work } = countingSqlite();
    try {
      for (const instance of ["inst_1", "inst_2"])
        store.ingestBatch(
          [
            {
              instance,
              stream: "events",
              key: `${instance}-k`,
              data: { id: `${instance}-k`, v: "1" },
              emitted_at: "2026-01-01T00:00:00Z",
            },
          ],
          () => "mutable_state",
          () => ["id"],
        );
      const sync = createPdppSyncSessionService(store, {
        maxExaminedPerRequest: 1,
      });
      const perRequest: number[] = [];
      work.statements = 0;
      const { seen } = drain(
        sync,
        {
          stream: "events",
          owner: "owner-a",
          instanceIds: ["inst_1", ...Array(10_000).fill("inst_2")],
          limit: 100,
          oneRecordPerKey: true,
        } as never,
        () => {
          perRequest.push(work.statements);
          work.statements = 0;
        },
      );
      expect(seen).toHaveLength(2);
      expect(Math.max(...perRequest)).toBeLessThanOrEqual(60);

      // limit 1 with room in the budget: each page buffers its extra row,
      // and the next page re-reads it against the same deduplicated scope.
      const paged = createPdppSyncSessionService(store, {
        maxExaminedPerRequest: 100,
      });
      const pages: number[] = [];
      work.statements = 0;
      const again = drain(
        paged,
        {
          stream: "events",
          owner: "owner-a",
          instanceIds: ["inst_1", ...Array(10_000).fill("inst_2")],
          limit: 1,
          oneRecordPerKey: true,
        } as never,
        () => {
          pages.push(work.statements);
          work.statements = 0;
        },
      );
      expect(again.seen).toHaveLength(2);
      expect(Math.max(...pages)).toBeLessThanOrEqual(60);
    } finally {
      store.close();
    }
  });
});
