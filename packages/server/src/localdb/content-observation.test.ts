// An unchanged refresh makes no new stream version and uploads no bytes; a
// changed record still re-uploads only its own part; and the newest
// observation still wins a conflict, whether or not the other surface had
// pulled yet. Real intake, real publish, real apply, two databases.
import { afterEach, describe, expect, it } from "vitest";
import {
  createLocalSync,
  connectionQueue,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import {
  MemoryStreamSyncRegistry,
  createMemoryStreamSyncBlobs,
} from "../../../core/src/stream-sync/index.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const owner = `0x${"12".repeat(20)}` as const;
const connection = "pdpp.fixture-source~";
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

type Row = { readonly id: string; readonly v: string };

/** Two surfaces over one registry and one store, counting what crosses the wire. */
async function world() {
  const registry = new MemoryStreamSyncRegistry();
  const store = createMemoryStreamSyncBlobs();
  const puts: string[] = [];
  const blobs: typeof store = {
    get: (key) => store.get(key),
    exists: (key) => store.exists(key),
    put: async (key, bytes) => {
      puts.push(key);
      return store.put(key, bytes);
    },
  };
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const publishLines: Record<string, unknown>[] = [];
  const surfaces = [];
  for (const name of ["desktop", "web", "phone"]) {
    const db = await openLocalDb(openBetterSqlite3(":memory:"), {
      owner,
      network: "test",
      deviceId: `${name}-device`,
    });
    drivers.push(db);
    let now = 1000;
    let op = 0;
    const deps: LocalSyncDeps = {
      db,
      queue: connectionQueue(),
      keys,
      registry,
      blobs,
      ownerAddress: owner,
      signer: { signAddData: async () => "0x00" },
      logger: {
        info: (line: Record<string, unknown>) => {
          if (typeof line.partsUploaded === "number") publishLines.push(line);
        },
        warn() {},
      },
      now: () => now,
      newOp: () => `${name}-${++op}`,
      partTargetBytes: 2048,
    };
    const sync = createLocalSync(deps, {
      resolveArtifact: () => ({
        connector: "fixture-source",
        version: "1",
        streams: [
          {
            name: "A",
            primaryKey: ["id"],
            coverageStrategy: "full_inventory",
            semantics: "mutable_state",
          },
        ],
      }),
      declaredStreams: () => ["A"],
      olderVersionReads: () => true,
    });
    /** One run that observes `rows` in full, then one sync cycle. */
    const refresh = async (
      id: string,
      at: number,
      rows: readonly Row[],
      options: {
        cycle?: boolean;
        /** FALSE: a partial run that proves nothing about records it does not list. */
        full?: boolean;
        /** Runs while this run is collecting: after its begin, before its rows. */
        during?: () => Promise<void>;
      } = {},
    ) => {
      now = at;
      await sync.intake.begin(id, {
        connector: "fixture-source",
        artifactDigest: "fixture",
        owner: { address: owner, leaseId: null },
        wantFull: options.full !== false,
        observedAt: at,
      });
      await options.during?.();
      if (rows.length)
        await sync.intake.batch(id, {
          batch: 0,
          records: rows.map((data) => ({ stream: "A", data })),
        });
      await sync.intake.end(id, {
        outcome: "succeeded",
        coveredStreams: ["A"],
        provenFullStreams: options.full === false ? [] : ["A"],
        lastBatch: rows.length ? 0 : -1,
      });
      if (options.cycle !== false) await cycle();
    };
    const cycle = async () => {
      const report = await sync.cycle();
      expect(report.connections.map((c) => c.error)).toEqual([null]);
    };
    const values = async (): Promise<Record<string, string>> => {
      const page = await sync.query.listRecords({
        connectionId: connection,
        stream: "A",
        limit: 1000,
      });
      return Object.fromEntries(
        page.records.map((r) => [r.recordKey, (JSON.parse(r.body) as Row).v]),
      );
    };
    const emittedAt = async (): Promise<Record<string, number>> => {
      const page = await sync.query.listRecords({
        connectionId: connection,
        stream: "A",
        limit: 1000,
      });
      return Object.fromEntries(
        page.records.map((r) => [r.recordKey, r.emittedAt]),
      );
    };
    surfaces.push({ db, sync, refresh, cycle, values, emittedAt });
  }
  const streamPosts = () =>
    registry.log.filter((post) => post.scope.includes("A")).length;
  return {
    desktop: surfaces[0]!,
    web: surfaces[1]!,
    phone: surfaces[2]!,
    registry,
    puts,
    publishLines,
    streamPosts,
  };
}

const rows = (count: number, v = "1"): Row[] =>
  Array.from({ length: count }, (_, i) => ({
    id: `row-${String(i).padStart(4, "0")}`,
    v,
  }));

describe("an unchanged refresh", () => {
  it("uploads no part, puts nothing, and makes no new stream version", async () => {
    const w = await world();
    await w.desktop.refresh("r1", 1000, rows(120));
    expect(w.publishLines.at(-1)).toMatchObject({ outcome: "published" });
    const posts = w.streamPosts();
    const puts = w.puts.length;
    const lines = w.publishLines.length;

    await w.desktop.refresh("r2", 2000, rows(120));

    expect(w.streamPosts()).toBe(posts);
    expect(w.puts).toHaveLength(puts);
    // A stream with nothing to publish logs no publish line, so no part went up.
    expect(
      w.publishLines
        .slice(lines)
        .reduce((n, l) => n + Number(l.partsUploaded), 0),
    ).toBe(0);
  });

  it("still reads as freshly collected on the device that collected it", async () => {
    const w = await world();
    await w.desktop.refresh("r1", 1000, rows(3));
    await w.desktop.refresh("r2", 2000, rows(3));
    expect(Object.values(await w.desktop.emittedAt())).toEqual([
      2000, 2000, 2000,
    ]);
  });

  it("is stable on a second device too: it applies nothing and posts nothing", async () => {
    const w = await world();
    await w.desktop.refresh("r1", 1000, rows(30));
    await w.web.sync.apply();
    await w.desktop.refresh("r2", 2000, rows(30));
    const posts = w.streamPosts();
    await w.web.cycle();
    expect(w.streamPosts()).toBe(posts);
    expect(await w.web.values()).toEqual(await w.desktop.values());
  });
});

describe("a change in the source", () => {
  it("re-uploads only the part that holds the changed record", async () => {
    const w = await world();
    await w.desktop.refresh("r1", 1000, rows(200));
    const first = w.publishLines.at(-1)!;
    expect(Number(first.partsUploaded)).toBeGreaterThan(2);
    const lines = w.publishLines.length;

    const next = rows(200);
    next[77] = { ...next[77]!, v: "changed" };
    await w.desktop.refresh("r2", 2000, next);

    const second = w.publishLines.slice(lines);
    expect(second).toHaveLength(1);
    expect(second[0]).toMatchObject({ outcome: "published", partsUploaded: 1 });
    await w.web.sync.apply();
    expect((await w.web.values())["row-0077"]).toBe("changed");
    expect((await w.web.values())["row-0076"]).toBe("1");
  });

  it("a record the source dropped is deleted here and on the other device", async () => {
    const w = await world();
    await w.desktop.refresh("r1", 1000, rows(10));
    await w.web.sync.apply();
    await w.desktop.refresh(
      "r2",
      2000,
      rows(10).filter((r) => r.id !== "row-0003"),
    );
    expect(Object.keys(await w.desktop.values())).not.toContain("row-0003");
    await w.web.sync.apply();
    expect(Object.keys(await w.web.values())).toHaveLength(9);
    expect(Object.keys(await w.web.values())).not.toContain("row-0003");
  });
});

describe("the newest observation wins a conflict whether or not the other surface had pulled", () => {
  const one = (v: string): Row[] => [{ id: "k", v }];

  it("an unchanged re-observation made before the edit was pulled still beats the edit", async () => {
    const w = await world();
    await w.desktop.refresh("r1", 1000, one("X")); // Desktop observes X at t1
    await w.web.sync.apply();
    await w.web.refresh("w2", 2000, one("Y")); // Web edits to Y at t2
    // Desktop has not pulled Y. Upstream still says X at t3.
    await w.desktop.refresh("r3", 3000, one("X"));
    await w.web.sync.apply();
    expect(await w.desktop.values()).toEqual({ k: "X" });
    expect(await w.web.values()).toEqual({ k: "X" });
  });

  it("gives the same result when Desktop had already pulled the edit", async () => {
    const w = await world();
    await w.desktop.refresh("r1", 1000, one("X"));
    await w.web.sync.apply();
    await w.web.refresh("w2", 2000, one("Y"));
    await w.desktop.sync.apply(); // Desktop pulls Y first
    await w.desktop.refresh("r3", 3000, one("X"));
    await w.web.sync.apply();
    expect(await w.desktop.values()).toEqual({ k: "X" });
    expect(await w.web.values()).toEqual({ k: "X" });
  });

  it("a later edit beats an earlier unchanged observation", async () => {
    const w = await world();
    await w.desktop.refresh("r1", 1000, one("X"));
    await w.desktop.refresh("r2", 2000, one("X"), { cycle: false }); // seen, not yet synced
    await w.web.sync.apply();
    await w.web.refresh("w3", 3000, one("Y"));
    await w.desktop.cycle();
    await w.web.sync.apply();
    expect(await w.desktop.values()).toEqual({ k: "Y" });
    expect(await w.web.values()).toEqual({ k: "Y" });
  });
});

describe("a refresh that omits a record is an observation of its absence", () => {
  const both: Row[] = [
    { id: "k", v: "X" },
    { id: "z", v: "1" },
  ];
  const without: Row[] = [{ id: "z", v: "1" }];

  it("a newer unchanged observation, made while the omission landed, keeps the record", async () => {
    const w = await world();
    await w.desktop.refresh("r1", 1000, both); // both devices hold k@t1
    await w.web.sync.apply();
    // Desktop's run begins (it has pulled everything so far). While it collects,
    // Web's full refresh omits k at t2. The source still lists k at t3.
    await w.desktop.refresh("r3", 3000, both, {
      during: async () => {
        await w.web.refresh("w2", 2000, without);
      },
    });
    await w.web.sync.apply();
    expect(Object.keys(await w.desktop.values()).sort()).toEqual(["k", "z"]);
    expect(Object.keys(await w.web.values()).sort()).toEqual(["k", "z"]);
  });

  it("an omission newer than the unchanged observation deletes the record", async () => {
    const w = await world();
    await w.desktop.refresh("r1", 1000, both);
    await w.web.sync.apply();
    await w.desktop.refresh("r2", 2000, both, {
      during: async () => {
        await w.web.refresh("w3", 3000, without);
      },
    });
    await w.web.sync.apply();
    expect(Object.keys(await w.desktop.values())).toEqual(["z"]);
    expect(Object.keys(await w.web.values())).toEqual(["z"]);
  });

  it("a partial run published with the omitting refresh does not widen the omission", async () => {
    const w = await world();
    await w.desktop.refresh("r1", 1000, both);
    await w.web.sync.apply();
    // Desktop's run has begun. While it collects, Web holds a full refresh that
    // omits k at t2 and a later partial run at t4, and publishes them as ONE
    // head whose observedAt is t4. The source still lists k at t3, newer than
    // the omission and older than the head's observedAt.
    await w.desktop.refresh("r3", 3000, both, {
      during: async () => {
        await w.web.refresh("w2", 2000, without, { cycle: false });
        await w.web.refresh("w4", 4000, [{ id: "p", v: "1" }], { full: false });
      },
    });
    await w.web.sync.apply();
    expect(Object.keys(await w.desktop.values()).sort()).toEqual([
      "k",
      "p",
      "z",
    ]);
    expect(Object.keys(await w.web.values()).sort()).toEqual(["k", "p", "z"]);
  });

  it("the omission still deletes a record last observed before it, beside a later partial run", async () => {
    const w = await world();
    await w.desktop.refresh("r1", 1000, both);
    await w.web.sync.apply();
    await w.web.refresh("w2", 2000, without, { cycle: false });
    await w.web.refresh("w4", 4000, [{ id: "p", v: "1" }], { full: false });
    await w.desktop.sync.apply();
    expect(Object.keys(await w.desktop.values()).sort()).toEqual(["p", "z"]);
  });

  it("a publish from a device whose clock is behind does not lower the omission time", async () => {
    const w = await world();
    await w.desktop.refresh("r1", 1000, both); // all three hold k@t1
    await w.web.sync.apply();
    await w.phone.sync.apply();
    // Phone saw k again at t2.5 and has not published or pulled since.
    await w.phone.refresh("p2", 2500, both, { cycle: false });
    // Web's full refresh omits k at t3.
    await w.web.refresh("w3", 3000, without);
    // Desktop pulls that head, then publishes an unrelated record from a
    // partial run at t2, a clock behind the omission. The head's observedAt
    // is t2; the omission is still t3.
    await w.desktop.refresh("d4", 2000, [{ id: "p", v: "1" }], { full: false });
    // Phone's sighting (t2.5) is older than the omission (t3): k is deleted.
    await w.phone.sync.apply();
    expect(Object.keys(await w.phone.values()).sort()).toEqual(["p", "z"]);
    await w.phone.cycle();
    await w.web.sync.apply();
    await w.desktop.sync.apply();
    expect(Object.keys(await w.web.values()).sort()).toEqual(["p", "z"]);
    expect(Object.keys(await w.desktop.values()).sort()).toEqual(["p", "z"]);
  });
});
