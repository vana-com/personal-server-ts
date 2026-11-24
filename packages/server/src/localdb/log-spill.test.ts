// What the log spills to disk must not stay reachable from memory. A spool
// holds a sealed object as rows; the handle the candidate keeps (`objects()`)
// names it and reads it back, and must not keep the bytes. The fold workspace
// holds a history as rows; after a segment or part is folded in, nothing of
// it may stay behind in the workspace object. Each test spills objects, drops
// the caller's references, forces a collection and asks a `WeakRef` for the
// object: a handle or a closure that still holds the bytes keeps it alive.
import { afterEach, describe, expect, it } from "vitest";
import {
  LOG_FORMAT,
  type Segment,
  type WireOperation,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  openLocalDb,
  type SqlDriver,
} from "../../../core/src/localdb/index.js";
import { openFoldWorkspace } from "../../../core/src/localdb/log-fold-workspace.js";
import { openSpool, type Spool } from "../../../core/src/localdb/log-spool.js";
import { publishLog } from "../../../core/src/localdb/log-publish.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { collected, liveBytes } from "./gc.test-utils.js";
import {
  CONNECTION_ID,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

const ID = { owner: "0xAbC", network: "moksha", deviceId: "dev-1" };

describe("spilled bytes are not reachable from memory", () => {
  const open: SqlDriver[] = [];
  afterEach(async () => {
    for (const d of open.splice(0)) await d.close().catch(() => undefined);
  });
  const database = async () => {
    const db = await openLocalDb(openBetterSqlite3(":memory:"), ID);
    open.push(db);
    return db;
  };

  /** Seals `n` objects of `size` bytes into `spool`; returns weak refs to the ciphertexts and no strong ones. */
  async function spill(spool: Spool, n: number, size: number) {
    const refs: WeakRef<object>[] = [];
    for (let i = 0; i < n; i++) {
      const cipher = new Uint8Array(size).fill(i + 1);
      refs.push(new WeakRef(cipher));
      await spool.add(`v-${i}`, cipher);
    }
    return refs;
  }

  it("a spool's handles do not keep the sealed objects", async () => {
    const db = await database();
    const spool = openSpool(db, "c1");
    const refs = await spill(spool, 6, 1_500_000);
    expect(await collected(refs)).toBe(true);
    // The handles are alive and read the bytes back from the rows.
    const objects = spool.objects();
    expect(objects).toHaveLength(6);
    for (const [i, object] of objects.entries()) {
      expect(object.bytes).toBe(1_500_000);
      const read = await object.read();
      expect(read.length).toBe(1_500_000);
      expect(read[0]).toBe(i + 1);
      expect(read[1_499_999]).toBe(i + 1);
    }
  });

  it("a workspace does not keep the history folded into it", async () => {
    const db = await database();
    const workspace = await openFoldWorkspace(db, "c1");
    const fold = async () => {
      const refs: WeakRef<object>[] = [];
      const operations: WireOperation[] = [];
      for (let i = 0; i < 4; i++) {
        const value = { id: i, text: "x".repeat(600_000) };
        refs.push(new WeakRef(value));
        operations.push({
          kind: "upsert",
          stream: "s",
          pkHash: String(i).repeat(64).slice(0, 64),
          stamp: { o: 1, r: "run" },
          firstSeen: null,
          value,
        });
      }
      const segment: Segment<WireOperation> = {
        format: LOG_FORMAT,
        connector: "k",
        ns: "",
        generation: 1,
        keyCheck: "k",
        position: 1,
        observedAt: 1,
        base: 0,
        snapshot: null,
        refs: [],
        streams: [
          {
            stream: "s",
            primaryKey: ["id"],
            profile: { key: null, version: "1" },
            complete: true,
          },
        ],
        operations,
      };
      await workspace.addSegment(segment);
      return refs;
    };
    const refs = await fold();
    expect(await collected(refs)).toBe(true);
    // Still open and still holds what it folded.
    let entries = 0;
    for await (const page of workspace.pages()) entries += page.length;
    expect(entries).toBe(4);
    await workspace.close();
  });
});

describe("a publish round retains the references of the bodies it selects, not the bodies", () => {
  afterEach(closeWorldDrivers);

  // 60 records of 400 KB against a part target of 100 KB. Each counts as a few
  // hundred bytes of the round (`opSize`: its pieces are named, not carried),
  // so the round takes all 60: 24 MB of bodies. A planner that keeps the
  // bodies until the segment is built holds all of them at once; one that
  // seals the pieces into the spool as it selects a record holds one.
  const TARGET = 100_000;
  const RECORDS = 60;
  const PAD = 400_000;

  /** A database that measures what the process holds each time a sealed piece is written to the spool. */
  const sampling = (inner: SqlDriver, peak: { bytes: number }) =>
    ({
      ...inner,
      batch: async (statements: Parameters<SqlDriver["batch"]>[0]) => {
        const result = await inner.batch(statements);
        if (statements.some((s) => s.sql.includes("INSERT INTO log_spool")))
          peak.bytes = Math.max(peak.bytes, liveBytes());
        return result;
      },
    }) as SqlDriver;

  for (const full of [false, true])
    it(`${full ? "a replacing run (the whole stream is read at once)" : "an ordinary run"} of ${RECORDS} bodies above the part target stays well under their size`, async () => {
      const peak = { bytes: 0 };
      const w = await world({
        streams: 1,
        partTargetBytes: TARGET,
        database: (deviceId) =>
          deviceId === "a"
            ? sampling(openBetterSqlite3(":memory:"), peak)
            : openBetterSqlite3(":memory:"),
      });
      const a = await w.device("a");
      await a.run(
        "r1",
        Array.from({ length: RECORDS }, (_, i) => ({
          stream: sName(0),
          id: `k${i}`,
          pad: PAD,
        })),
        { full },
      );
      const before = liveBytes();
      await publishLog(a.deps, CONNECTION_ID);
      const retained = peak.bytes - before;
      expect(peak.bytes).toBeGreaterThan(0);
      // The bodies are 24 MB; one body and one batch of reads are a few MB (about 2 MB measured).
      expect(retained).toBeLessThan(8 * 1024 * 1024);
    }, 120_000);
});
