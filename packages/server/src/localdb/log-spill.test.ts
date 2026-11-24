// What the log spills to disk must not stay reachable from memory. A spool
// holds a sealed object as rows; the handle the candidate keeps (`objects()`)
// names it and reads it back, and must not keep the bytes. The fold workspace
// holds a history as rows; after a segment or part is folded in, nothing of
// it may stay behind in the workspace object. Each test spills objects, drops
// the caller's references, forces a collection and asks a `WeakRef` for the
// object: a handle or a closure that still holds the bytes keeps it alive.
import vm from "node:vm";
import v8 from "node:v8";
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
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

v8.setFlagsFromString("--expose-gc");
const collect = vm.runInNewContext("gc") as () => void;

/** True once every object behind `refs` is collected: a macrotask, then a collection, until it is or 10 rounds pass. */
async function collected(refs: readonly WeakRef<object>[]): Promise<boolean> {
  for (let round = 0; round < 10; round++) {
    // A WeakRef target stays alive to the end of the job that made it.
    await new Promise((resolve) => setTimeout(resolve, 0));
    collect();
    if (refs.every((ref) => ref.deref() === undefined)) return true;
  }
  return false;
}

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
    const spool = openSpool(db, "c1", "op-1");
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
    const workspace = await openFoldWorkspace(db, "c1", "compact");
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
