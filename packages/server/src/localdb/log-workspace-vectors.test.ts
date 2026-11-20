import { afterEach, expect, it } from "vitest";
import { rebaseOnLog } from "../../../core/dist/localdb/log-rebase.js";
import { readLogState } from "../../../core/dist/localdb/log-state.js";
import { nobleStreamCrypto } from "../../../core/dist/stream-sync/crypto-port.js";
import {
  deriveKeyCheck,
  controlHashes,
} from "../../../stream-sync/src/index.js";
import {
  world,
  closeWorldDrivers,
  CONNECTION_ID,
  LOG,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

it("replacement fragments preserve typed tombstones, first seen and completion with escaped string keys and referenced bodies", async () => {
  const w = await world({ streams: 1, partTargetBytes: 3000 });
  const reader = await w.device("reader");
  let armed = false,
    puts = 0,
    midwayComplete: number | null = null;
  let midwayRows: string[] | null = null;
  const a = await w.device("a", {
    beforePut: async (key) => {
      if (!armed || !key.startsWith(`${LOG}/s-`) || ++puts !== 2) return;
      await reader.cycle();
      midwayRows = await reader.rows();
      midwayComplete = (
        await reader.db.query<{ complete: number }>(
          "SELECT complete FROM stream_state WHERE stream='s0'",
        )
      )[0]!.complete;
    },
  });
  const ids = Array.from(
    { length: 120 },
    (_, i) => `id-${String(i).padStart(3, "0")}-"é\\${"k".repeat(40)}`,
  );
  await a.run(
    "initial",
    ids.map((id) => ({ stream: "s0", id, v: 1 })),
    { observedAt: 1100 },
  );
  await a.cycle();
  await a.run("explicit", [{ stream: "s0", id: ids.at(-1)!, remove: true }], {
    full: false,
    observedAt: 1200,
  });
  await a.cycle();
  await reader.cycle();
  const before = await a.position();
  armed = true;
  const kept = ids.slice(0, 2);
  await a.run(
    "replace",
    kept.map((id) => ({ stream: "s0", id, v: 2, pad: 10000 })),
    { observedAt: 1300 },
  );
  await a.cycle();
  const all = [...(await w.segments()).values()].sort(
    (a, b) => a.position - b.position,
  );
  const fragments = all.filter((g) => g.position > before);
  expect(fragments.length).toBeGreaterThan(2);
  expect(fragments.at(-1)!.streams[0]!.complete).toBe(true);
  expect(
    fragments.slice(0, -1).every((g) => g.streams[0]!.complete === false),
  ).toBe(true);
  expect(midwayComplete).toBe(0);
  expect(midwayRows).not.toBeNull();
  expect(midwayRows).not.toEqual(await a.rows());
  expect(
    fragments.some((g) => g.operations.some((op) => op.kind === "upsert-ref")),
  ).toBe(true);
  expect(w.innerBlobs.keys().some((key) => key.startsWith(`${LOG}/v-`))).toBe(
    true,
  );
  await reader.cycle();
  expect(await reader.rows()).toEqual(await a.rows());
  expect(
    (
      await reader.db.query<{ complete: number }>(
        "SELECT complete FROM stream_state WHERE stream='s0'",
      )
    )[0]!.complete,
  ).toBe(1);
  const expected = new Map<
    string,
    {
      record_key: string;
      pk_hash: string;
      stamp_o: number;
      stamp_r: string;
      rank: number;
    }
  >();
  for (const segment of all)
    for (const op of segment.operations) {
      if (op.kind !== "delete" && op.kind !== "complete") continue;
      const stamp = op.kind === "delete" ? op.stamp : op.cutoff;
      for (const key of op.kind === "delete" ? [op] : op.omitted)
        expected.set(key.pkHash, {
          record_key: String(key.key[0]),
          pk_hash: key.pkHash,
          stamp_o: stamp.o,
          stamp_r: stamp.r,
          rank: op.kind === "delete" ? 2 : 0,
        });
    }
  const tombstones = await reader.db.query(
    "SELECT record_key,pk_hash,stamp_o,stamp_r,rank FROM log_tombstones ORDER BY pk_hash",
  );
  expect(tombstones).toEqual(
    [...expected.values()].sort((a, b) => a.pk_hash.localeCompare(b.pk_hash)),
  );
  expect(tombstones.length).toBe(ids.length - kept.length);
  const settled = await a.position();
  await a.cycle();
  await reader.cycle();
  expect(await a.position()).toBe(settled);
  expect(await reader.rows()).toEqual(await a.rows());
}, 60000);

it("rebase seeds current unpublished observations without replacing rows or duplicating pending changes", async () => {
  const w = await world({ streams: 1 });
  const a = await w.device("a");
  await a.run("published", [{ stream: "s0", id: "stable", v: 1 }], {
    observedAt: 1100,
  });
  await a.cycle();
  const log = await readLogState(a.deps, CONNECTION_ID);
  await a.run(
    "unpublished",
    [
      { stream: "s0", id: "stable", v: 999 },
      { stream: "s0", id: "local-only", v: 999 },
    ],
    { full: false, observedAt: 9000 },
  );
  const rows = await a.rows();
  const pending = () =>
    a.db
      .query(`SELECT c.stream,c.pk_hash,c.record_key,c.op,c.stamp_o,c.stamp_r,c.origin FROM record_changes c
    JOIN stream_state s ON c.connection_id=s.connection_id AND c.stream=s.stream WHERE c.seq>s.publish_watermark ORDER BY c.seq`);
  const before = await pending();
  const keyCheck = await deriveKeyCheck(a.deps.keys.namespaceHmac);
  await rebaseOnLog(
    a.deps,
    CONNECTION_ID,
    {
      connector: "fixture",
      ns: "",
      generation: 1,
      keyCheck,
      hashes: await controlHashes(
        async (bytes) => nobleStreamCrypto.keccak256(bytes),
        keyCheck,
      ),
    },
    log,
    [],
  );
  expect(await a.rows()).toEqual(rows);
  expect(await pending()).toEqual(before);
  expect((await readLogState(a.deps, CONNECTION_ID)).position).toBe(0);
  await a.cycle();
  const b = await w.device("b");
  await b.cycle();
  expect(await b.rows()).toEqual(await a.rows());
});
