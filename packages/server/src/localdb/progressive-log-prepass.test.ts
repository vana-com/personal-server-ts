// The prepass of a progressive first load reads every segment that removes a
// key before the first batch applies, so a key a later segment deletes is never
// shown. It must not cost a second download of those segments when their
// batches come, and it must not start every download at once on a long tail.
import { afterEach, expect, it } from "vitest";
import { applyConnection } from "../../../core/src/localdb/index.js";
import { PARTS_IN_FLIGHT } from "../../../core/src/stream-sync/storage-retry.js";
import {
  CONNECTION_ID,
  CONNECTOR,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const STREAM = sName(0);
const SEGMENT = /\/s-[0-9a-f]+$/;
const REMOVING = PARTS_IN_FLIGHT + 8;

async function deletionHeavyLog(w: Awaited<ReturnType<typeof world>>) {
  const a = await w.device("a");
  const ids = Array.from({ length: REMOVING }, (_, i) => `k${i}`);
  await a.run(
    "r0",
    ids.map((id) => ({ stream: STREAM, id })),
    { observedAt: 1000 },
  );
  await a.cycle();
  for (const [i, id] of ids.entries()) {
    await a.run("d" + i, [{ stream: STREAM, id, remove: true }], {
      full: false,
      covered: [STREAM],
      observedAt: 1100 + i,
    });
    await a.cycle();
  }
}

it("reads each removing segment from storage once, and not all of them at once", async () => {
  const w = await world({ streams: 1 });
  await deletionHeavyLog(w);

  let waiting = 0;
  let widest = 0;
  let open = false;
  let head: string | undefined;
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const b = await w.device("b", {
    progressiveFirstLoad: true,
    keyedFirstLoad: false,
    beforeGet: async (key) => {
      if (open || !SEGMENT.test(key)) return;
      // The first segment read is the head, which the prepass waits for.
      head ??= key;
      if (key === head) return;
      widest = Math.max(widest, ++waiting);
      await gate;
      waiting--;
    },
  });
  await b.db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,?,'',1,'active',1)",
      params: [CONNECTION_ID, CONNECTOR],
    },
  ]);
  const applying = applyConnection(b.deps, CONNECTION_ID);
  // Let every download the prepass starts reach the gate.
  for (let turn = 0; turn < 50; turn++)
    await new Promise((r) => setTimeout(r, 5));
  const started = widest;
  open = true;
  release();
  await applying;

  expect(started).toBeLessThanOrEqual(PARTS_IN_FLIGHT);
  const perSegment = new Map<string, number>();
  for (const key of b.gets)
    if (SEGMENT.test(key)) perSegment.set(key, (perSegment.get(key) ?? 0) + 1);
  expect([...perSegment.values()].filter((n) => n > 1)).toEqual([]);
  // The ciphertext kept on disk for the batches is gone when the load ends.
  const [kept] = await b.db.query<{ n: number }>(
    "SELECT COUNT(*) AS n FROM log_spool",
  );
  expect(kept!.n).toBe(0);
});
