// What publish and compaction read of a connection's held records crosses the
// phone bridge in replies of at most 4 MiB, whatever the characters of a body
// are. A body is stored as JSON text; a text value in a reply is escaped a
// second time, so a body of backslashes is twice its stored size in the reply
// when it is read as text. The reads here are blobs, cut by their stored size
// (`byte-pages.ts`): the replace probe (`omittedBy`), the batch planner
// (`bodyBatches`) and the operation read (`operationsFor`).
import { afterEach, describe, expect, it } from "vitest";
import { deriveKeyCheck } from "@opendatalabs/personal-server-ts-stream-sync";
import { compactLog } from "../../../core/src/localdb/log-compact.js";
import { publishLog } from "../../../core/src/localdb/log-publish.js";
import { openSpool } from "../../../core/src/localdb/log-spool.js";
import { readLogState } from "../../../core/src/localdb/log-state.js";
import {
  frameLimited,
  SQL_FRAME_BYTES,
} from "./frame-limited-driver.test-utils.js";
import {
  CONNECTION_ID,
  CONNECTOR,
  LOG,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const TARGET = 400_000;

/** Bodies of `char` (what a record's `pad` repeats), below and above the part target and the 1 MiB page. */
const shapes: ReadonlyArray<{
  label: string;
  padWith: string;
  sizes: readonly number[];
}> = [
  {
    label: "backslashes",
    padWith: "\\",
    sizes: [
      1_500_000, // 3 MiB stored: over a page, read in chunks
      450_000, // 900 KB stored: a page of its own
      200_000,
      200_000,
      50_000,
      50_000,
      50_000,
      50_000,
    ],
  },
  {
    label: "quotes",
    padWith: '"',
    sizes: [600_000, 300_000, 300_000, 20_000, 20_000, 20_000],
  },
  {
    label: "three-byte characters",
    padWith: "€",
    sizes: [900_000, 300_000, 130_000, 130_000, 10_000],
  },
  {
    label: "four-byte characters",
    padWith: "😀",
    sizes: [500_000, 250_000, 100_000, 100_000, 10_000],
  },
];

describe("publish and compaction read held bodies in replies under 4 MiB", () => {
  for (const { label, padWith, sizes } of shapes)
    it(`bodies of ${label}, a publish then a replacing run that drops most of them, then a compaction`, async () => {
      const w = await world({ streams: 1, partTargetBytes: TARGET });
      const a = await w.device("a");
      const framed = frameLimited(a.db);
      const deps = { ...a.deps, db: framed, partTargetBytes: TARGET };
      const records = sizes.map((pad, i) => ({
        stream: sName(0),
        id: `k${i}`,
        pad,
        padWith,
      }));
      await a.run("r1", records, { full: false, observedAt: 2000 });
      // The planner reads the bodies to send (batches, operations).
      await publishLog(deps, CONNECTION_ID);
      // A replacing run that keeps the smallest: the pass that names the rest
      // reads their bodies to find their keys (the replace probe).
      await a.run("r2", records.slice(-1), { full: true, observedAt: 2001 });
      await publishLog(deps, CONNECTION_ID);
      // A compaction folds the whole history.
      const log = await readLogState(deps, CONNECTION_ID);
      const spool = openSpool(framed, CONNECTION_ID);
      const keyCheck = await deriveKeyCheck(async () => new Uint8Array(32));
      await compactLog(
        deps,
        {
          connectionId: CONNECTION_ID,
          connector: CONNECTOR,
          ns: "",
          generation: 1,
          keyCheck,
          scope: LOG,
          log,
        },
        spool,
      );
      for (const object of spool.objects()) await object.read();
      await spool.discard();
      expect(framed.frames.largestRequest).toBeLessThan(SQL_FRAME_BYTES);
      expect(framed.frames.largestReply).toBeLessThan(SQL_FRAME_BYTES);
    }, 120_000);
});
