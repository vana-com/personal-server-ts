import { afterEach, expect, it } from "vitest";
import { createLocalListing } from "../../../core/src/localdb/listing.js";
import { createRecordQuery } from "../../../core/src/localdb/query.js";
import { createLocalResolver } from "../../../core/src/localdb/resolve.js";
import {
  world,
  closeWorldDrivers,
  CONNECTOR,
  sName,
} from "./log-world.test-utils.js";

import { endRequest } from "../../../core/src/test-utils/run-end.js";

afterEach(closeWorldDrivers);

it("syncs an uncertified first collection between two real databases and lets each owner inspect the same records", async () => {
  const w = await world({ streams: 4 });
  const desktop = await w.device("desktop");
  const web = await w.device("web");
  const records = Array.from({ length: 4 }, (_, i) => ({
    stream: sName(i),
    id: `saved-${i}`,
  }));
  await desktop.begin("partial-import", { full: true, observedAt: 1100 });
  await desktop.sync.intake.batch("partial-import", {
    batch: 0,
    records: records.map(({ stream, id }) => ({ stream, data: { id } })),
  });
  await desktop.sync.intake.end(
    "partial-import",
    endRequest({
      lastBatch: 0,
      streams: records.map((r) => r.stream),
      live: records.map((r) => r.stream),
      finish: "certified_failed_done",
    }),
  );
  await desktop.cycle();
  await web.cycle();
  for (const device of [desktop, web]) {
    const listing = createLocalListing(device.deps);
    const status = await listing.status();
    expect(
      Object.values(status.connections[0]!.streams).map((s) => s.complete),
    ).toEqual([false, false, false, false]);
    expect(await listing.listScopes({ canRead: () => true })).toEqual([]);
    const saved = await listing.listScopes({
      canRead: () => true,
      includeIncomplete: true,
    });
    expect(saved).toHaveLength(4);
    expect(
      saved.every((s) => s.dataStatus === "incomplete" && s.records === 1),
    ).toBe(true);
    const resolver = createLocalResolver(device.deps, {
      query: createRecordQuery(device.db),
    });
    for (const record of records) {
      const read = await resolver.resolve({
        scope: `pdpp.${CONNECTOR}.${record.stream}`,
        connection: null,
        cursor: null,
        legacyFile: false,
        isOwnerView: true,
        includeIncomplete: true,
      });
      expect(read).toMatchObject({ kind: "view", complete: false });
      if (!("body" in read)) throw new Error("missing saved record");
      expect((await new Response(read.body).json()).data.records).toEqual([
        { id: record.id },
      ]);
    }
  }
});
