// A complete read gives its connection's queue back once it has decided its
// headers, so a run may end, and write its rows, while the body is still being
// read. The body pages through the stream and each page checks, in its own
// statement, that nothing changed since the read began. Real publisher, real
// SQLite and the real resolver (log-world.test-utils.ts).
//
// The window: a run's end writes its rows into the table, but the stream's
// head moves only when the device's next cycle publishes them. For that time
// the head still names the old state, so a check of the head alone passes
// over rows of the new one.
import { afterEach, describe, expect, it } from "vitest";
import { COMPLETE_PAGE_SIZE } from "../../../core/src/localdb/complete-read.js";
import { PartialViewMoved } from "../../../core/src/localdb/partial-read.js";
import { createRecordQuery } from "../../../core/src/localdb/query.js";
import { createLocalResolver } from "../../../core/src/localdb/resolve.js";
import {
  CONNECTOR,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);
const STREAM = sName(0);
const SCOPE = `pdpp.${CONNECTOR}.${STREAM}`;
const within = <T>(work: Promise<T>, ms = 3000) =>
  Promise.race([
    work,
    new Promise<"timeout">((r) => setTimeout(() => r("timeout"), ms)),
  ]);

describe("a complete read while a run ends on the same connection", () => {
  it("ends the body in an error once the run's rows are in the table, and the run is not held up", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    const records = (ids: string[]) => ids.map((id) => ({ stream: STREAM, id }));
    const before = Array.from(
      { length: COMPLETE_PAGE_SIZE + 5 },
      (_, i) => `a${i}`,
    );
    await a.run("run-1", records(before), {
      full: true,
      covered: [STREAM],
      observedAt: 1100,
    });
    await a.cycle();

    const resolver = createLocalResolver(a.deps, {
      query: createRecordQuery(a.db),
    });
    const ask = {
      scope: SCOPE,
      connection: null,
      cursor: null,
      legacyFile: false,
      isOwnerView: true,
    };
    const decision = await resolver.resolve(ask);
    if (decision.kind !== "view") throw new Error("missing view");
    const reader = decision.body.getReader();
    const decoder = new TextDecoder();
    let served = "";
    // The envelope, the opening of the list and fifty records of the first page, which holds more.
    for (let i = 0; i < 52; i++)
      served += decoder.decode((await reader.read()).value);

    // A run ends: its rows are in the table while the head is still the first.
    const added = ["b0", "b1", "b2"];
    const ended = await within(
      a.run("run-2", records(added), {
        full: false,
        covered: [STREAM],
        observedAt: 1200,
      }),
    );
    expect(ended).not.toBe("timeout");
    const inTable = await a.db.query<{ body: string }>(
      "SELECT body FROM records WHERE stream = ?",
      [STREAM],
    );
    expect(inTable).toHaveLength(COMPLETE_PAGE_SIZE + 5 + added.length);
    const [head] = await a.db.query<{ head_version: number }>(
      "SELECT head_version FROM stream_state WHERE stream = ?",
      [STREAM],
    );
    expect(head!.head_version).toBe(1); // the head has not moved

    let failure: unknown;
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        served += decoder.decode(chunk.value);
      }
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(PartialViewMoved);
    // What it served before the error is of the first state alone.
    expect(served).toMatch(/"id":"a\d+"/);
    expect(served).not.toMatch(/"id":"b\d+"/);

    // A read begun after the run publishes is the new state, whole.
    await a.cycle();
    const again = await resolver.resolve(ask);
    if (again.kind !== "view") throw new Error("missing view");
    const body = JSON.parse(await new Response(again.body).text()) as {
      data: { records: { id: string }[] };
    };
    expect(body.data.records.map((r) => r.id).sort()).toEqual(
      [...before, ...added].sort(),
    );
  });
});
