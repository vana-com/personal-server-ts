/**
 * A stream whose newest publish is incomplete stays readable at its last
 * complete head (stream-sync accounts only), whichever device first sees it,
 * and across restarts. Accounts that have not switched read as they did before.
 */

import { describe, expect, it } from "vitest";
import { createMemoryStreamSyncReadFiles } from "./memory-files.js";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

const base = (ns: string) => `views/acme/${ns === "" ? "_" : ns}/items`;

async function setup(seed: number) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  await f.activate("acme", ns);
  const complete = await f.publish({
    connector: "acme",
    ns,
    stream: "items",
    generation: 1,
    complete: true,
    records: [{ id: "complete" }],
  });
  return { f, ns, complete };
}

const publishIncomplete = (
  f: Fixture,
  ns: string,
  complete: { dataHash: string },
) =>
  f.publish({
    connector: "acme",
    ns,
    stream: "items",
    generation: 1,
    complete: false,
    records: [{ id: "partial" }],
    lastComplete: { version: 1, dataHash: complete.dataHash },
  });

const ids = async (
  decision: Awaited<ReturnType<Fixture["service"]>>["resolve"] extends (
    ...a: any[]
  ) => Promise<infer R>
    ? R
    : never,
) =>
  decision.kind === "view"
    ? (await body(decision)).data.records.map((r: any) => r.id).sort()
    : decision.kind;

describe("latest complete head", () => {
  it.each([true, false])(
    "a fresh device that only sees the incomplete row serves the complete head it names (owner=%s)",
    async (isOwnerView) => {
      const { f, ns, complete } = await setup(91);
      await publishIncomplete(f, ns, complete);
      // The registry lists only the current row (version 2). This device never
      // imported version 1.
      const fresh = await f.service({
        files: createMemoryStreamSyncReadFiles(),
      });
      await f.sync(fresh);
      expect(
        await ids(
          await fresh.resolve(
            ask("pdpp.acme.items", { streamOnly: true, isOwnerView }),
          ),
        ),
      ).toEqual(["complete"]);
      expect(
        await fresh.listScopes({ streamOnly: true, isOwnerView }),
      ).toContainEqual(expect.objectContaining({ scope: "pdpp.acme.items" }));
    },
  );

  it("never-complete streams stay unreadable on a fresh device", async () => {
    const { f, ns } = await setup(92);
    await f.publish({
      connector: "acme",
      ns,
      stream: "other",
      generation: 1,
      complete: false,
      records: [{ id: "partial" }],
    });
    const fresh = await f.service({ files: createMemoryStreamSyncReadFiles() });
    await f.sync(fresh);
    expect(
      await fresh.resolve(ask("pdpp.acme.other", { streamOnly: true })),
    ).toMatchObject({ kind: "unavailable", reason: "no_data" });
  });

  it("keeps the complete head when only the incomplete cache is damaged", async () => {
    const { f, ns, complete } = await setup(93);
    let service = await f.service();
    await f.sync(service);
    const partial = await publishIncomplete(f, ns, complete);
    await f.sync(service);
    const only = partial.head.parts
      .map((p) => p.hash)
      .filter((h) => !complete.head.parts.some((p) => p.hash === h));
    expect(only.length).toBeGreaterThan(0);
    for (const hash of only) await f.files.remove(`${base(ns)}/parts/${hash}`);
    service = await f.service();
    expect(
      await ids(
        await service.resolve(ask("pdpp.acme.items", { streamOnly: true })),
      ),
    ).toEqual(["complete"]);
    // Importing the incomplete head again keeps the complete pointer.
    await f.sync(service);
    expect(
      await ids(
        await (
          await f.service()
        ).resolve(ask("pdpp.acme.items", { streamOnly: true })),
      ),
    ).toEqual(["complete"]);
  });

  it("an account that has not switched replays a cursor as before: stale", async () => {
    const { f, ns, complete } = await setup(94);
    const service = await f.service();
    await f.sync(service);
    const first = await service.resolve(ask("pdpp.acme.items"));
    if (first.kind !== "view") throw new Error(first.kind);
    const cursor = first.cursor;
    await body(first);
    await publishIncomplete(f, ns, complete);
    await f.sync(service);
    expect(
      await ids(await service.resolve(ask("pdpp.acme.items", { cursor }))),
    ).toBe("cursor_stale");
  });
});
