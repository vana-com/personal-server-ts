/**
 * A stream whose newest publish is incomplete stays readable at its last
 * complete head (stream-sync accounts only), whichever device first sees it,
 * and across restarts. Accounts that have not switched read as they did before.
 */

import { partBlobName } from "@opendatalabs/personal-server-ts-stream-sync";
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

  describe("a fallback the current head names is checked before it is trusted", () => {
    const publishNaming = (
      f: Fixture,
      ns: string,
      lastComplete: { version: number; dataHash: string },
      lastDeleteVersion = 0,
    ) =>
      f.publish({
        connector: "acme",
        ns,
        stream: "items",
        generation: 1,
        complete: false,
        records: [{ id: "partial" }],
        lastComplete,
        lastDeleteVersion,
      });

    async function readsOn(
      f: Fixture,
      files = createMemoryStreamSyncReadFiles(),
    ) {
      const service = await f.service({ files });
      await f.sync(service);
      return {
        service,
        outcome: await service.resolve(
          ask("pdpp.acme.items", { streamOnly: true }),
        ),
      };
    }

    it("never serves a complete head that predates a delete, whatever version the current head claims", async () => {
      const { f, ns, complete } = await setup(95);
      // v2 deletes the stream, v3 is a later publish, v4 is incomplete and
      // claims that v3 is the hash of the pre-delete v1.
      await f.publish({
        connector: "acme",
        ns,
        stream: "items",
        generation: 1,
        complete: false,
        records: [],
        lastDeleteVersion: 2,
      });
      await f.publish({
        connector: "acme",
        ns,
        stream: "items",
        generation: 1,
        complete: true,
        records: [{ id: "later" }],
      });
      await publishNaming(
        f,
        ns,
        { version: 3, dataHash: complete.dataHash },
        2,
      );
      const files = createMemoryStreamSyncReadFiles();
      const first = await readsOn(f, files);
      expect(await ids(first.outcome)).not.toContain("complete");
      expect(first.outcome.kind).toBe("unavailable");
      // After a restart over the same files nothing has been resurrected.
      const second = await readsOn(f, files);
      expect(second.outcome.kind).toBe("unavailable");
      expect(
        await second.service.listScopes({
          streamOnly: true,
          isOwnerView: true,
        }),
      ).not.toContainEqual(
        expect.objectContaining({ scope: "pdpp.acme.items" }),
      );
    });

    it.each([
      ["the current version", 2],
      ["a later version", 9],
    ])("does not follow a name at %s", async (_label, version) => {
      const { f, ns, complete } = await setup(96);
      await publishNaming(f, ns, { version, dataHash: complete.dataHash });
      const { outcome } = await readsOn(f);
      expect(outcome).toMatchObject({ kind: "unavailable", reason: "no_data" });
    });
  });

  describe("an incomplete head whose own parts cannot be read", () => {
    const damage = {
      missing: (f: Fixture, keys: string[]) => {
        for (const k of keys) f.blobs.delete(k);
      },
      corrupt: (f: Fixture, keys: string[]) => {
        for (const k of keys) f.blobs.set(k, new Uint8Array([1, 2, 3]));
      },
    };

    it.each(["missing", "corrupt"] as const)(
      "still lists and serves the complete head on a cold and a warm device (%s parts)",
      async (how) => {
        const { f, ns, complete } = await setup(97);
        const warm = await f.service();
        await f.sync(warm);
        const partial = await publishIncomplete(f, ns, complete);
        damage[how](
          f,
          partial.head.parts.map(
            (p) => `${partial.scope}/${partBlobName(1, p.hash)}`,
          ),
        );
        await f.sync(warm);
        const cold = await f.service({
          files: createMemoryStreamSyncReadFiles(),
        });
        await f.sync(cold);
        for (const isOwnerView of [true, false]) {
          const query = { streamOnly: true, isOwnerView };
          expect(
            await ids(await cold.resolve(ask("pdpp.acme.items", query))),
          ).toEqual(["complete"]);
          expect(
            await ids(await warm.resolve(ask("pdpp.acme.items", query))),
          ).toEqual(["complete"]);
          expect(await cold.listScopes(query)).toEqual(
            await warm.listScopes(query),
          );
          expect(await cold.listScopes(query)).toContainEqual(
            expect.objectContaining({ scope: "pdpp.acme.items" }),
          );
        }
        // The unread current view is never acknowledged, so the overlay keeps
        // what it holds for it; the next pass retries the import.
        expect(f.overlay.acks.every((a) => a.version !== 2)).toBe(true);
      },
    );
  });

  it("keeps at most one complete head besides the current one, and drops it once a newer complete head lands", async () => {
    const { f, ns, complete } = await setup(130);
    const service = await f.service();
    const heads = async () => (await f.files.list(`${base(ns)}/heads`)).length;
    await f.sync(service);
    expect(await heads()).toBe(1);
    await publishIncomplete(f, ns, complete);
    await f.sync(service);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      complete: false,
      records: [{ id: "partial-2" }],
      lastComplete: { version: 1, dataHash: complete.dataHash },
    });
    await f.sync(service);
    // The current incomplete head and the one complete head: never more.
    expect(await heads()).toBe(2);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      complete: true,
      records: [{ id: "later" }],
    });
    await f.sync(service);
    expect(await heads()).toBe(1);
  });
});
