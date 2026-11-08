/**
 * The reader tells the overlay source what it has durably installed: after a
 * ViewStore commit, and for every durable current view at startup. Never when
 * its files are not durable, and never for an import that did not commit.
 */

import { describe, expect, it } from "vitest";
import { ask } from "./service-fixture.js";
import { Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

async function setup(seed: number) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  await f.activate("acme", ns);
  return { f, ns };
}

describe("reader acknowledgment", () => {
  it("acknowledges what a durable commit installed, after the pointer is written", async () => {
    const { f, ns } = await setup(91);
    const built = await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a" }],
    });
    const pointerAtAck: (number | null)[] = [];
    const original = f.overlay.acknowledge.bind(f.overlay);
    f.overlay.acknowledge = async (c) => {
      const current = await f.files.read(`views/acme/${ns}/items/current.json`);
      pointerAtAck.push(
        current ? JSON.parse(new TextDecoder().decode(current)).version : null,
      );
      return original(c);
    };
    const service = await f.service();
    await f.sync(service);
    expect(f.overlay.acks).toEqual([
      {
        connector: "acme",
        ns,
        stream: "items",
        generation: 1,
        registryVersion: 1,
        dataHash: built.dataHash.toLowerCase(),
      },
    ]);
    expect(pointerAtAck).toEqual([1]);
  });

  it("never acknowledges when the read files are not durable", async () => {
    const { f, ns } = await setup(92);
    f.durable = false;
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a" }],
    });
    const service = await f.service();
    await f.sync(service);
    await (await f.service()).importPending();
    expect(f.overlay.acks).toEqual([]);
  });

  it("does not acknowledge a head whose blobs are missing", async () => {
    const { f, ns } = await setup(93);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a" }],
      withholdBlobs: true,
    });
    const service = await f.service();
    await f.sync(service);
    expect(f.overlay.acks).toEqual([]);
  });

  it("acknowledges every durable current view at startup", async () => {
    const { f, ns } = await setup(94);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a" }],
    });
    await f.sync(await f.service());
    f.overlay.acks.length = 0;
    await f.service(); // restart over the same files
    expect(f.overlay.acks).toHaveLength(1);
    expect(f.overlay.acks[0]).toMatchObject({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      registryVersion: 1,
    });
  });

  it("keeps importing and serving when an acknowledgment fails", async () => {
    const { f, ns } = await setup(95);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a" }],
    });
    f.overlay.acknowledge = async () => {
      throw new Error("source unavailable");
    };
    const service = await f.service();
    await f.sync(service);
    expect((await service.resolve(ask("pdpp.acme.items"))).kind).toBe("view");
    expect(service.status().issues).toEqual([]);
  });
});
