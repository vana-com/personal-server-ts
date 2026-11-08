/** `viewServes` answers "would a read serve the view, not the legacy file". */

import { describe, expect, it } from "vitest";
import { ask, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

async function setup(seed: number) {
  const f = new Fixture(await testOwnerKey(await masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  await f.activate("acme", ns);
  return { f, ns };
}

describe("viewServes", () => {
  it("is true for a complete live view and agrees with the read path", async () => {
    const { f, ns } = await setup(901);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a" }],
      complete: true,
    });
    const service = await f.service();
    await f.sync(service);
    expect(service.viewServes("pdpp.acme.items")).toBe(true);
    const decision = await service.resolve(
      ask("pdpp.acme.items", { legacyFile: true }),
    );
    expect("body" in decision).toBe(true);
    if ("body" in decision) await decision.body.cancel();
  });

  it("is false for an incomplete view, and the read still serves the legacy file", async () => {
    const { f, ns } = await setup(902);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a" }],
      complete: false,
    });
    const service = await f.service();
    await f.sync(service);
    expect(service.viewServes("pdpp.acme.items")).toBe(false);
    const decision = await service.resolve(
      ask("pdpp.acme.items", { legacyFile: true }),
    );
    expect(decision.kind).toBe("legacy");
  });

  it("is false for an unknown connector and for a physical name", async () => {
    const { f } = await setup(903);
    const service = await f.service();
    await f.sync(service);
    expect(service.viewServes("pdpp.other.items")).toBe(false);
    expect(service.viewServes("pdpp.acme~0123456789abcdef.items")).toBe(false);
  });
});
