/**
 * What a legacy delete may ask the read service about a scope
 * (`retireBasis`): which connectors count, whether the scope is deleted whole,
 * and when each delete happened. Real service, registry mirror and heads.
 */

import { describe, expect, it } from "vitest";
import { Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

async function setup(connectors: string[]) {
  const fixture = new Fixture(await testOwnerKey(masterKey(902)));
  const ns: Record<string, string> = {};
  for (const connector of connectors) {
    ns[connector] = await fixture.key.ns(connector, "retire-basis");
    await fixture.activate(connector, ns[connector]!);
  }
  const publish = (connector: string, stream: string, ids: string[]) =>
    fixture.publish({
      connector,
      ns: ns[connector]!,
      stream,
      generation: 1,
      records: ids.map((id) => ({ id })),
    });
  return { fixture, publish };
}

describe("retireBasis", () => {
  it("counts only the connectors the registry knows: an alternate that was never connected leaves the scope covered (UNKNOWN_ALTERNATE_UNCOVERS)", async () => {
    // github.events is served by `github` or by `github-browser`.
    const { fixture, publish } = await setup(["github"]);
    await publish("github", "events", ["a"]);
    const service = await fixture.service();
    await fixture.sync(service);
    const basis = service.retireBasis("github.events")!;
    expect(basis.covered).toBe(true);
    expect(basis.ambiguous).toBe(false);
    expect(basis.streams.map((s) => s.connector)).toEqual(["github"]);
  });

  it("says deleted, not covered, when every target is deleted and none came back, with the registry time of the delete (WHOLE_DELETE_BASIS)", async () => {
    const { fixture, publish } = await setup(["chatgpt"]);
    const head = await publish("chatgpt", "memories", ["m0"]);
    const service = await fixture.service();
    await fixture.sync(service);
    expect(service.retireBasis("chatgpt.memories")).toMatchObject({
      covered: true,
      deleted: false,
    });

    const version = fixture.tombstoneStream(head.scope);
    await fixture.sync(service);
    const basis = service.retireBasis("chatgpt.memories")!;
    expect(basis).toMatchObject({ covered: false, deleted: true });
    expect(basis.streams).toEqual([
      {
        connector: "chatgpt",
        stream: "memories",
        deleteVersion: version,
        deleteAtMs: Date.parse(fixture.rows.get(head.scope)!.addedAt!),
      },
    ]);
  });

  it("keeps the delete time across a restart, and a reconnect does not clear it (DELETE_TIME_LOST)", async () => {
    const { fixture, publish } = await setup(["chatgpt"]);
    const head = await publish("chatgpt", "memories", ["m0"]);
    const service = await fixture.service();
    await fixture.sync(service);
    fixture.tombstoneStream(head.scope);
    await fixture.sync(service);
    const at = Date.parse(fixture.rows.get(head.scope)!.addedAt!);

    await publish("chatgpt", "memories", ["m1"]); // reconnected
    const reopened = await fixture.service();
    await fixture.sync(reopened);
    const basis = reopened.retireBasis("chatgpt.memories")!;
    expect(basis).toMatchObject({ covered: true, deleted: false });
    expect(basis.streams[0]).toMatchObject({
      deleteVersion: 2,
      deleteAtMs: at,
    });
  });
});
