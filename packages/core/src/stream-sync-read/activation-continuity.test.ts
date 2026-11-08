/**
 * A row once visible to the owner stays visible. The owner reads an
 * incomplete local stream before its generation is activated (local_pending);
 * after activation it must still read the same rows. A grantee gets exactly
 * what it gets for an incomplete imported view of the same stream.
 */

import { describe, expect, it } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import type { FakeRun } from "./service-fixture.js";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

const T = Date.parse("2026-11-01T00:00:00Z");
const row = (id: string): Line => ({ o: T, r: "r1", v: { id } });
const run = (
  ns: string,
  extra: { receipt?: { registryVersion: number; dataHash: string } } = {},
): FakeRun => ({
  runId: "r1",
  ns,
  generation: 1,
  streams: [
    {
      name: "items",
      rows: [row("x"), row("y")],
      complete: false,
      ...(extra.receipt
        ? { receipt: { ...extra.receipt, generation: 1 } }
        : {}),
    },
  ],
});

async function setup(seed: number) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  return { f, ns };
}

async function read(f: Fixture, extra = {}) {
  const service = await f.service();
  await f.sync(service);
  const decision = await service.resolve(ask("pdpp.acme.items", extra));
  if (decision.kind !== "view" && decision.kind !== "local_pending") {
    return { kind: decision.kind };
  }
  const envelope = await body(decision);
  return {
    kind: decision.kind,
    origin: envelope.origin as string | undefined,
    ids: envelope.data.records.map((r: any) => r.id).sort() as string[],
  };
}

describe("an incomplete local stream across activation", () => {
  it("serves the owner the same rows before and after activation", async () => {
    const { f, ns } = await setup(401);
    f.overlay.runs = [run(ns)];
    const before = await read(f);
    expect(before).toEqual({
      kind: "local_pending",
      origin: "local-pending",
      ids: ["x", "y"],
    });
    await f.activate("acme", ns);
    expect(await read(f)).toEqual(before);
  });

  it("replays a cursor taken before activation after activation", async () => {
    const { f, ns } = await setup(405);
    f.overlay.runs = [run(ns)];
    const first = await (await f.service()).resolve(ask("pdpp.acme.items"));
    expect(first.kind).toBe("local_pending");
    const cursor = (first as { cursor: string }).cursor;
    await (first as { body: ReadableStream }).body.cancel();
    await f.activate("acme", ns);
    const service = await f.service();
    await f.sync(service);
    const again = await service.resolve(ask("pdpp.acme.items", { cursor }));
    expect(again.kind).toBe("local_pending");
    expect((await body(again)).data.records).toHaveLength(2);
  });

  it("keeps the rows after the imported head that covers them is incomplete too", async () => {
    const { f, ns } = await setup(402);
    f.overlay.runs = [run(ns)];
    await f.activate("acme", ns);
    const built = await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "x" }, { id: "y" }],
      complete: false,
      observedAt: T,
    });
    f.overlay.runs = [
      run(ns, { receipt: { registryVersion: 1, dataHash: built.dataHash } }),
    ];
    const out = await read(f);
    expect(out.kind).toBe("local_pending");
    expect((out as any).ids).toEqual(["x", "y"]);
  });

  it("gives a grantee what an incomplete imported view gives it", async () => {
    const overlayOnly = await setup(403);
    overlayOnly.f.overlay.runs = [run(overlayOnly.ns)];
    await overlayOnly.f.activate("acme", overlayOnly.ns);

    const imported = await setup(404);
    await imported.f.activate("acme", imported.ns);
    await imported.f.publish({
      connector: "acme",
      ns: imported.ns,
      stream: "items",
      generation: 1,
      records: [{ id: "x" }, { id: "y" }],
      complete: false,
      observedAt: T,
    });

    const grant = { isOwnerView: false };
    expect(await read(overlayOnly.f, grant)).toEqual(
      await read(imported.f, grant),
    );
  });
});
