/**
 * On a stream-sync account the owner still reads the rows this device
 * collected itself, whatever their publish state. A grant reads imported
 * complete heads only.
 */

import { describe, expect, it } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

const T = Date.parse("2026-11-01T00:00:00Z");
const line = (id: string): Line => ({ o: T, r: "r1", v: { id } });

async function setup(seed: number) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  await f.activate("acme", ns);
  f.overlay.runs = [
    {
      runId: "r1",
      ns,
      generation: 1,
      streams: [{ name: "items", rows: [line("own")], complete: true }],
    },
  ];
  return { f, ns };
}

async function read(f: Fixture, isOwnerView: boolean) {
  const service = await f.service();
  await f.sync(service);
  const query = { streamOnly: true, isOwnerView };
  const decision = await service.resolve(ask("pdpp.acme.items", query));
  const ids =
    decision.kind === "view" || decision.kind === "local_pending"
      ? (await body(decision)).data.records.map((r: any) => r.id).sort()
      : decision.kind;
  const listed = (await service.listScopes(query)).map((s) => s.scope);
  return { ids, listed };
}

describe("stream-only reads of this device's own writes", () => {
  it("serves and lists an unpublished local run to the owner, not to a grant", async () => {
    const { f } = await setup(98);
    expect(await read(f, true)).toEqual({
      ids: ["own"],
      listed: ["pdpp.acme.items"],
    });
    expect(await read(f, false)).toEqual({ ids: "unavailable", listed: [] });
  });
});
