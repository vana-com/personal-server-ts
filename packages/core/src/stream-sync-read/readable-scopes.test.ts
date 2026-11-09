/**
 * The switched-account scope list is exactly the set of scopes a body read
 * serves the same caller, and it is decided from metadata: no body is built,
 * an uncovered scope costs nothing and cannot fail the list.
 */

import { describe, expect, it, vi } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import type { FakeRun } from "./service-fixture.js";
import { ask, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";
import type { StreamSyncReadService } from "./service.js";

const T = Date.parse("2026-11-01T00:00:00Z");
const row = (id: string): Line => ({ o: T, r: "r1", v: { id } });
const overlayRun = (ns: string, streams: string[], runId = "r1"): FakeRun => ({
  runId,
  ns,
  generation: 1,
  streams: streams.map((name) => ({
    name,
    rows: [row(`${name}-1`)],
    complete: true,
  })),
});

/** Scopes a body read serves `isOwnerView`, among `universe`. */
async function bodyReadable(
  service: StreamSyncReadService,
  universe: string[],
  isOwnerView: boolean,
): Promise<string[]> {
  const out: string[] = [];
  for (const scope of universe) {
    const decision = await service.resolve(ask(scope, { isOwnerView }));
    if ("body" in decision) await decision.body.cancel();
    if (decision.kind === "view" || decision.kind === "local_pending") {
      out.push(scope);
    }
  }
  return out.sort();
}

async function listed(
  service: StreamSyncReadService,
  isOwnerView: boolean,
  extra: { isCovered?: (scope: string) => boolean } = {},
): Promise<string[]> {
  return (await service.readableScopes({ isOwnerView, ...extra }))
    .map((s) => s.scope)
    .sort();
}

describe("readableScopes against the body read", () => {
  // MIRROR_ONLY_CONNECTOR_DISCOVERY
  it("lists an owner's first run of a connector the mirror has never seen", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(61)));
    const ns = await f.key.ns("acme", "account-1");
    f.overlay.runs = [overlayRun(ns, ["items"])];
    const service = await f.service();
    await f.sync(service);
    const universe = ["pdpp.acme.items", "pdpp.acme.other", "pdpp.nobody.x"];
    const read = await bodyReadable(service, universe, true);
    expect(read).toEqual(["pdpp.acme.items"]);
    expect(await listed(service, true)).toEqual(read);
    // A grant never sees the owner's local run, in the body or the list.
    expect(await bodyReadable(service, universe, false)).toEqual([]);
    expect(await listed(service, false)).toEqual([]);
  });

  // OMIT_OVERLAY_STREAM_NAMES
  it("lists an overlay-only stream beside an imported one of the same connector", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(62)));
    const ns = await f.key.ns("acme", "account-1");
    await f.activate("acme", ns);
    await f.publish({
      connector: "acme",
      ns,
      stream: "old",
      generation: 1,
      records: [{ id: "o" }],
      observedAt: T - 1000,
    });
    f.overlay.runs = [overlayRun(ns, ["new"])];
    const service = await f.service();
    await f.sync(service);
    const universe = ["pdpp.acme.old", "pdpp.acme.new", "pdpp.acme.none"];
    const owner = await bodyReadable(service, universe, true);
    expect(owner).toEqual(["pdpp.acme.new", "pdpp.acme.old"]);
    expect(await listed(service, true)).toEqual(owner);
    const grant = await bodyReadable(service, universe, false);
    expect(grant).toEqual(["pdpp.acme.old"]);
    expect(await listed(service, false)).toEqual(grant);
  });

  it("builds no view or body while deciding", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(63)));
    const ns = await f.key.ns("acme", "account-1");
    await f.activate("acme", ns);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a" }],
      observedAt: T - 1000,
    });
    const service = await f.service();
    await f.sync(service);
    const resolve = vi.spyOn(service, "resolve");
    const serve = vi.spyOn(service as any, "serveView");
    expect(await listed(service, true)).toEqual(["pdpp.acme.items"]);
    expect(resolve).not.toHaveBeenCalled();
    expect(serve).not.toHaveBeenCalled();
  });
});

describe("readableScopes work is bounded by the grant", () => {
  async function many(count: number) {
    const f = new Fixture(await testOwnerKey(masterKey(64)));
    const ns = await f.key.ns("acme", "account-1");
    await f.activate("acme", ns);
    const names = Array.from({ length: count }, (_, i) => `s${i}`);
    f.overlay.runs = [overlayRun(ns, names)];
    const service = await f.service();
    await f.sync(service);
    return { f, service };
  }

  // RESOLVE_BEFORE_GRANT_AND_PAGE
  it("checks only the covered scope among 1000 candidates", async () => {
    const { service } = await many(1000);
    const eligibility = vi.spyOn(service as any, "eligibility");
    const resolve = vi.spyOn(service, "resolve");
    const names = await listed(service, true, {
      isCovered: (scope) => scope === "pdpp.acme.s7",
    });
    expect(names).toEqual(["pdpp.acme.s7"]);
    expect(eligibility.mock.calls.length).toBeLessThanOrEqual(2);
    expect(resolve).not.toHaveBeenCalled();
  });

  it("lets an uncovered broken scope neither block nor be checked", async () => {
    const { service } = await many(3);
    const real = (service as any).eligibility.bind(service);
    vi.spyOn(service as any, "eligibility").mockImplementation(((
      input: { scope: string },
      ...rest: unknown[]
    ) => {
      if (input.scope === "pdpp.acme.s1") throw new Error("broken");
      return real(input, ...rest);
    }) as never);
    expect(
      await listed(service, true, {
        isCovered: (scope) => scope === "pdpp.acme.s2",
      }),
    ).toEqual(["pdpp.acme.s2"]);
  });

  it("skips a covered broken scope, logs it, and still lists the others", async () => {
    const warn = vi.fn();
    const f = new Fixture(await testOwnerKey(masterKey(65)));
    const ns = await f.key.ns("acme", "account-1");
    await f.activate("acme", ns);
    f.overlay.runs = [overlayRun(ns, ["s1", "s2"])];
    const service = await f.service({
      logger: { info() {}, warn, error() {} },
    });
    await f.sync(service);
    const real = (service as any).eligibility.bind(service);
    vi.spyOn(service as any, "eligibility").mockImplementation(((
      input: { scope: string },
      ...rest: unknown[]
    ) => {
      if (input.scope === "pdpp.acme.s1") throw new Error("broken");
      return real(input, ...rest);
    }) as never);
    expect(await listed(service, true)).toEqual(["pdpp.acme.s2"]);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(warn.mock.calls[0])).toContain("pdpp.acme.s1");
  });
});
