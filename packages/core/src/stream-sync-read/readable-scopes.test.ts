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
import { Rig } from "./writer-rig.js";

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

describe("readableScopes with the real writer overlay", () => {
  // OVERLAY_CONNECTORS_EMPTY
  it("lists an owner's first run, collected and not yet published, of an unseen connector", async () => {
    const rig = new Rig();
    await rig.open();
    await rig.collect({
      runId: "first",
      key: "id",
      version: "1.0.0",
      rows: [{ id: "a" }],
      full: true,
    });
    expect(await rig.overlay.connectors()).toEqual([rig.connector]);
    const scope = `pdpp.${rig.connector}.items`;
    const read = await bodyReadable(rig.service, [scope], true);
    expect(read).toEqual([scope]);
    expect(await listed(rig.service, true)).toEqual(read);
  });
});

describe("readableScopes survives one connector's local failure", () => {
  async function twoConnectors() {
    const f = new Fixture(await testOwnerKey(masterKey(66)));
    for (const connector of ["acme", "bee"]) {
      const ns = await f.key.ns(connector, "account-1");
      await f.activate(connector, ns);
      await f.publish({
        connector,
        ns,
        stream: "items",
        generation: 1,
        records: [{ id: "a" }],
        observedAt: T - 1000,
      });
    }
    // Connector `bee`'s local state cannot be read (a retained run with
    // missing byte counts): its snapshot rejects, `acme`'s works.
    const overlay = {
      observeDeletes: f.overlay.observeDeletes?.bind(f.overlay),
      acknowledge: f.overlay.acknowledge.bind(f.overlay),
      connectors: async () => ["acme", "bee"],
      snapshot: async (connector: string) => {
        if (connector === "bee") throw new Error("ready stream has no counts");
        return f.overlay.snapshot(connector);
      },
    };
    const service = await f.service({ overlay });
    await f.sync(service);
    return service;
  }

  // ABORT_CANDIDATE_DISCOVERY
  it("lists A when B's overlay fails, covered or not, and A's body still reads", async () => {
    const service = await twoConnectors();
    expect(await bodyReadable(service, ["pdpp.acme.items"], true)).toEqual([
      "pdpp.acme.items",
    ]);
    await expect(
      listed(service, true, { isCovered: (s) => s === "pdpp.acme.items" }),
    ).resolves.toEqual(["pdpp.acme.items"]);
    await expect(
      listed(service, true, {
        isCovered: (s) => s === "pdpp.acme.items" || s === "pdpp.bee.items",
      }),
    ).resolves.toEqual(["pdpp.acme.items"]);
    // Nothing is covered but B's own scope: B fails, A is not asked.
    await expect(
      listed(service, true, { isCovered: (s) => s === "pdpp.bee.items" }),
    ).resolves.toEqual([]);
  });
  // OVERLAY_CONNECTORS_DROP_ALL
  it("keeps the last good overlay connector set when connectors() fails", async () => {
    const warn = vi.fn();
    const f = new Fixture(await testOwnerKey(masterKey(70)));
    const ns = await f.key.ns("acme", "account-1");
    f.overlay.runs = [overlayRun(ns, ["items"])];
    const service = await f.service({
      logger: { info() {}, warn, error() {} },
    });
    await f.sync(service);
    const real = f.overlay.connectors.bind(f.overlay);
    let down = false;
    f.overlay.connectors = async () => {
      if (down) throw new Error("overlay index unavailable");
      return real();
    };
    expect(await listed(service, true)).toEqual(["pdpp.acme.items"]);
    down = true;
    expect(await listed(service, true)).toEqual(["pdpp.acme.items"]);
    const skips = warn.mock.calls.filter((c) =>
      JSON.stringify(c).includes("overlay connectors"),
    );
    expect(skips).toHaveLength(1);
  });
});

describe("readableScopes against what a body read can build", () => {
  const readOk = async (
    service: StreamSyncReadService,
    scope: string,
    isOwnerView: boolean,
  ) => {
    const decision = await service.resolve(ask(scope, { isOwnerView }));
    if (decision.kind !== "view" && decision.kind !== "local_pending") {
      return false;
    }
    JSON.parse(await new Response(decision.body).text());
    return true;
  };

  // LIST_UNSERVABLE_PROJECTION
  it("omits an alias over the size budget and keeps the control alias", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(67)));
    const ns = await f.key.ns("linkedin", "account-1");
    await f.activate("linkedin", ns);
    await f.publish({
      connector: "linkedin",
      ns,
      stream: "skills",
      generation: 1,
      records: Array.from({ length: 60 }, (_, i) => ({
        id: `s${i}`,
        name: `a skill with a fairly long name number ${i}`,
        endorsement_count: i,
      })),
      observedAt: T - 1000,
    });
    await f.publish({
      connector: "linkedin",
      ns,
      stream: "languages",
      generation: 1,
      records: [{ id: "l", name: "en", proficiency: "native" }],
      observedAt: T - 1000,
    });
    const service = await f.service({ arrayProjectionBudgetBytes: 400 });
    await f.sync(service);
    const universe = [
      "linkedin.skills",
      "linkedin.languages",
      "pdpp.linkedin.skills",
      "pdpp.linkedin.languages",
    ];
    for (const isOwnerView of [true, false]) {
      const served: string[] = [];
      for (const scope of universe) {
        if (await readOk(service, scope, isOwnerView)) served.push(scope);
      }
      expect(served.sort()).toEqual([
        "linkedin.languages",
        "pdpp.linkedin.languages",
        "pdpp.linkedin.skills",
      ]);
      const names = (await listed(service, isOwnerView)).filter((n) =>
        universe.includes(n),
      );
      expect(names).toEqual([...served].sort());
    }
  });

  it("omits an owner alias whose partial view cannot be projected", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(68)));
    f.overlay.connector = "strava-browser";
    const ns = await f.key.ns("strava-browser", "account-1");
    await f.activate("strava-browser", ns);
    await f.publish({
      connector: "strava-browser",
      ns,
      stream: "activities",
      generation: 1,
      records: [{ id: "old" }],
      observedAt: T - 1000,
      profileKey: "unmapped",
      profileVersion: "1.0.0",
      complete: false,
    });
    f.overlay.runs = [
      {
        runId: "r1",
        ns,
        generation: 1,
        observedAt: T,
        streams: [
          {
            name: "activities",
            complete: false,
            primaryKey: ["id"],
            version: "1.0.0",
            profileKey: "unmapped",
            rows: [{ o: T, r: "r1", v: { id: "new" } } as Line],
          },
        ],
      },
    ];
    const service = await f.service();
    await f.sync(service);
    expect(await readOk(service, "strava.activities", true)).toBe(false);
    const names = await listed(service, true);
    expect(names).not.toContain("strava.activities");
    expect(names).toContain("pdpp.strava-browser.activities");
  });

  // PROJECTABLE_KEY_OMITS_CONTROL
  it("a control change that imports nothing changes the listing", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(71)));
    const small = await f.key.ns("linkedin", "account-1");
    const big = await f.key.ns("linkedin", "account-2");
    await f.activate("linkedin", small);
    await f.activate("linkedin", big);
    await f.publish({
      connector: "linkedin",
      ns: small,
      stream: "skills",
      generation: 1,
      records: [{ id: "s", name: "x", endorsement_count: 1 }],
      observedAt: T - 1000,
    });
    // Published last, so this namespace's head is the newest and serves.
    await f.publish({
      connector: "linkedin",
      ns: big,
      stream: "skills",
      generation: 1,
      records: Array.from({ length: 60 }, (_, i) => ({
        id: `s${i}`,
        name: `a skill with a fairly long name number ${i}`,
        endorsement_count: i,
      })),
      observedAt: T - 1000,
    });
    const service = await f.service({ arrayProjectionBudgetBytes: 400 });
    await f.sync(service);
    const before = await readOk(service, "linkedin.skills", true);
    expect(before).toBe(false);
    expect((await listed(service, true)).includes("linkedin.skills")).toBe(
      false,
    );
    // Deleting the serving namespace writes control only: nothing is imported.
    await f.deleteConnection("linkedin", big);
    await service.observe([...f.rows.values()], {
      fromStart: true,
      lastPage: true,
    });
    const after = await readOk(service, "linkedin.skills", true);
    expect(after).toBe(true);
    expect((await listed(service, true)).includes("linkedin.skills")).toBe(
      true,
    );
  });

  // PROJECTOR_REFUSAL_NOT_CACHED
  it("a projector refusal is built once across listings with no version change", async () => {
    const f = new Fixture(await testOwnerKey(masterKey(72)));
    f.overlay.connector = "strava-browser";
    const ns = await f.key.ns("strava-browser", "account-1");
    await f.activate("strava-browser", ns);
    await f.publish({
      connector: "strava-browser",
      ns,
      stream: "activities",
      generation: 1,
      records: [{ id: "old" }],
      observedAt: T - 1000,
      profileKey: "unmapped",
      profileVersion: "1.0.0",
      complete: true,
    });
    const log = vi.fn();
    const service = await f.service({
      logger: { info: log, warn: log, error() {} },
    });
    await f.sync(service);
    const resolve = vi.spyOn(service, "resolve");
    const first = await listed(service, true);
    const second = await listed(service, true);
    expect(second).toEqual(first);
    expect(first).not.toContain("strava.activities");
    const builds = resolve.mock.calls.filter(
      ([input]) => input.scope === "strava.activities",
    );
    expect(builds).toHaveLength(1);
    const logged = log.mock.calls.filter((c) =>
      JSON.stringify(c).includes("strava.activities"),
    );
    expect(logged).toHaveLength(1);
  });
});
