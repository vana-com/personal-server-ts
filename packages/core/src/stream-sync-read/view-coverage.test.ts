/**
 * `viewCoverage` answers "do the stream views cover this legacy scope, and up
 * to when": the question a legacy delete asks.
 */

import { describe, expect, it } from "vitest";
import {
  alternateLegacyBindingsForScope,
  LEGACY_SCOPE_BINDINGS,
} from "../legacy-projection/index.js";
import { Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

const OBSERVED = Date.parse("2026-11-03T00:00:00Z");

async function setup(seed: number) {
  const f = new Fixture(await testOwnerKey(await masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  await f.activate("acme", ns);
  return { f, ns };
}

describe("viewCoverage", () => {
  it("covers a complete live view, through the head's observation time", async () => {
    const { f, ns } = await setup(901);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a" }],
      complete: true,
      observedAt: OBSERVED,
    });
    const service = await f.service();
    await f.sync(service);
    expect(service.viewCoverage("pdpp.acme.items")).toEqual({
      kind: "covered",
      throughMs: OBSERVED,
    });
  });

  it("skips an incomplete view", async () => {
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
    expect(service.viewCoverage("pdpp.acme.items")).toEqual({
      kind: "skip",
      reason: "incomplete",
    });
  });

  it("skips an unknown connector, a physical name and an unlisted mirror", async () => {
    const { f } = await setup(903);
    const service = await f.service();
    expect(service.viewCoverage("pdpp.acme.items").kind).toBe("skip");
    await f.sync(service);
    expect(service.viewCoverage("pdpp.other.items").kind).toBe("skip");
    expect(service.viewCoverage("pdpp.acme~0123456789abcdef.items").kind).toBe(
      "skip",
    );
  });

  it("does not count another owner's head: a connection under a foreign key is not a view", async () => {
    const f = new Fixture(await testOwnerKey(await masterKey(904)));
    const other = await testOwnerKey(await masterKey(905));
    const otherNs = await other.ns("acme", "account-1");
    await f.activate("acme", otherNs, other);
    await f.publish({
      connector: "acme",
      ns: otherNs,
      stream: "items",
      generation: 1,
      records: [{ id: "a" }],
      complete: true,
      key: other,
    });
    const service = await f.service();
    await f.sync(service);
    expect(service.viewCoverage("pdpp.acme.items").kind).toBe("skip");
  });

  it("is ambiguous when the connector has two active connections", async () => {
    const { f, ns } = await setup(906);
    const second = await f.key.ns("acme", "account-2");
    await f.activate("acme", second);
    for (const n of [ns, second]) {
      await f.publish({
        connector: "acme",
        ns: n,
        stream: "items",
        generation: 1,
        records: [{ id: n }],
        complete: true,
      });
    }
    const service = await f.service();
    await f.sync(service);
    expect(service.viewCoverage("pdpp.acme.items")).toEqual({
      kind: "skip",
      reason: "ambiguous",
    });
  });

  describe("a scope with an alternate binding has more than one target", () => {
    // A scope whose alternate binding is read from another connector.
    const scope = "oura.sleep";
    const original = LEGACY_SCOPE_BINDINGS.get(scope)!;
    const originalConnector = original.pdppSource.slice(
      original.pdppSource.lastIndexOf("/") + 1,
    );
    const [profileKey, alternate] = [
      ...alternateLegacyBindingsForScope(scope),
    ][0]!;

    async function publishTarget(
      f: Fixture,
      connector: string,
      streams: readonly string[],
      complete = true,
    ) {
      const ns = await f.key.ns(connector, "account-1");
      await f.activate(connector, ns);
      for (const stream of streams) {
        await f.publish({
          connector,
          ns,
          stream,
          generation: 1,
          records: [{ id: "a" }],
          complete,
          observedAt: OBSERVED,
        });
      }
    }

    it("covers only when EVERY target is complete", async () => {
      expect(profileKey).not.toBe(originalConnector);
      const f = new Fixture(await testOwnerKey(await masterKey(910)));
      await publishTarget(f, originalConnector, original.pdppStreams);
      // The alternate target is known but its head is incomplete.
      await publishTarget(f, profileKey, alternate.pdppStreams, false);
      const service = await f.service();
      await f.sync(service);
      expect(service.viewCoverage(scope).kind).toBe("skip");

      const ns = await f.key.ns(profileKey, "account-1");
      for (const stream of alternate.pdppStreams) {
        await f.publish({
          connector: profileKey,
          ns,
          stream,
          generation: 1,
          records: [{ id: "b" }],
          complete: true,
          observedAt: OBSERVED,
        });
      }
      await f.sync(service);
      expect(service.viewCoverage(scope)).toEqual({
        kind: "covered",
        throughMs: OBSERVED,
      });
    });
  });
});

// ---------------------------------------------------------------------------
// Membership and the edges that decide a delete.
// ---------------------------------------------------------------------------

import { retireLegacyScopes } from "../sync/workers/retire-legacy.js";
import { entityKeySets } from "../storage/legacy-entity-key-sets.js";
import type { DataStoragePort } from "../ports/index.js";

const SCOPE = "strava.activities";
const CONNECTOR = "strava-browser";
const activityRow = (id: string) => ({
  id,
  activity_type: "Ride",
  start_date: "2026-09-20",
  start_date_local: "2026-09-20",
  start_time: "2026-09-20T06:30:00-07:00",
  start_time_basis: "local",
  distance_m: 32150.4,
  moving_time_s: 5400,
  elapsed_time_s: 6120,
  total_elevation_gain_m: 610,
  average_heartrate: null,
  max_heartrate: null,
  calories_kcal: null,
  gear: null,
  freshness: "live",
  exported_at: null,
});

async function stravaView(
  seed: number,
  ids: readonly string[],
  observedAt = OBSERVED,
) {
  const f = new Fixture(await testOwnerKey(await masterKey(seed)));
  // strava.activities has two targets: the original binding's connector and
  // the browser connector's alternate. Both must be complete to cover it.
  for (const [connector, profile] of [
    ["strava", {}],
    [CONNECTOR, { profileKey: CONNECTOR, profileVersion: "2.0.0" }],
  ] as const) {
    const ns = await f.key.ns(connector, "account-1");
    await f.activate(connector, ns);
    await f.publish({
      connector,
      ns,
      stream: "activities",
      generation: 1,
      records: ids.map(activityRow),
      complete: true,
      observedAt,
      ...profile,
    });
  }
  const service = await f.service();
  await f.sync(service);
  return { f, service };
}

const body = (ids: readonly string[]) => ({
  activities: ids.map((id) => ({ id })),
});

/** Retire one scope against the real reader; the local file holds `ids`. */
async function retireWith(
  service: Awaited<ReturnType<typeof stravaView>>["service"],
  localIds: readonly string[],
  collectedAt = "2026-11-01T00:00:00.000Z",
) {
  const local = new Set([SCOPE]);
  const entry = {
    id: 1,
    fileId: null,
    schemaId: null,
    path: "p",
    scope: SCOPE,
    collectedAt,
    createdAt: collectedAt,
    sizeBytes: 1,
    version: 1,
    dataPointId: null,
  };
  const storage = {
    listScopes: () => ({
      total: 1,
      scopes: [...local].map((scope) => ({
        scope,
        latestCollectedAt: collectedAt,
        versionCount: 1,
      })),
    }),
    listVersions: () => (local.has(SCOPE) ? [entry] : []),
    readEnvelope: async () => ({ data: body(localIds) }),
  } as unknown as DataStoragePort;
  const deleted: string[] = [];
  const result = await retireLegacyScopes({
    storage,
    switchedAt: "2026-11-05T00:00:00.000Z",
    coverage: (scope) => service.viewCoverage(scope),
    viewKeys: (scope) => service.viewKeys(scope),
    registeredAt: async () => null,
    deleteScope: async (scope) => {
      deleted.push(scope);
      local.delete(scope);
      return { durable: true } as never;
    },
    logger: { info: () => {}, warn: () => {} },
  });
  return { result, deleted };
}

describe("membership against the real reader", () => {
  it("viewKeys returns the keys the served view holds", async () => {
    const { service } = await stravaView(920, ["a", "c"]);
    expect(await service.viewKeys(SCOPE)).toEqual(
      entityKeySets(SCOPE, body(["a", "c"])),
    );
    expect(await service.viewKeys("pdpp.acme.items")).toBeNull(); // not keyed
  });

  it("head complete at T1 holds {a}; the local version at T0 < T1 holds {a, b}: skipped, not deleted", async () => {
    const { service } = await stravaView(921, ["a"], OBSERVED);
    expect(service.viewCoverage(SCOPE).kind).toBe("covered"); // time says yes
    const { result, deleted } = await retireWith(service, ["a", "b"]);
    expect(deleted).toEqual([]);
    expect(result.skipped.notInView).toBe(1);
    expect(result.deleted).toBe(0);
  });

  it("the view holds every key of the local version: deleted", async () => {
    const { service } = await stravaView(922, ["a", "b", "extra"]);
    const { result, deleted } = await retireWith(service, ["a", "b"]);
    expect(deleted).toEqual([SCOPE]);
    expect(result.deleted).toBe(1);
  });

  it("a view that is not complete serves no keys: skipped", async () => {
    const f = new Fixture(await testOwnerKey(await masterKey(923)));
    const ns = await f.key.ns(CONNECTOR, "account-1");
    await f.activate(CONNECTOR, ns);
    await f.publish({
      connector: CONNECTOR,
      ns,
      stream: "activities",
      generation: 1,
      records: [activityRow("a")],
      complete: false,
      observedAt: OBSERVED,
      profileKey: CONNECTOR,
      profileVersion: "2.0.0",
    });
    const service = await f.service();
    await f.sync(service);
    expect(await service.viewKeys(SCOPE)).toBeNull();
  });
});

describe("viewCoverage: the edges a delete relies on", () => {
  it("a mirror that does not hold the whole registry listing covers nothing", async () => {
    const f = new Fixture(await testOwnerKey(await masterKey(930)));
    const ns = await f.key.ns("acme", "account-1");
    await f.activate("acme", ns);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a" }],
      complete: true,
      observedAt: OBSERVED,
    });
    const service = await f.service();
    // The first page of a longer listing: the mirror is not whole yet.
    await service.observe([...f.rows.values()], {
      fromStart: true,
      lastPage: false,
    });
    expect(service.viewCoverage("pdpp.acme.items")).toEqual({
      kind: "skip",
      reason: "incomplete",
    });
    await f.sync(service); // the whole listing arrives
    expect(service.viewCoverage("pdpp.acme.items").kind).toBe("covered");
  });

  it("covers through the OLDEST head of a multi-stream scope, not the newest", async () => {
    const scope = "chatgpt.conversations";
    const binding = LEGACY_SCOPE_BINDINGS.get(scope)!;
    expect(binding.pdppStreams.length).toBeGreaterThan(1);
    const f = new Fixture(await testOwnerKey(await masterKey(931)));
    const ns = await f.key.ns("chatgpt", "account-1");
    await f.activate("chatgpt", ns);
    const times = [OBSERVED - 5000, OBSERVED, OBSERVED + 5000];
    let i = 0;
    for (const stream of binding.pdppStreams) {
      await f.publish({
        connector: "chatgpt",
        ns,
        stream,
        generation: 1,
        records: [{ id: "a" }],
        complete: true,
        observedAt: times[i++ % times.length]!,
      });
    }
    const service = await f.service();
    await f.sync(service);
    expect(service.viewCoverage(scope)).toEqual({
      kind: "covered",
      throughMs: OBSERVED - 5000,
    });
  });

  it("one incomplete stream of a multi-stream target keeps the whole scope uncovered", async () => {
    const scope = "chatgpt.conversations";
    const binding = LEGACY_SCOPE_BINDINGS.get(scope)!;
    const f = new Fixture(await testOwnerKey(await masterKey(932)));
    const ns = await f.key.ns("chatgpt", "account-1");
    await f.activate("chatgpt", ns);
    let first = true;
    for (const stream of binding.pdppStreams) {
      await f.publish({
        connector: "chatgpt",
        ns,
        stream,
        generation: 1,
        records: [{ id: "a" }],
        complete: first, // only the first stream is complete
        observedAt: OBSERVED,
      });
      first = false;
    }
    const service = await f.service();
    await f.sync(service);
    expect(service.viewCoverage(scope).kind).toBe("skip");
  });
});
