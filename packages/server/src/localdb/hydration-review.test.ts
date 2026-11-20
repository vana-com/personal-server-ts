import { afterEach, expect, it } from "vitest";
import { createLocalSync } from "../../../core/src/localdb/sync.js";
import { closeWorldDrivers, sName, world } from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

it("hydrates only after every connection succeeds", async () => {
  const w = await world({ streams: 1 });
  const peer = await w.device("peer");
  await peer.run("first", [{ stream: sName(0), id: "first" }]);
  await peer.run("second", [{ stream: sName(0), id: "second" }], {
    connector: "second-connector",
  });
  await peer.cycle();
  let fail = true;
  const here = await w.device("here", {
    beforeGet: async (key) => {
      if (fail && key.includes("pdpp.fixture"))
        throw new Error("download failed");
    },
  });
  const first = await here.sync.cycle();
  expect(first.connections).toHaveLength(2);
  expect(
    first.connections.some((c) => c.error?.includes("download failed")),
  ).toBe(true);
  expect((await here.sync.listing.status()).accountHydrated).toBe(false);
  fail = false;
  const second = await here.sync.cycle();
  expect(second.connections.every((c) => c.error === null)).toBe(true);
  expect(await here.rows()).toEqual(await peer.rows());
  expect((await here.sync.listing.status()).accountHydrated).toBe(true);
});

it("starts unhydrated when a runtime reopens the same database", async () => {
  const w = await world({ streams: 1 });
  const here = await w.device("here");
  await here.sync.cycle();
  expect((await here.sync.listing.status()).accountHydrated).toBe(true);
  const reopened = createLocalSync(here.deps, { resolveArtifact: () => null });
  expect((await reopened.listing.status()).accountHydrated).toBe(false);
});

it("keeps hydration false while a full download is held and a scoped retry runs", async () => {
  const w = await world({ streams: 1 });
  const peer = await w.device("peer");
  await peer.run("seed", [{ stream: sName(0), id: "first" }]);
  await peer.run("other", [{ stream: sName(0), id: "other" }], {
    connector: "second-connector",
  });
  await peer.cycle();
  let arrive!: () => void;
  let release!: () => void;
  const arrived = new Promise<void>((resolve) => {
    arrive = resolve;
  });
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const here = await w.device("here", {
    beforeGet: async (key) => {
      if (key.includes("pdpp.fixture")) {
        arrive();
        await held;
      }
    },
  });
  const full = here.sync.cycle();
  let publishing: Promise<unknown> | undefined;
  try {
    await arrived;
    expect((await here.sync.listing.status()).accountHydrated).toBe(false);
    expect(
      (await here.sync.cycle({ connections: ["pdpp.second-connector~"] }))
        .connections,
    ).toHaveLength(1);
    expect((await here.sync.listing.status()).accountHydrated).toBe(false);
    publishing = here.sync.publish();
    expect((await here.sync.listing.status()).accountHydrated).toBe(false);
  } finally {
    release();
    await full;
    await publishing;
  }
  expect((await here.sync.listing.status()).accountHydrated).toBe(true);
  expect(
    (await here.sync.cycle({ connections: ["pdpp.second-connector~"] }))
      .connections,
  ).toHaveLength(1);
  expect((await here.sync.listing.status()).accountHydrated).toBe(true);
});

it("reads a record whose connection appears on a later registry page", async () => {
  const { createGatewayStreamSyncRegistry } =
    await import("../../../core/src/stream-sync/registry.js");
  const w = await world({ streams: 1 });
  const peer = await w.device("paged-peer");
  await peer.run("first", [{ stream: sName(0), id: "first" }]);
  await peer.run("later", [{ stream: sName(0), id: "later" }], {
    connector: "second-connector",
  });
  await peer.cycle();
  const here = await w.device("paged-here");
  const laterScopes: string[] = [];
  const registry = createGatewayStreamSyncRegistry({
    gatewayUrl: "https://gateway.test",
    ownerAddress: here.deps.ownerAddress,
    listPageSize: 1,
    fetch: (async (input: string, init?: RequestInit) => {
      const url = new URL(input);
      const response = await w.gateway.fetch(input, init);
      if (url.pathname !== "/v1/data" || (init?.method ?? "GET") !== "GET")
        return response;
      const body = (await response.json()) as {
        data: { dataPoints: { scope: string }[] };
      };
      const offset = Number(url.searchParams.get("cursor") ?? "0");
      const rows = body.data.dataPoints.slice(offset, offset + 1);
      if (offset > 0) laterScopes.push(...rows.map((row) => row.scope));
      const next = offset + rows.length;
      return new Response(
        JSON.stringify({
          data: { dataPoints: rows },
          pagination: {
            hasMore: next < body.data.dataPoints.length,
            nextCursor: String(next),
          },
        }),
      );
    }) as typeof fetch,
  });
  const sync = createLocalSync(
    { ...here.deps, registry },
    { resolveArtifact: () => null },
  );
  expect((await sync.listing.status()).accountHydrated).toBe(false);
  await sync.apply();
  expect((await sync.listing.status()).accountHydrated).toBe(true);
  expect(laterScopes.some((scope) => scope.includes("second-connector"))).toBe(
    true,
  );
  const result = await sync.query.listRecords({
    connectionId: "pdpp.second-connector~",
    stream: sName(0),
  });
  expect(result.records).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        recordKey: "later",
        body: '{"id":"later"}',
      }),
    ]),
  );
});
