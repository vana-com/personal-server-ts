import { expect, it, vi } from "vitest";
import {
  createCachedReplicaRoster,
  createGatewayReplicaRoster,
  REPLICA_ROSTER_MAX_AGE_MS,
  ReplicaRosterUnavailableError,
  type ReplicaRosterRecord,
} from "./roster.js";

const server = `0x${"1".repeat(40)}` as const;
const record: ReplicaRosterRecord = {
  owner: `0x${"a".repeat(40)}`,
  id: `0x${"2".repeat(64)}`,
  revokedAt: null,
};

it("serves an answer for at most five minutes, then reads again", async () => {
  let time = 0;
  let answer: ReplicaRosterRecord | null = record;
  const port = { server: vi.fn(async () => answer) };
  const roster = createCachedReplicaRoster(port, { now: () => time });
  await expect(roster.server(server)).resolves.toEqual(record);
  answer = { ...record, revokedAt: "2026-10-27T00:00:00Z" };
  time = REPLICA_ROSTER_MAX_AGE_MS - 1;
  await expect(roster.server(server)).resolves.toEqual(record);
  time = REPLICA_ROSTER_MAX_AGE_MS;
  await expect(roster.server(server)).resolves.toEqual(answer);
  expect(port.server).toHaveBeenCalledTimes(2);
  // Proven absence is an answer and is cached the same way.
  answer = null;
  time += REPLICA_ROSTER_MAX_AGE_MS;
  await expect(roster.server(server)).resolves.toBeNull();
  await expect(roster.server(server)).resolves.toBeNull();
  expect(port.server).toHaveBeenCalledTimes(3);
});

it("never serves an expired answer when the gateway is down", async () => {
  let time = 0;
  let down = false;
  const roster = createCachedReplicaRoster(
    {
      async server() {
        if (down) throw new Error("ECONNRESET");
        return record;
      },
    },
    { now: () => time },
  );
  await roster.server(server);
  down = true;
  time = 1000;
  await expect(roster.server(server)).resolves.toEqual(record);
  time = REPLICA_ROSTER_MAX_AGE_MS;
  await expect(roster.server(server)).rejects.toBeInstanceOf(
    ReplicaRosterUnavailableError,
  );
});

it("bounds its entries and shares one read per address", async () => {
  const port = { server: vi.fn(async () => record) };
  const roster = createCachedReplicaRoster(port, { maxEntries: 2 });
  await Promise.all([roster.server(server), roster.server(server)]);
  expect(port.server).toHaveBeenCalledTimes(1);
  await roster.server(`0x${"2".repeat(40)}`);
  await roster.server(`0x${"3".repeat(40)}`);
  // The oldest entry was evicted, so this is a new read.
  await roster.server(server);
  expect(port.server).toHaveBeenCalledTimes(4);
  // Addresses compare case-insensitively.
  await roster.server(
    `0x${"3".repeat(40)}`.toUpperCase().replace("0X", "0x") as `0x${string}`,
  );
  expect(port.server).toHaveBeenCalledTimes(4);
});

it("reads the gateway server record and proves absence only from its JSON 404", async () => {
  const respond = (status: number, body: unknown) =>
    vi.fn(async () => new Response(JSON.stringify(body), { status }));
  const data = {
    id: record.id,
    ownerAddress: record.owner,
    serverAddress: server,
    publicKey: "0x04",
    serverUrl: "https://ps.example",
    addedAt: "2026-10-01T00:00:00Z",
    revokedAt: null,
  };
  const roster = (fetch: typeof globalThis.fetch) =>
    createGatewayReplicaRoster({ gatewayUrl: "https://gw.example/", fetch });
  const ok = respond(200, { data, proof: {} });
  await expect(roster(ok).server(server)).resolves.toEqual(record);
  expect(ok.mock.calls[0]![0]).toBe(`https://gw.example/v1/servers/${server}`);
  await expect(
    roster(respond(404, { error: "Server not found" })).server(server),
  ).resolves.toBeNull();
  for (const fetch of [
    respond(404, { error: "NOT_FOUND" }),
    respond(500, { error: "Server not found" }),
    respond(200, { data: { ...data, serverAddress: `0x${"9".repeat(40)}` } }),
    respond(200, { data: { ...data, id: "abc" } }),
    respond(200, {}),
    vi.fn(async () => new Response("<html>", { status: 404 })),
    vi.fn(async () => {
      throw new TypeError("fetch failed");
    }),
  ])
    await expect(roster(fetch as never).server(server)).rejects.toBeInstanceOf(
      ReplicaRosterUnavailableError,
    );
});
