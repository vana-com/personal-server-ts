import { expect, it } from "vitest";
import { createFleetPeerClient, createFleetPeerServer } from "./peer.js";
import { createFakeDstackClient } from "../dstack/fake.js";
import type { FleetPeerIdentity } from "./contracts.js";
it("encrypts both directions, binds the admitted peer and rejects replay", async () => {
  const identity = (role: "worker" | "controller"): FleetPeerIdentity => ({
    role,
    nodeId: role,
    nodeIncarnation: "1",
    appId: role,
    instanceId: role,
    composeHash: role,
  });
  let calls = 0;
  const captures: { url: string; body: string }[] = [];
  const verifier = async (
    _e: unknown,
    _b: Uint8Array,
    peer: FleetPeerIdentity,
  ) => {
    if (peer.nodeId !== peer.role) throw new Error("not admitted");
  };
  const handler = createFleetPeerServer({
    identity: identity("worker"),
    client: createFakeDstackClient({ appId: "1".repeat(40) }),
    verifyPeer: verifier,
    dispatch: async (_m, b) => {
      calls++;
      return { secret: b };
    },
  });
  const wire: typeof fetch = async (input, init) => {
    captures.push({ url: String(input), body: String(init?.body) });
    return handler(new Request(input, init));
  };
  const client = createFleetPeerClient({
    identity: identity("controller"),
    client: createFakeDstackClient({ appId: "1".repeat(40) }),
    verifyPeer: verifier,
    baseUrl: "https://worker.invalid",
    expectedPeer: identity("worker"),
    fetch: wire,
  });
  expect(await client.call("execute", { secret: "private plaintext" })).toEqual(
    { secret: { secret: "private plaintext" } },
  );
  expect(captures.some((c) => c.body.includes("private plaintext"))).toBe(
    false,
  );
  const replay = captures.at(-1)!;
  expect(
    (
      await handler(
        new Request(replay.url, { method: "POST", body: replay.body }),
      )
    ).status,
  ).toBe(403);
  expect(calls).toBe(1);
});

it("refuses a different admitted worker before sending the owner payload", async () => {
  const makeIdentity = (nodeId: string): FleetPeerIdentity => ({
    role: "worker",
    nodeId,
    nodeIncarnation: `${nodeId}-inc`,
    appId: "workers",
    instanceId: nodeId,
    composeHash: "approved",
  });
  const actual = makeIdentity("b"),
    expected = makeIdentity("a");
  let wireCalls = 0;
  const handler = createFleetPeerServer({
    identity: actual,
    client: createFakeDstackClient({ appId: "1".repeat(40) }),
    verifyPeer: async () => {},
    dispatch: async () => {
      throw new Error("must never receive owner A");
    },
  });
  const client = createFleetPeerClient({
    identity: { ...makeIdentity("controller"), role: "controller" },
    expectedPeer: expected,
    client: createFakeDstackClient({ appId: "1".repeat(40) }),
    verifyPeer: async () => {},
    baseUrl: "https://a.invalid",
    fetch: async (input, init) => {
      wireCalls++;
      return handler(new Request(input, init));
    },
  });
  await expect(
    client.call("execute", { owner: "A", secret: "payload" }),
  ).rejects.toThrow("Unexpected peer destination");
  expect(wireCalls).toBe(1);
});

it("rejects oversized public handshakes before asking dstack for a quote", async () => {
  const client = createFakeDstackClient({ appId: "1".repeat(40) });
  let quotes = 0;
  const quote = client.quote;
  client.quote = async (data) => {
    quotes++;
    return quote(data);
  };
  const identity: FleetPeerIdentity = {
    role: "worker",
    nodeId: "worker",
    nodeIncarnation: "1",
    appId: "app",
    instanceId: "instance",
    composeHash: "compose",
  };
  const handler = createFleetPeerServer({
    identity,
    client,
    verifyPeer: async () => {},
    dispatch: async () => null,
  });
  const response = await handler(
    new Request("https://worker.invalid/fleet-peer/v1/challenge", {
      method: "POST",
      body: JSON.stringify({
        identity,
        nonce: "a".repeat(64),
        publicKey: "key",
        padding: "x".repeat(65_536),
      }),
    }),
  );
  expect(response.status).toBe(403);
  expect(quotes).toBe(0);
});

it("accepts equivalent identities whose properties use a different order", async () => {
  const worker: FleetPeerIdentity = {
    appId: "app",
    instanceId: "instance",
    composeHash: "compose",
    role: "worker",
    nodeId: "worker",
    nodeIncarnation: "1",
  };
  const controller: FleetPeerIdentity = {
    ...worker,
    role: "controller",
    nodeId: "controller",
  };
  const dstack = createFakeDstackClient({ appId: "1".repeat(40) });
  const handler = createFleetPeerServer({
    identity: worker,
    client: dstack,
    verifyPeer: async () => {},
    dispatch: async () => "accepted",
  });
  const client = createFleetPeerClient({
    identity: controller,
    expectedPeer: worker,
    client: dstack,
    verifyPeer: async () => {},
    baseUrl: "https://worker.invalid",
    fetch: async (input, init) => handler(new Request(input, init)),
  });
  await expect(client.call("execute", {})).resolves.toBe("accepted");
});

it("describes only the exact canonical identity later used by a pinned call", async () => {
  const worker = {
    role: "worker" as const,
    nodeId: "a",
    nodeIncarnation: "boot",
    appId: "app",
    instanceId: "instance",
    composeHash: "compose",
    osVersion: "0.5.9",
  };
  const dstack = createFakeDstackClient({ appId: "1".repeat(40) });
  const handler = createFleetPeerServer({
    identity: worker,
    client: dstack,
    verifyPeer: async () => {},
    dispatch: async () => "accepted",
  });
  const options = {
    identity: { ...worker, role: "controller" as const, nodeId: "controller" },
    client: dstack,
    verifyPeer: async () => {},
    baseUrl: "https://worker.invalid",
    fetch: (async (input, init) =>
      handler(new Request(input, init))) as typeof fetch,
  };
  const described = await createFleetPeerClient(options).call<{
    identity: FleetPeerIdentity;
  }>("describe", {});
  const pinned = createFleetPeerClient({
    ...options,
    expectedPeer: described.identity,
  });
  await expect(pinned.call("execute", {})).resolves.toBe("accepted");
});
