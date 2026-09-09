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
