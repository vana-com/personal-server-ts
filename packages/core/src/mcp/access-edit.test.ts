import { describe, expect, it, vi } from "vitest";
import { createInMemoryMcpConnectionStore } from "./store.js";
import {
  approveMcpConnection,
  createMcpConnection,
  McpConnectionStateError,
  McpScopeRequestError,
  requestMcpScopeAccess,
  revokeMcpConnection,
  setMcpConnectionAccess,
} from "./connection-api.js";
import {
  createFakeGrantGateway,
  type FakeGrantGatewayOptions,
} from "../test-utils/fake-grant-gateway.js";

const OWNER = "0x00000000000000000000000000000000000000aa" as const;
const ORIGIN = "https://example-session.relay.test";

const serverSigner = {
  signGrantRegistration: vi.fn(async () => "0xsig" as `0x${string}`),
  signGrantRevocation: vi.fn(async () => "0xrev" as `0x${string}`),
};

/** Seeds the gateway and the connection with the same two old grants. */
async function setup(
  gatewayOptions: FakeGrantGatewayOptions = {},
  grants = [
    { grantId: "0xold1", scopes: ["instagram.*"] },
    { grantId: "0xold2", scopes: ["chatgpt.history", "write:memory.claude"] },
  ],
) {
  const fake = createFakeGrantGateway(gatewayOptions);
  for (const grant of grants) fake.seed(grant.grantId, grant.scopes);
  const store = createInMemoryMcpConnectionStore();
  const created = await createMcpConnection(
    { displayName: "Maple" },
    { store, publicOrigin: ORIGIN },
  );
  await approveMcpConnection(
    { connectionId: created.connectionId, grants },
    { store },
  );
  return { store, id: created.connectionId, fake };
}

const opts = (
  store: ReturnType<typeof createInMemoryMcpConnectionStore>,
  fake: ReturnType<typeof createFakeGrantGateway>,
) => ({
  store,
  gateway: fake.gateway,
  serverOwner: OWNER,
  serverSigner,
  now: () => new Date("2026-11-10T10:00:00.000Z"),
});

describe("setMcpConnectionAccess", () => {
  it("widens: one new grant, same connection id and token, old grants proven revoked", async () => {
    const { store, id, fake } = await setup();
    const before = await store.getById(id);

    const result = await setMcpConnectionAccess(
      {
        connectionId: id,
        scopes: [
          "instagram.*",
          "chatgpt.history",
          "youtube.history",
          "write:memory.claude",
        ],
      },
      opts(store, fake),
    );

    const after = await store.getById(id);
    expect(after?.id).toBe(before?.id);
    expect(after?.tokenHash).toBe(before?.tokenHash);
    expect(after?.grants).toEqual([
      { grantId: result.grantId, scopes: result.grantedScopes },
    ]);
    expect(result.grantedScopes).toEqual([
      "chatgpt.history",
      "instagram.*",
      "write:memory.claude",
      "youtube.history",
    ]);
    // Checked at the gateway, not from the call's return value.
    expect(fake.grants.get("0xold1")?.revokedAt).toBeTruthy();
    expect(fake.grants.get("0xold2")?.revokedAt).toBeTruthy();
    expect(fake.grants.get(result.grantId)?.revokedAt).toBeNull();
    expect(result.revokedGrantIds).toEqual(["0xold1", "0xold2"]);
    expect(result.revokeFailures).toEqual([]);
    expect(after?.pendingRevocations).toBeUndefined();
    expect(after?.accessEdit).toBeUndefined();
    expect(after?.scopeAccessDecision?.approvedScopes).toEqual([
      "youtube.history",
    ]);
  });

  it("narrows to a subset the same way", async () => {
    const { store, id, fake } = await setup();
    const result = await setMcpConnectionAccess(
      { connectionId: id, scopes: ["instagram.*"] },
      opts(store, fake),
    );
    expect(result.grantedScopes).toEqual(["instagram.*"]);
    expect((await store.getById(id))?.grants).toEqual([
      { grantId: result.grantId, scopes: ["instagram.*"] },
    ]);
    expect(fake.grants.get("0xold1")?.revokedAt).toBeTruthy();
    expect(fake.grants.get("0xold2")?.revokedAt).toBeTruthy();
  });

  // P1-1: the revoke must never be able to hit the new grant, and a revoke
  // signed at the old grant's own version + 1 is a swallowed 409.
  describe("replacement under the gateway's shared version counter", () => {
    it("signs each revoke above the counter and never revokes the new grant", async () => {
      const { store, id, fake } = await setup();
      const result = await setMcpConnectionAccess(
        { connectionId: id, scopes: ["instagram.*"] },
        opts(store, fake),
      );
      const versions = serverSigner.signGrantRevocation.mock.calls
        .slice(-2)
        .map(([args]) => (args as { grantVersion: bigint }).grantVersion);
      const registered = BigInt(
        (await fake.gateway.getGrant(result.grantId))!.grantVersion,
      );
      expect(versions[0]).toBeGreaterThan(registered);
      expect(versions[1]).toBeGreaterThan(versions[0]);
      expect(fake.grants.get(result.grantId)?.revokedAt).toBeNull();
    });

    it("does not count a swallowed 409 revoke as revoked", async () => {
      // A gateway whose revoke does nothing but looks successful.
      const { store, id, fake } = await setup();
      const original = fake.gateway.revokeGrant.bind(fake.gateway);
      fake.gateway.revokeGrant = async () => undefined;
      const result = await setMcpConnectionAccess(
        { connectionId: id, scopes: ["instagram.*"] },
        opts(store, fake),
      );
      expect(result.revokedGrantIds).toEqual([]);
      expect(result.revokeFailures.map((f) => f.grantId)).toEqual([
        "0xold1",
        "0xold2",
      ]);
      expect((await store.getById(id))?.pendingRevocations).toEqual([
        "0xold1",
        "0xold2",
      ]);
      fake.gateway.revokeGrant = original;
    });

    it("refuses to revoke when the new grant is found revoked afterwards", async () => {
      const { store, id, fake } = await setup({
        afterRevoke: (grant) => {
          // The revoke took the newest grant too (a lying counter).
          for (const g of fake.grants.values()) {
            if (g.id.startsWith("0xnew")) g.revokedAt = grant.revokedAt;
          }
        },
      });
      const result = await setMcpConnectionAccess(
        { connectionId: id, scopes: ["instagram.*"] },
        opts(store, fake),
      );
      expect(result.revokeFailures[0]?.error).toMatch(/new grant/);
      // The second old grant is not touched once the new one is in doubt.
      expect(result.revokeFailures.map((f) => f.grantId)).toContain("0xold2");
    });
  });

  // P1-3
  describe("failed revocation stays retryable", () => {
    it("keeps un-revoked ids on the connection and retries them on the next edit", async () => {
      let down = true;
      const { store, id, fake } = await setup({
        throwOnRevoke: (grantId) => down && grantId === "0xold1",
      });
      const first = await setMcpConnectionAccess(
        { connectionId: id, scopes: ["instagram.*"] },
        opts(store, fake),
      );
      expect(first.revokeFailures).toEqual([
        { grantId: "0xold1", error: "gateway down" },
      ]);
      expect(first.revokedGrantIds).toEqual(["0xold2"]);
      const mid = await store.getById(id);
      expect(mid?.grants[0].grantId).toBe(first.grantId);
      expect(mid?.pendingRevocations).toEqual(["0xold1"]);

      down = false;
      const second = await setMcpConnectionAccess(
        { connectionId: id, scopes: ["instagram.*"] },
        opts(store, fake),
      );
      expect(second.revokedGrantIds).toContain("0xold1");
      expect(fake.grants.get("0xold1")?.revokedAt).toBeTruthy();
      // The first edit's grant is now superseded and revoked too.
      expect(fake.grants.get(first.grantId)?.revokedAt).toBeTruthy();
      expect((await store.getById(id))?.pendingRevocations).toBeUndefined();
    });

    it("keeps a write scope only if a LIVE gateway grant holds it", async () => {
      const { store, id, fake } = await setup();
      // The local record still names the write grant, but the gateway has
      // revoked it (or it expired).
      fake.grants.get("0xold2")!.revokedAt = "2026-11-01T00:00:00.000Z";
      await expect(
        setMcpConnectionAccess(
          { connectionId: id, scopes: ["instagram.*", "write:memory.claude"] },
          opts(store, fake),
        ),
      ).rejects.toMatchObject({ code: "WRITE_SCOPE_NOT_GRANTED" });
      expect(fake.counter()).toBe(2n); // no registration happened
    });

    it("rejects a kept write scope on an expired gateway grant", async () => {
      const { store, id, fake } = await setup();
      fake.grants.get("0xold2")!.expired = true;
      await expect(
        setMcpConnectionAccess(
          { connectionId: id, scopes: ["write:memory.claude"] },
          opts(store, fake),
        ),
      ).rejects.toMatchObject({ code: "WRITE_SCOPE_NOT_GRANTED" });
    });

    it("rejects a legacy non-memory or wildcard write entry even if held", async () => {
      const { store, id, fake } = await setup({}, [
        { grantId: "0xold1", scopes: ["instagram.*", "write:instagram.*"] },
      ]);
      await expect(
        setMcpConnectionAccess(
          { connectionId: id, scopes: ["instagram.*", "write:instagram.*"] },
          opts(store, fake),
        ),
      ).rejects.toMatchObject({ code: "WRITE_SCOPE_NOT_GRANTED" });
    });
  });

  // P1-2
  describe("concurrent edits", () => {
    it("the loser never registers a grant at the gateway", async () => {
      const { store, id, fake } = await setup();
      const [a, b] = await Promise.allSettled([
        setMcpConnectionAccess(
          { connectionId: id, scopes: ["instagram.*"] },
          opts(store, fake),
        ),
        setMcpConnectionAccess(
          { connectionId: id, scopes: ["chatgpt.history"] },
          opts(store, fake),
        ),
      ]);
      const winners = [a, b].filter((r) => r.status === "fulfilled");
      expect(winners).toHaveLength(1);
      const loser = [a, b].find(
        (r) => r.status === "rejected",
      ) as PromiseRejectedResult;
      expect(loser.reason).toMatchObject({ code: "CONCURRENT_UPDATE" });
      // Exactly one live new grant exists, and it is the stored one.
      const liveNew = [...fake.grants.values()].filter(
        (g) => g.id.startsWith("0xnew") && !g.revokedAt,
      );
      expect(liveNew).toHaveLength(1);
      expect((await store.getById(id))?.grants[0].grantId).toBe(liveNew[0].id);
    });

    it("parks a registered grant when the local commit loses", async () => {
      const { store, id, fake } = await setup();
      // Another writer changes the connection's grants after our claim and
      // before our commit: the gateway create is where we can interleave.
      const create = fake.gateway.createGrant.bind(fake.gateway);
      fake.gateway.createGrant = async (params) => {
        const out = await create(params);
        await store.mutate(id, (latest) => ({
          ...latest,
          grants: [{ grantId: "0xother", scopes: ["spotify.library"] }],
        }));
        return out;
      };
      await expect(
        setMcpConnectionAccess(
          { connectionId: id, scopes: ["instagram.*"] },
          opts(store, fake),
        ),
      ).rejects.toMatchObject({ code: "CONCURRENT_UPDATE" });
      const after = await store.getById(id);
      expect(after?.accessEdit).toBeUndefined();
      expect(after?.pendingRevocations).toEqual(["0xnew1"]);
    });

    it("refuses an approve while an edit is in flight", async () => {
      const { store, id, fake } = await setup();
      await store.mutate(id, (latest) => ({
        ...latest,
        accessEdit: {
          claimId: "other",
          startedAt: "2026-11-10T10:00:00.000Z",
        },
      }));
      await expect(
        setMcpConnectionAccess(
          { connectionId: id, scopes: ["instagram.*"] },
          opts(store, fake),
        ),
      ).rejects.toMatchObject({ code: "CONCURRENT_UPDATE" });
      expect(fake.counter()).toBe(2n);
    });

    it("takes over a stale edit claim", async () => {
      const { store, id, fake } = await setup();
      await store.mutate(id, (latest) => ({
        ...latest,
        accessEdit: {
          claimId: "crashed",
          startedAt: "2026-11-10T09:00:00.000Z",
        },
      }));
      const result = await setMcpConnectionAccess(
        { connectionId: id, scopes: ["instagram.*"] },
        opts(store, fake),
      );
      expect(result.revokeFailures).toEqual([]);
    });
  });

  describe("create collision (the SDK swallows a 409 on create)", () => {
    it("rejects an id the gateway did not register with the requested scopes", async () => {
      const { store, id, fake } = await setup();
      // Another request already advanced the counter: our create is a 409 and
      // the SDK returns the id of the latest existing grant.
      fake.seed("0xother", ["spotify.library"]);
      const before = await store.getById(id);
      await expect(
        setMcpConnectionAccess(
          { connectionId: id, scopes: ["instagram.*"] },
          opts(store, fake),
        ),
      ).rejects.toMatchObject({ code: "GRANT_CREATION_FAILED" });
      const after = await store.getById(id);
      expect(after?.grants).toEqual(before?.grants);
      expect(after?.accessEdit).toBeUndefined();
      // The foreign grant is parked for revocation, not left untracked.
      expect(after?.pendingRevocations).toEqual(["0xother"]);
    });

    it("rejects when the gateway grant's scopes differ from the request", async () => {
      const { store, id, fake } = await setup();
      const create = fake.gateway.createGrant.bind(fake.gateway);
      fake.gateway.createGrant = async (params) =>
        create({ ...params, scopes: [...params.scopes, "extra.scope"] });
      await expect(
        setMcpConnectionAccess(
          { connectionId: id, scopes: ["instagram.*"] },
          opts(store, fake),
        ),
      ).rejects.toMatchObject({ code: "GRANT_CREATION_FAILED" });
      expect((await store.getById(id))?.pendingRevocations).toEqual(["0xnew1"]);
    });
  });

  it("clears a pending request the new set covers, keeps the rest", async () => {
    const { store, id, fake } = await setup();
    await requestMcpScopeAccess(
      { connectionId: id, scopes: ["youtube.history", "spotify.library"] },
      { store },
    );
    await setMcpConnectionAccess(
      { connectionId: id, scopes: ["instagram.*", "youtube.history"] },
      opts(store, fake),
    );
    const after = await store.getById(id);
    expect(after?.scopeAccessRequest?.scopes).toEqual(["spotify.library"]);
    expect(after?.scopeAccessDecision).toMatchObject({
      decision: "approved",
      approvedScopes: ["youtube.history"],
      deniedScopes: ["spotify.library"],
    });

    await setMcpConnectionAccess(
      {
        connectionId: id,
        scopes: ["instagram.*", "youtube.history", "spotify.library"],
      },
      opts(store, fake),
    );
    expect((await store.getById(id))?.scopeAccessRequest).toBeUndefined();
  });

  it.each([
    ["empty", []],
    ["not an array", "instagram.*"],
    ["system scope", ["vana.system.state"]],
    ["malformed scope", ["not a scope"]],
    ["new wildcard", ["instagram.*", "youtube.*"]],
    ["new write access", ["instagram.*", "write:memory.other"]],
  ])("rejects %s without touching the gateway", async (_name, scopes) => {
    const { store, id, fake } = await setup();
    await expect(
      setMcpConnectionAccess({ connectionId: id, scopes }, opts(store, fake)),
    ).rejects.toBeInstanceOf(McpScopeRequestError);
    expect(fake.counter()).toBe(2n);
    expect((await store.getById(id))?.accessEdit).toBeUndefined();
  });

  it("rejects a revoked connection", async () => {
    const { store, id, fake } = await setup();
    await revokeMcpConnection(id, { store });
    await expect(
      setMcpConnectionAccess(
        { connectionId: id, scopes: ["instagram.*"] },
        opts(store, fake),
      ),
    ).rejects.toBeInstanceOf(McpConnectionStateError);
  });
});
