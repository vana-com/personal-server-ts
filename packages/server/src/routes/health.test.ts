import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import type { RuntimeAvailabilityPort } from "@opendatalabs/personal-server-ts-core/ports";
import { describe, it, expect, vi } from "vitest";
import { healthRoute } from "./health.js";

describe("healthRoute", () => {
  const deps = { version: "0.0.1", startedAt: new Date() };

  function createMockGateway(
    overrides?: Partial<GatewayClient>,
  ): GatewayClient {
    return {
      isRegisteredBuilder: vi.fn().mockResolvedValue(true),
      getBuilder: vi.fn().mockResolvedValue(null),
      getGrant: vi.fn().mockResolvedValue(null),
      listGrantsByUser: vi.fn().mockResolvedValue([]),
      getSchemaForScope: vi.fn().mockResolvedValue(null),
      getServer: vi.fn().mockResolvedValue(null),
      registerServer: vi.fn().mockResolvedValue({
        alreadyRegistered: false,
      }),
      registerFile: vi.fn().mockResolvedValue({}),
      createGrant: vi.fn().mockResolvedValue({}),
      revokeGrant: vi.fn().mockResolvedValue(undefined),
      ...overrides,
    };
  }

  function createApp() {
    return healthRoute(deps);
  }

  it("GET /health returns 200", async () => {
    const app = createApp();
    const res = await app.request("/health");
    expect(res.status).toBe(200);
  });

  it("body has status, version, uptime, owner, and identity", async () => {
    const app = createApp();
    const res = await app.request("/health");
    const body = await res.json();

    expect(body.status).toBe("healthy");
    expect(body.version).toBe("0.0.1");
    expect(typeof body.uptime).toBe("number");
    expect(body.uptime).toBeGreaterThanOrEqual(0);
    expect(body.owner).toBeNull();
    expect(body.apiOrigin).toBeNull();
    expect(body.identity).toBeNull();
    expect(body.registration).toBeNull();
    expect(body.runtime).toEqual({
      kind: "ps-node",
      available: true,
    });
  });

  it("exposes runtime availability when an availability port is configured", async () => {
    const runtimeAvailability: RuntimeAvailabilityPort = {
      isAvailable: vi.fn().mockResolvedValue(false),
    };
    const app = healthRoute({
      version: "0.0.1",
      startedAt: new Date(),
      runtimeAvailability,
    });

    const res = await app.request("/health");
    const body = await res.json();

    expect(body.status).toBe("unavailable");
    expect(body.runtime).toEqual({
      kind: "ps-node",
      available: false,
    });
  });

  it("includes owner when serverOwner is set", async () => {
    const app = healthRoute({
      version: "0.0.1",
      startedAt: new Date(),
      serverOwner: "0x1234567890abcdef1234567890abcdef12345678",
    });
    const res = await app.request("/health");
    const body = await res.json();

    expect(body.owner).toBe("0x1234567890abcdef1234567890abcdef12345678");
  });

  it("owner is null when serverOwner is not set", async () => {
    const app = healthRoute({ version: "0.0.1", startedAt: new Date() });
    const res = await app.request("/health");
    const body = await res.json();

    expect(body.owner).toBeNull();
  });

  it("uptime increases over time", async () => {
    const past = new Date(Date.now() - 5000);
    const app = healthRoute({ version: "0.0.1", startedAt: past });
    const res = await app.request("/health");
    const body = await res.json();

    expect(body.uptime).toBeGreaterThanOrEqual(5);
  });

  it("Content-Type is application/json", async () => {
    const app = createApp();
    const res = await app.request("/health");
    expect(res.headers.get("content-type")).toMatch(/application\/json/);
  });

  it("identity is null when not configured", async () => {
    const app = healthRoute({ version: "0.0.1", startedAt: new Date() });
    const res = await app.request("/health");
    const body = await res.json();
    expect(body.identity).toBeNull();
  });

  it("includes identity info when configured", async () => {
    const app = healthRoute({
      version: "0.0.1",
      startedAt: new Date(),
      identity: {
        address: "0xServerAddr",
        publicKey: "0x04PubKey",
        serverId: "0xserver1",
      },
    });
    const res = await app.request("/health");
    const body = await res.json();

    expect(body.identity).not.toBeNull();
    expect(body.identity.address).toBe("0xServerAddr");
    expect(body.identity.publicKey).toBe("0x04PubKey");
    expect(body.identity.serverId).toBe("0xserver1");
  });

  it("includes registration candidate when owner, identity, and api URL are available", async () => {
    const app = healthRoute({
      version: "0.0.1",
      startedAt: new Date(),
      serverOwner: "0x1234567890abcdef1234567890abcdef12345678",
      serverOrigin: "http://localhost:8080",
      identity: {
        address: "0xServerAddr",
        publicKey: "0x04PubKey",
        serverId: "0xserver1",
      },
      getTunnelStatus: () => ({
        enabled: true,
        status: "connected",
        publicUrl: "https://0xserveraddr.server.vana.org",
        connectedSince: "2026-02-04T10:30:00.000Z",
      }),
    });
    const res = await app.request("/health");
    const body = await res.json();

    expect(body.apiOrigin).toBe("https://0xserveraddr.server.vana.org");
    expect(body.registration).toEqual({
      ownerAddress: "0x1234567890abcdef1234567890abcdef12345678",
      serverAddress: "0xServerAddr",
      publicKey: "0x04PubKey",
      serverUrl: "https://0xserveraddr.server.vana.org",
      serverId: "0xserver1",
      registered: true,
    });
  });

  it("identity shows serverId null when not registered", async () => {
    const app = healthRoute({
      version: "0.0.1",
      startedAt: new Date(),
      identity: {
        address: "0xServerAddr",
        publicKey: "0x04PubKey",
        serverId: null,
      },
    });
    const res = await app.request("/health");
    const body = await res.json();

    expect(body.identity.serverId).toBeNull();
  });

  it("re-checks gateway registration on every /health call", async () => {
    const getServer = vi
      .fn()
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce({
        id: "0xlive-server",
        ownerAddress: "0xOwner",
        serverAddress: "0xServerAddr",
        publicKey: "0x04PubKey",
        serverUrl: "https://example.com",
        addedAt: "2026-01-21T10:00:00.000Z",
      });

    const gateway = createMockGateway({ getServer });

    const app = healthRoute({
      version: "0.0.1",
      startedAt: new Date(),
      identity: {
        address: "0xServerAddr",
        publicKey: "0x04PubKey",
        serverId: null,
      },
      gateway,
    });

    const first = await app.request("/health");
    const firstBody = await first.json();
    expect(firstBody.identity.serverId).toBeNull();

    const second = await app.request("/health");
    const secondBody = await second.json();
    expect(secondBody.identity.serverId).toBe("0xlive-server");
    expect(getServer).toHaveBeenCalledTimes(2);
    expect(getServer).toHaveBeenCalledWith("0xServerAddr");
  });

  it("tunnel is null when getTunnelStatus is not provided", async () => {
    const app = healthRoute({ version: "0.0.1", startedAt: new Date() });
    const res = await app.request("/health");
    const body = await res.json();
    expect(body.tunnel).toBeNull();
  });

  it("includes tunnel status when getTunnelStatus is provided", async () => {
    const app = healthRoute({
      version: "0.0.1",
      startedAt: new Date(),
      getTunnelStatus: () => ({
        enabled: true,
        status: "connected",
        publicUrl: "https://0xabc.server.vana.org",
        connectedSince: "2026-02-04T10:30:00.000Z",
      }),
    });
    const res = await app.request("/health");
    const body = await res.json();

    expect(body.tunnel).not.toBeNull();
    expect(body.tunnel.enabled).toBe(true);
    expect(body.tunnel.status).toBe("connected");
    expect(body.tunnel.publicUrl).toBe("https://0xabc.server.vana.org");
    expect(body.tunnel.connectedSince).toBe("2026-02-04T10:30:00.000Z");
  });

  it("reports a connected tunnel as not routable while server registration is missing", async () => {
    const app = healthRoute({
      version: "0.0.1",
      startedAt: new Date(),
      serverOwner: "0x1234567890abcdef1234567890abcdef12345678",
      serverOrigin: "http://localhost:8080",
      identity: {
        address: "0xServerAddr",
        publicKey: "0x04PubKey",
        serverId: null,
      },
      getTunnelStatus: () => ({
        enabled: true,
        status: "connected",
        publicUrl: "https://0xserveraddr.server.vana.org",
        connectedSince: "2026-02-04T10:30:00.000Z",
      }),
    });
    const res = await app.request("/health");
    const body = await res.json();

    expect(body.tunnel.status).toBe("connected");
    expect(body.tunnel.routable).toBe(false);
    expect(body.tunnel.warning).toBe("Server not registered with gateway");
    expect(body.tunnel.error).toBeUndefined();
    expect(body.registration.registered).toBe(false);
  });

  it("preserves tunnel routing warnings separately from registration", async () => {
    const app = healthRoute({
      version: "0.0.1",
      startedAt: new Date(),
      serverOwner: "0x1234567890abcdef1234567890abcdef12345678",
      identity: {
        address: "0xServerAddr",
        publicKey: "0x04PubKey",
        serverId: "0xserver1",
      },
      getTunnelStatus: () => ({
        enabled: true,
        status: "connected",
        publicUrl: "https://0xserveraddr.server.vana.org",
        connectedSince: "2026-02-04T10:30:00.000Z",
        routable: false,
        warning: "HTTP 404",
      }),
    });
    const res = await app.request("/health");
    const body = await res.json();

    expect(body.registration.registered).toBe(true);
    expect(body.tunnel.status).toBe("connected");
    expect(body.tunnel.routable).toBe(false);
    expect(body.tunnel.warning).toBe("HTTP 404");
    expect(body.tunnel.error).toBeUndefined();
  });

  it("tunnel status reflects disconnected state", async () => {
    const app = healthRoute({
      version: "0.0.1",
      startedAt: new Date(),
      getTunnelStatus: () => ({
        enabled: true,
        status: "disconnected",
        publicUrl: null,
        connectedSince: null,
        error: "Connection lost",
      }),
    });
    const res = await app.request("/health");
    const body = await res.json();

    expect(body.tunnel.status).toBe("disconnected");
    expect(body.tunnel.publicUrl).toBeNull();
    expect(body.tunnel.error).toBe("Connection lost");
  });
});
