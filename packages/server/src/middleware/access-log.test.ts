import { describe, it, expect, vi } from "vitest";
import { Hono } from "hono";
import { createAccessLogMiddleware } from "./access-log.js";
import type {
  AccessLogWriter,
  AccessLogEntry,
} from "@opendatalabs/personal-server-ts-core/logging/access-log";
import type { VerifiedAuth } from "@opendatalabs/vana-sdk/node";
import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/node";

function createMockWriter(
  overrides: Partial<AccessLogWriter> = {},
): AccessLogWriter & { write: ReturnType<typeof vi.fn> } {
  return {
    write: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

function createApp(
  writer: AccessLogWriter,
  options: {
    status?: number;
    setAuth?: boolean;
    setGrant?: boolean;
    policyBypass?: boolean;
  } = {},
) {
  const {
    status = 200,
    setAuth = true,
    setGrant = true,
    policyBypass = false,
  } = options;
  const app = new Hono();
  const accessLog = createAccessLogMiddleware(writer);

  const auth: VerifiedAuth = {
    signer: "0xBuilderAddress" as `0x${string}`,
    payload: {
      aud: "http://localhost:8080",
      method: "GET",
      uri: "/v1/data/instagram.profile",
      bodyHash: "",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
      grantId: "grant-123",
    },
  };

  const grant: GatewayGrantResponse = {
    id: "grant-123",
    grantorAddress: "0xOwnerAddress",
    granteeId: "0xbuilder1",
    grant: JSON.stringify({
      scopes: ["instagram.*"],
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
    }),
    fileIds: [],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    revokedAt: null,
    revocationSignature: null,
  };

  // Simulate upstream middleware setting context
  app.use("/v1/data/:scope", async (c, next) => {
    if (setAuth) c.set("auth", auth);
    if (setGrant) c.set("grant", grant);
    if (policyBypass) c.set("isPolicyBypass", true);
    await next();
  });

  app.get("/v1/data/:scope", accessLog, (c) => {
    return c.json({ ok: true }, status as 200);
  });

  // Route that returns 401 (simulating auth failure)
  app.use("/v1/fail/:scope", async (c, next) => {
    // Don't set auth/grant — simulating upstream failure
    await next();
  });
  app.get("/v1/fail/:scope", accessLog, (c) => {
    return c.json({ error: "unauthorized" }, 401);
  });

  return app;
}

function createSuccessfulAuditFixture() {
  const entries: AccessLogEntry[] = [];
  const audit = createAccessLogMiddleware({
    write: (entry) => {
      entries.push(entry);
      return Promise.resolve();
    },
  });

  return {
    entries,
    record: async (scope: string) => {
      // Stand in for an already authorized, successful request. No router or
      // upstream middleware is involved in these record-format assertions.
      const context = {
        get(name: string) {
          if (name === "auth") return { signer: "fixture-reader" };
          if (name === "grant") return { id: "fixture-grant" };
          return undefined;
        },
        req: { param: () => scope, header: () => undefined },
        res: { status: 200 },
      } as unknown as Parameters<
        ReturnType<typeof createAccessLogMiddleware>
      >[0];
      await audit(context, () => Promise.resolve());
    },
  };
}

describe("successful access audit records", () => {
  it("keeps the scope label with the corresponding record", async () => {
    const { entries, record } = createSuccessfulAuditFixture();
    await record("synthetic.first");
    await record("synthetic.second");

    expect(entries.map(({ scope }) => scope)).toEqual([
      "synthetic.first",
      "synthetic.second",
    ]);
  });

  it("gives consecutive reads on the same scope distinct IDs", async () => {
    const { entries, record } = createSuccessfulAuditFixture();
    await record("synthetic.records");
    await record("synthetic.records");

    const ids = entries.map(({ logId }) => logId);
    expect(ids).toEqual([expect.any(String), expect.any(String)]);
    expect(new Set(ids).size).toBe(2);
  });
});

describe("createAccessLogMiddleware", () => {
  it("200 response writes entry with correct fields", async () => {
    const writer = createMockWriter();
    const app = createApp(writer);

    const res = await app.request("/v1/data/instagram.profile", {
      headers: { "user-agent": "TestAgent/1.0" },
    });

    expect(res.status).toBe(200);
    expect(writer.write).toHaveBeenCalledOnce();

    const entry = writer.write.mock.calls[0][0] as AccessLogEntry;
    expect(entry.grantId).toBe("grant-123");
    expect(entry.builder).toBe("0xBuilderAddress");
    expect(entry.action).toBe("read");
    expect(entry.scope).toBe("instagram.profile");
    expect(entry.userAgent).toBe("TestAgent/1.0");
    expect(entry.logId).toBeDefined();
    expect(entry.timestamp).toBeDefined();
  });

  it("401 response does not write entry", async () => {
    const writer = createMockWriter();
    const app = createApp(writer);

    const res = await app.request("/v1/fail/instagram.profile");

    expect(res.status).toBe(401);
    expect(writer.write).not.toHaveBeenCalled();
  });

  it("missing user-agent uses unknown", async () => {
    const writer = createMockWriter();
    const app = createApp(writer);

    const res = await app.request("/v1/data/instagram.profile");

    expect(res.status).toBe(200);
    expect(writer.write).toHaveBeenCalledOnce();

    const entry = writer.write.mock.calls[0][0] as AccessLogEntry;
    expect(entry.userAgent).toBe("unknown");
  });

  it("policy-bypass reads without grants are logged for debug UI visibility", async () => {
    const writer = createMockWriter();
    const app = createApp(writer, { setGrant: false, policyBypass: true });

    const res = await app.request("/v1/data/instagram.profile");

    expect(res.status).toBe(200);
    expect(writer.write).toHaveBeenCalledOnce();
    const entry = writer.write.mock.calls[0][0] as AccessLogEntry;
    expect(entry.grantId).toBe("policy-bypass");
    expect(entry.builder).toBe("0xBuilderAddress");
  });

  it("writer failure does not affect response", async () => {
    const writer = createMockWriter({
      write: vi.fn().mockRejectedValue(new Error("disk full")),
    });
    const app = createApp(writer);

    const res = await app.request("/v1/data/instagram.profile");

    expect(res.status).toBe(200);
    const json = (await res.json()) as { ok: boolean };
    expect(json.ok).toBe(true);
    expect(writer.write).toHaveBeenCalledOnce();
  });
});
