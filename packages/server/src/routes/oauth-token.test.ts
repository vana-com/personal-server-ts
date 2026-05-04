import { describe, it, expect, vi, beforeEach } from "vitest";
import { pino } from "pino";
import { oauthTokenRoutes } from "./oauth-token.js";
import type { TokenStore } from "../token-store.js";

const logger = pino({ level: "silent" });

function createMemoryTokenStore(): TokenStore {
  const tokens = new Map<string, { expiresAt: string | null }>();
  return {
    addToken: vi.fn(async (token: string, opts) => {
      tokens.set(token, { expiresAt: opts?.expiresAt ?? null });
    }),
    isValid: vi.fn(async (token: string) => {
      const entry = tokens.get(token);
      if (!entry) return false;
      if (entry.expiresAt && new Date(entry.expiresAt).getTime() < Date.now()) {
        return false;
      }
      return true;
    }),
    removeToken: vi.fn(async (token: string) => {
      tokens.delete(token);
    }),
  } as unknown as TokenStore;
}

function form(body: Record<string, string>): string {
  return new URLSearchParams(body).toString();
}

describe("POST /oauth/token", () => {
  describe("client_credentials grant", () => {
    let tokenStore: TokenStore;
    let app: ReturnType<typeof oauthTokenRoutes>;
    const SECRET = "vana_ps_supersecretcontrolplaneforthistest";

    beforeEach(() => {
      tokenStore = createMemoryTokenStore();
      app = oauthTokenRoutes({
        logger,
        tokenStore,
        controlPlaneSecret: SECRET,
      });
    });

    it("issues access_token for valid client_credentials in body", async () => {
      const res = await app.request("/", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: form({
          grant_type: "client_credentials",
          client_id: "control-plane",
          client_secret: SECRET,
        }),
      });
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.token_type).toBe("Bearer");
      expect(json.access_token).toMatch(/^vana_ps_[0-9a-f]+$/);
      expect(json.expires_in).toBeGreaterThan(0);
      expect(res.headers.get("cache-control")).toContain("no-store");
      // Verify the token was registered with the store.
      expect(await tokenStore.isValid(json.access_token)).toBe(true);
    });

    it("issues access_token for valid client_credentials via HTTP Basic", async () => {
      const basic = Buffer.from(`control-plane:${SECRET}`, "utf-8").toString(
        "base64",
      );
      const res = await app.request("/", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${basic}`,
        },
        body: form({ grant_type: "client_credentials" }),
      });
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.access_token).toMatch(/^vana_ps_/);
    });

    /**
     * Regression: RFC 6749 §2.3.1 requires the client_id and client_secret
     * sent via HTTP Basic to be `application/x-www-form-urlencoded` encoded
     * before base64. Conformant OAuth2 clients like `oauth4webapi` percent-
     * encode `-`, `_`, and other URL-significant characters. The server
     * MUST decode them before comparing.
     */
    it("accepts percent-encoded credentials in HTTP Basic per RFC 6749 §2.3.1", async () => {
      // application/x-www-form-urlencoded encoding of "control-plane" → "control%2Dplane"
      // and of the secret (which contains underscores) → uppercase %5F sequences.
      const encodedId = encodeURIComponent("control-plane").replace(
        /-/g,
        "%2D",
      );
      const encodedSecret = encodeURIComponent(SECRET).replace(/_/g, "%5F");
      const basic = Buffer.from(
        `${encodedId}:${encodedSecret}`,
        "utf-8",
      ).toString("base64");
      const res = await app.request("/", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${basic}`,
        },
        body: form({ grant_type: "client_credentials" }),
      });
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.access_token).toMatch(/^vana_ps_/);
    });

    it("returns invalid_client (401) for wrong client_secret", async () => {
      const res = await app.request("/", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: form({
          grant_type: "client_credentials",
          client_id: "control-plane",
          client_secret: "definitely-wrong",
        }),
      });
      expect(res.status).toBe(401);
      const json = await res.json();
      expect(json.error).toBe("invalid_client");
    });

    it("returns invalid_client (401) for unknown client_id", async () => {
      const res = await app.request("/", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: form({
          grant_type: "client_credentials",
          client_id: "some-random-app",
          client_secret: SECRET,
        }),
      });
      expect(res.status).toBe(401);
      const json = await res.json();
      expect(json.error).toBe("invalid_client");
    });

    it("returns invalid_client (401) for missing credentials", async () => {
      const res = await app.request("/", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: form({ grant_type: "client_credentials" }),
      });
      expect(res.status).toBe(401);
      const json = await res.json();
      expect(json.error).toBe("invalid_client");
    });

    it("returns unauthorized_client when controlPlaneSecret is not configured", async () => {
      const noSecret = oauthTokenRoutes({
        logger,
        tokenStore: createMemoryTokenStore(),
      });
      const res = await noSecret.request("/", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: form({
          grant_type: "client_credentials",
          client_id: "control-plane",
          client_secret: SECRET,
        }),
      });
      expect(res.status).toBe(401);
      const json = await res.json();
      expect(json.error).toBe("unauthorized_client");
    });
  });

  describe("device_code grant", () => {
    const sessionsByCode = new Map<
      string,
      {
        status: "pending" | "approved" | "expired";
        accessToken?: string;
        accessTokenExpiresAt?: string;
        sessionId: string;
      }
    >();

    function buildApp() {
      return oauthTokenRoutes({
        logger,
        tokenStore: createMemoryTokenStore(),
        controlPlaneSecret: "irrelevant-for-device-code",
        deviceSessions: {
          findByDeviceCode(code) {
            return sessionsByCode.get(code) ?? null;
          },
          consume(sessionId) {
            for (const [code, sess] of sessionsByCode) {
              if (sess.sessionId === sessionId) sessionsByCode.delete(code);
            }
          },
        },
      });
    }

    beforeEach(() => sessionsByCode.clear());

    it("returns access_token when device session is approved", async () => {
      sessionsByCode.set("dev-code-1", {
        status: "approved",
        sessionId: "sess-1",
        accessToken: "vana_ps_devtoken1234",
        accessTokenExpiresAt: new Date(
          Date.now() + 60 * 60 * 1000,
        ).toISOString(),
      });

      const res = await buildApp().request("/", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: "dev-code-1",
        }),
      });
      expect(res.status).toBe(200);
      const json = await res.json();
      expect(json.access_token).toBe("vana_ps_devtoken1234");
      expect(json.token_type).toBe("Bearer");
      expect(json.expires_in).toBeGreaterThan(0);
      // The session should have been consumed.
      expect(sessionsByCode.has("dev-code-1")).toBe(false);
    });

    it("returns authorization_pending when session is pending", async () => {
      sessionsByCode.set("dev-code-2", {
        status: "pending",
        sessionId: "sess-2",
      });

      const res = await buildApp().request("/", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: "dev-code-2",
        }),
      });
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error).toBe("authorization_pending");
    });

    it("returns expired_token when device_code is unknown", async () => {
      const res = await buildApp().request("/", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: "no-such-code",
        }),
      });
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error).toBe("expired_token");
    });

    it("returns invalid_request when device_code is missing", async () => {
      const res = await buildApp().request("/", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        }),
      });
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error).toBe("invalid_request");
    });
  });

  describe("error handling", () => {
    let app: ReturnType<typeof oauthTokenRoutes>;
    beforeEach(() => {
      app = oauthTokenRoutes({
        logger,
        tokenStore: createMemoryTokenStore(),
        controlPlaneSecret: "secret",
      });
    });

    it("rejects non-form-encoded content-type", async () => {
      const res = await app.request("/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ grant_type: "client_credentials" }),
      });
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error).toBe("invalid_request");
    });

    it("returns invalid_request when grant_type missing", async () => {
      const res = await app.request("/", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form({ client_id: "control-plane" }),
      });
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error).toBe("invalid_request");
    });

    it("returns unsupported_grant_type for unknown grants", async () => {
      const res = await app.request("/", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form({ grant_type: "password", username: "x", password: "y" }),
      });
      expect(res.status).toBe(400);
      const json = await res.json();
      expect(json.error).toBe("unsupported_grant_type");
    });
  });
});
