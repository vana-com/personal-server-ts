import { describe, it, expect, vi, beforeEach } from "vitest";
import { uiRoute } from "./ui.js";

// Mock fs.readFileSync to avoid needing the actual HTML file during tests
vi.mock("node:fs", () => ({
  readFileSync: () =>
    '<html><script>const TOKEN = "__DEV_TOKEN__"; window.__PS_LITE_BOOTSTRAP__ = "__PS_LITE_BOOTSTRAP_JSON__";</script></html>',
}));

describe("uiRoute", () => {
  const DEV_TOKEN = "test-dev-token-456";
  const BOOTSTRAP = {
    ownerSignature: "0xsignature" as `0x${string}`,
    config: { gateway: { url: "https://gateway.example" } },
  };

  beforeEach(() => {
    // Reset the cached HTML between tests by clearing the module-level cache
    // Since we mocked readFileSync, each test gets a fresh read
  });

  it("serves HTML with dev token injected", async () => {
    const app = uiRoute({ devToken: DEV_TOKEN });

    const res = await app.request("/");

    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(`const TOKEN = "${DEV_TOKEN}";`);
    expect(html).not.toContain("__DEV_TOKEN__");
  });

  // The owner signature is the master-key signature: it recovers the owner
  // identity and derives the storage encryption key. It must never be written
  // into a page that any GET can fetch. The page obtains it at runtime from
  // the dev-token-gated /api/bootstrap endpoint instead.
  it("never embeds the PS Lite bootstrap (owner signature) in the HTML", async () => {
    const app = uiRoute({ devToken: DEV_TOKEN, psLiteBootstrap: BOOTSTRAP });

    const res = await app.request("/");

    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).not.toContain("0xsignature");
    expect(html).not.toContain("ownerSignature");
    expect(html).not.toContain("__PS_LITE_BOOTSTRAP_JSON__");
    expect(html).toContain("window.__PS_LITE_BOOTSTRAP__ = null;");
  });

  it("returns HTML content type", async () => {
    const app = uiRoute({ devToken: DEV_TOKEN });

    const res = await app.request("/");

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
  });

  it("serves the browser PS Lite debug bundle", async () => {
    const app = uiRoute({ devToken: DEV_TOKEN });

    const res = await app.request("/ps-lite-debug.js");

    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/javascript");
  });

  describe("GET /api/bootstrap", () => {
    it("rejects a request without the dev token", async () => {
      const app = uiRoute({ devToken: DEV_TOKEN, psLiteBootstrap: BOOTSTRAP });

      const res = await app.request("/api/bootstrap");

      expect(res.status).toBe(401);
      expect(await res.text()).not.toContain("0xsignature");
    });

    it("rejects a wrong dev token", async () => {
      const app = uiRoute({ devToken: DEV_TOKEN, psLiteBootstrap: BOOTSTRAP });

      const res = await app.request("/api/bootstrap", {
        headers: { authorization: "Bearer not-the-token" },
      });

      expect(res.status).toBe(401);
      expect(await res.text()).not.toContain("0xsignature");
    });

    it("returns the bootstrap to a dev-token holder", async () => {
      const app = uiRoute({ devToken: DEV_TOKEN, psLiteBootstrap: BOOTSTRAP });

      const res = await app.request("/api/bootstrap", {
        headers: { authorization: `Bearer ${DEV_TOKEN}` },
      });

      expect(res.status).toBe(200);
      expect(res.headers.get("cache-control")).toBe("no-store");
      expect(await res.json()).toEqual(BOOTSTRAP);
    });

    it("404s when no bootstrap is configured", async () => {
      const app = uiRoute({ devToken: DEV_TOKEN });

      const res = await app.request("/api/bootstrap", {
        headers: { authorization: `Bearer ${DEV_TOKEN}` },
      });

      expect(res.status).toBe(404);
    });
  });
});
