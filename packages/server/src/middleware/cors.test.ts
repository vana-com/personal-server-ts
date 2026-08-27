import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { WRITE_SIGNATURE_HEADER } from "@opendatalabs/personal-server-ts-core/write";
import {
  CORS_ALLOW_HEADERS,
  CORS_EXPOSE_HEADERS,
  corsMiddleware,
} from "./cors.js";

function lowerList(value: string | null): string[] {
  return (value ?? "").split(",").map((h) => h.trim().toLowerCase());
}

describe("CORS middleware", () => {
  function createApp() {
    const app = new Hono();
    app.use("*", corsMiddleware());
    app.get("/test", (c) => c.json({ ok: true }));
    app.post("/test", (c) => c.json({ ok: true }));
    return app;
  }

  it("OPTIONS preflight returns correct CORS headers", async () => {
    const app = createApp();
    const res = await app.request("/test", {
      method: "OPTIONS",
      headers: {
        Origin: "https://example.com",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type, Authorization",
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
    expect(res.headers.get("Access-Control-Allow-Methods")).toContain("POST");
    expect(res.headers.get("Access-Control-Allow-Headers")).toContain(
      "Content-Type",
    );
    expect(res.headers.get("Access-Control-Max-Age")).toBe("86400");
  });

  it("allowlists every non-safelisted request header the API reads", async () => {
    const app = createApp();
    const res = await app.request("/test", {
      method: "OPTIONS",
      headers: {
        Origin: "https://example.com",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": CORS_ALLOW_HEADERS.join(", "),
      },
    });
    expect(res.status).toBe(204);
    const allowed = lowerList(res.headers.get("Access-Control-Allow-Headers"));
    // Browsers match header names case-insensitively; so do we.
    for (const header of [
      "authorization",
      "content-type",
      WRITE_SIGNATURE_HEADER,
      "x-vana-metadata",
      "x-filename",
      "content-disposition",
      "x-ps-grant-id",
      "x-payment",
    ]) {
      expect(allowed).toContain(header);
    }
  });

  it("exposes the response headers a browser client reads back", async () => {
    const app = createApp();
    const res = await app.request("/test", {
      method: "GET",
      headers: { Origin: "https://example.com" },
    });
    expect(res.status).toBe(200);
    const exposed = lowerList(res.headers.get("Access-Control-Expose-Headers"));
    for (const header of CORS_EXPOSE_HEADERS) {
      expect(exposed).toContain(header.toLowerCase());
    }
    expect(exposed).toContain("x-vana-metadata");
    expect(exposed).toContain("x-payment-response");
  });

  it("regular GET includes Access-Control-Allow-Origin: *", async () => {
    const app = createApp();
    const res = await app.request("/test", {
      method: "GET",
      headers: { Origin: "https://example.com" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  it("regular POST includes Access-Control-Allow-Origin: *", async () => {
    const app = createApp();
    const res = await app.request("/test", {
      method: "POST",
      headers: {
        Origin: "https://example.com",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ data: "test" }),
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });
});
