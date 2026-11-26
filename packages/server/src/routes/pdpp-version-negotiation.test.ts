import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import { pdppVersionMiddleware } from "./pdpp-version-negotiation.js";

const report = () => "req_test";

describe("pdppVersionMiddleware scope (mounted at /v1 like the records router)", () => {
  function app() {
    let mutated = 0;
    const core = new Hono();
    core.use(
      "*",
      pdppVersionMiddleware(report, (path) =>
        /^(\/v1)?\/(streams|records|blobs\/ingest)(\/|$)/.test(path),
      ),
    );
    core.get("/streams", (c) => c.json({ ok: true }));
    const root = new Hono();
    root.route("/v1", core);
    // A non-PDPP router mounted later under the same prefix, as /v1/data is.
    const data = new Hono();
    data.post("/:scope", (c) => {
      mutated += 1;
      return c.json({ stored: true }, 201);
    });
    root.route("/v1/data", data);
    return { root, mutated: () => mutated };
  }

  it("leaves non-Core /v1 routes alone: a write with any PDPP-Version behaves as without it", async () => {
    const a = app();
    const res = await a.root.request("/v1/data/x", {
      method: "POST",
      headers: { "PDPP-Version": "2026-04-06" },
    });
    expect(res.status).toBe(201);
    expect(a.mutated()).toBe(1);
  });

  it("still negotiates on Core paths", async () => {
    const res = await app().root.request("/v1/streams", {
      headers: { "PDPP-Version": "2026-04-06" },
    });
    // The route here skips authentication, so the safety net refuses it.
    expect(res.status).toBe(400);
    expect(res.headers.get("PDPP-Version")).toBeNull();
  });
});

describe("pdppVersionMiddleware safety net", () => {
  it("replaces a success after a failed negotiation without keeping the refused response's headers", async () => {
    const core = new Hono();
    core.use("*", pdppVersionMiddleware(report, () => true));
    core.get("/blob", (c) =>
      c.redirect("https://signed.example/blob?sig=secret", 302),
    );
    const res = await core.request("/blob", {
      headers: { "PDPP-Version": "9" },
    });
    expect(res.status).toBe(400);
    expect(res.headers.get("Location")).toBeNull();
    expect(res.headers.get("PDPP-Version")).toBeNull();
  });
});
