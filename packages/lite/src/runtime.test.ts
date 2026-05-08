import { describe, expect, it } from "vitest";
import { createPsLiteRuntime } from "./runtime.js";

describe("createPsLiteRuntime", () => {
  it("reports ps-lite availability through health", async () => {
    const runtime = createPsLiteRuntime({
      storage: { kind: "indexeddb" },
      active: true,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    const res = await runtime.fetch(new Request("https://ps.local/health"));

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toEqual({
      status: "healthy",
      runtime: "ps-lite",
      storage: "indexeddb",
      active: true,
      checkedAt: "2026-05-08T00:00:00.000Z",
    });
  });

  it("returns PS_UNAVAILABLE while the browser runtime is inactive", async () => {
    const runtime = createPsLiteRuntime({
      storage: { kind: "opfs" },
      active: false,
    });

    const res = await runtime.fetch(
      new Request("https://ps.local/v1/data/instagram.profile"),
    );

    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.error.errorCode).toBe("PS_UNAVAILABLE");
  });

  it("can be activated for foreground handling", async () => {
    const runtime = createPsLiteRuntime({
      storage: { kind: "indexeddb" },
      active: false,
    });

    expect(await runtime.isAvailable()).toBe(false);
    runtime.activate();
    expect(await runtime.isAvailable()).toBe(true);
  });
});
