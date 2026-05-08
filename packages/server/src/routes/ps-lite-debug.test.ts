import { describe, expect, it } from "vitest";
import { psLiteDebugRoutes } from "./ps-lite-debug.js";

const DEV_TOKEN = "debug-token";

function authHeaders() {
  return { Authorization: `Bearer ${DEV_TOKEN}` };
}

describe("psLiteDebugRoutes", () => {
  it("requires the dev token", async () => {
    const app = psLiteDebugRoutes({ devToken: DEV_TOKEN });

    const res = await app.request("/health");

    expect(res.status).toBe(401);
  });

  it("returns ps-lite health while inactive", async () => {
    const app = psLiteDebugRoutes({
      devToken: DEV_TOKEN,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    const res = await app.request("/health", { headers: authHeaders() });

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      runtime: "ps-lite",
      active: false,
      checkedAt: "2026-05-08T00:00:00.000Z",
    });
  });

  it("exercises local ps-lite data and bridge flows end to end", async () => {
    const app = psLiteDebugRoutes({
      devToken: DEV_TOKEN,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    const res = await app.request("/local-smoke", {
      method: "POST",
      headers: authHeaders(),
    });

    expect(res.status).toBe(200);
    await expect(res.json()).resolves.toMatchObject({
      status: "ok",
      runtime: "ps-lite",
      mode: "local",
      write: { status: 201 },
      read: {
        status: 200,
        body: {
          data: {
            source: "debug-ui",
            mode: "local",
          },
        },
      },
      bridge: { status: 201 },
    });
  });
});
