import { describe, expect, it, vi } from "vitest";
import { enclaveFleetRoutes } from "./enclave-fleet.js";

describe("enclave fleet scoped readiness", () => {
  it("requires the local sandbox token before hydrating or observing owner data", async () => {
    const hydrate = vi.fn();
    const observe = vi.fn();
    const app = enclaveFleetRoutes({
      accessToken: "local-secret",
      hydrate,
      observe,
    });
    const response = await app.request("/readiness", {
      method: "POST",
      body: JSON.stringify({ scopes: [{ scope: "spotify.profile" }] }),
    });
    expect(response.status).toBe(401);
    expect(hydrate).not.toHaveBeenCalled();
    expect(observe).not.toHaveBeenCalled();
  });
});

it("reports requested scope/version readiness only after its scoped hydration settles", async () => {
  let hydrated = false;
  const app = enclaveFleetRoutes({
    accessToken: "local-secret",
    hydrate: async () => {
      hydrated = true;
    },
    observe: async () => ({ dataVersion: hydrated ? 2 : 1, ready: hydrated }),
  });
  const response = await app.request("/readiness", {
    method: "POST",
    headers: { authorization: "Bearer local-secret" },
    body: JSON.stringify({
      hydrate: true,
      scopes: [{ scope: "spotify.profile", minimumVersion: 3 }],
    }),
  });
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual([
    {
      scope: "spotify.profile",
      dataVersion: 2,
      state: "pending",
      observedAt: expect.any(String),
    },
  ]);
});
