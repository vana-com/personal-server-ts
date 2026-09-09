import { expect, it, vi } from "vitest";
import {
  createFleetControlHttp,
  type FleetControlHttpOptions,
} from "./controller-http.js";
import type { FleetController } from "./placement.js";
function fixture() {
  const ensure = vi.fn(async () => ({ generation: 1 }));
  const common = {
    controller: {
      ensure,
      readiness: vi.fn(async () => []),
      snapshot: () => [],
      nodeStatus: () => [],
      paused: () => false,
    } as unknown as FleetController,
    identity: vi.fn(),
    seal: vi.fn(),
    admit: vi.fn(),
    migrate: vi.fn(),
    activate: vi.fn(),
    quiesce: vi.fn(),
  };
  return { ensure, common };
}
function request(path: string, token: string, body: unknown = {}) {
  return new Request(`https://controller.invalid${path}`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
}
it("separates Gateway credentials and routes from private administration", async () => {
  const { common } = fixture();
  const gatewayToken = "g".repeat(32),
    adminToken = "a".repeat(32);
  const gateway = createFleetControlHttp({
    ...common,
    role: "gateway",
    credential: gatewayToken,
  });
  const admin = createFleetControlHttp({
    ...common,
    role: "admin",
    credential: adminToken,
  });
  expect((await admin(request("/fleet/v1/admit", gatewayToken))).status).toBe(
    401,
  );
  expect((await gateway(request("/fleet/v1/admit", gatewayToken))).status).toBe(
    404,
  );
  expect((await gateway(request("/fleet/v1/ensure", adminToken))).status).toBe(
    401,
  );
  expect(common.admit).not.toHaveBeenCalled();
});
it("does not enroll or allocate before migration and explicit activation", async () => {
  const { common, ensure } = fixture();
  const handler = createFleetControlHttp({
    ...common,
    role: "gateway",
    credential: "g".repeat(32),
    active: async () => false,
  } satisfies FleetControlHttpOptions);
  expect(
    (
      await handler(
        request("/fleet/v1/ensure", "g".repeat(32), {
          owner: { chainId: 14800, userPsId: "owner", identityEpoch: 1 },
          scopes: [],
        }),
      )
    ).status,
  ).toBe(503);
  expect(ensure).not.toHaveBeenCalled();
});
