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
    prepareRollback: vi.fn(async () => ({ owners: 1 })),
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

it("only private administration can prepare rollback identities", async () => {
  const { common } = fixture();
  for (const role of ["gateway", "admin"] as const) {
    const handler = createFleetControlHttp({
      ...common,
      role,
      credential: "a".repeat(32),
    });
    expect(
      (
        await handler(
          request("/fleet/v1/prepare-rollback", "a".repeat(32), {
            sourceNodeId: "source",
            migrationId: "rollback-1",
          }),
        )
      ).status,
    ).toBe(role === "admin" ? 200 : 404);
  }
  expect(common.prepareRollback).toHaveBeenCalledExactlyOnceWith({
    sourceNodeId: "source",
    migrationId: "rollback-1",
  });
});

it("reports the controller bundle window on private status only", async () => {
  const { common } = fixture();
  const token = "a".repeat(32);
  const config = {
    issuedAt: "2026-09-10T00:00:00.000Z",
    expiresAt: null,
    composeHash: "c".repeat(64),
    appId: "1".repeat(40),
    instanceId: "2".repeat(40),
  };
  const admin = createFleetControlHttp({
    ...common,
    config,
    role: "admin",
    credential: token,
  });
  const gateway = createFleetControlHttp({
    ...common,
    config,
    role: "gateway",
    credential: token,
  });

  const response = await admin(request("/fleet/v1/status", token));
  expect(response.status).toBe(200);
  // A deployment-lifetime bundle must survive serialization as literal null.
  expect(await response.text()).toContain('"expiresAt":null');
  expect((await gateway(request("/fleet/v1/status", token))).status).toBe(404);
});

it("annotates each directory member with its last admission outcome", async () => {
  const { common } = fixture();
  const token = "a".repeat(32);
  const node = {
    nodeId: "worker-2",
    nodeIncarnation: "",
    capacity: 4,
    draining: false,
    unavailable: true,
  };
  const lastAdmission = {
    code: "PEER_EVENTS_REJECTED",
    since: "2026-09-10T00:00:00.000Z",
    attempts: 3,
  };
  const admin = createFleetControlHttp({
    ...common,
    controller: {
      ...common.controller,
      nodeStatus: () => [node],
    } as unknown as FleetController,
    admissions: () => ({ [node.nodeId]: lastAdmission }),
    role: "admin",
    credential: token,
  });

  const body = (await (
    await admin(request("/fleet/v1/status", token))
  ).json()) as { nodes: unknown[] };
  expect(body.nodes).toEqual([{ ...node, lastAdmission }]);
});

it("reports a member that has never been admitted as a null outcome", async () => {
  const { common } = fixture();
  const token = "a".repeat(32);
  const admin = createFleetControlHttp({
    ...common,
    controller: {
      ...common.controller,
      nodeStatus: () => [{ nodeId: "worker-3" }],
    } as unknown as FleetController,
    role: "admin",
    credential: token,
  });

  expect(
    await (await admin(request("/fleet/v1/status", token))).text(),
  ).toContain('"lastAdmission":null');
});
