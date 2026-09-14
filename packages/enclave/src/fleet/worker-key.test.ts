import { describe, expect, it } from "vitest";
import type { FleetAssignment } from "./contracts.js";
import { currentFleetSandbox, fleetSandboxKey } from "./worker-key.js";

const ASSIGNMENT: FleetAssignment = {
  chainId: 14_800,
  userPsId: `0x${"ab".repeat(32)}`,
  identityEpoch: 1,
  nodeId: "node-1",
  nodeIncarnation: "incarnation-1",
  generation: 2,
  controllerTerm: 1,
  state: "ready",
  leaseExpiresAt: "2026-09-10T00:00:00.000Z",
};

const NEXT_GENERATION: FleetAssignment = { ...ASSIGNMENT, generation: 3 };

describe("current fleet sandbox", () => {
  it("serves a sandbox keyed by the current generation", () => {
    expect(currentFleetSandbox(fleetSandboxKey(ASSIGNMENT), [ASSIGNMENT])).toBe(
      true,
    );
  });

  it("rejects a sandbox left behind by a previous generation", () => {
    expect(
      currentFleetSandbox(fleetSandboxKey(ASSIGNMENT), [NEXT_GENERATION]),
    ).toBe(false);
  });

  it("rejects a fleet sandbox with no assignment on this worker", () => {
    expect(currentFleetSandbox(fleetSandboxKey(ASSIGNMENT), [])).toBe(false);
  });

  it("serves a key that carries no placement generation", () => {
    expect(currentFleetSandbox(`${ASSIGNMENT.userPsId}:1`, [])).toBe(true);
  });
});
