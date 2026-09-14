import type { FleetAssignment } from "./contracts.js";

const FLEET_KEY_TAG = ":fleet:";

export function fleetSandboxKey(a: FleetAssignment): string {
  return `${a.userPsId.toLowerCase()}:${a.identityEpoch}${FLEET_KEY_TAG}${a.generation}`;
}

/**
 * True when a registry key may still act for its owner. A fleet key embeds the
 * placement generation, so the sandbox a re-placed owner left behind (e.g.
 * `0x..:1:fleet:2` once generation 3 is live elsewhere) matches no assignment
 * and is refused. Job and local-MCP keys carry no generation and always pass.
 */
export function currentFleetSandbox(
  key: string,
  assignments: FleetAssignment[],
): boolean {
  if (!key.includes(FLEET_KEY_TAG)) {
    return true;
  }

  return assignments.some((a) => fleetSandboxKey(a) === key);
}
