import type { FleetAssignment } from "./contracts.js";
export function fleetSandboxKey(a: FleetAssignment): string {
  return `${a.userPsId.toLowerCase()}:${a.identityEpoch}:fleet:${a.generation}`;
}
