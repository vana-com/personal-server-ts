import type { McpConnectionRecord } from "@opendatalabs/personal-server-ts-core/mcp";
import type {
  McpOwnerBinding,
  McpWakeupIdentity,
} from "@opendatalabs/personal-server-ts-server/mcp/tee";

/** JSON wire contract shared by controller, workers, and Gateway. */
export interface FleetOwner {
  chainId: number;
  userPsId: string;
  identityEpoch: number;
}
export interface FleetAssignment extends FleetOwner {
  nodeId: string;
  nodeIncarnation: string;
  generation: number;
  controllerTerm: 1;
  state: "starting" | "ready" | "draining";
  leaseExpiresAt: string;
}
export interface FleetReadiness {
  assignment: FleetAssignment;
  scope: string;
  dataVersion: number | null;
  state: "pending" | "ready" | "error";
  observedAt: string;
}
export interface FleetScope {
  scope: string;
  minimumVersion?: number;
}
export interface FleetPrepareRequest {
  assignment: FleetAssignment;
  scopes: FleetScope[];
}
export interface FleetExecuteRequest extends FleetPrepareRequest {
  requestId: string;
  deadline: string;
  connection: McpConnectionRecord;
  binding: McpOwnerBinding;
  message: unknown;
}
export interface FleetExecuteResponse {
  assignment: FleetAssignment;
  status: number;
  contentType: string;
  body: string;
}
export interface FleetActivity {
  assignment: FleetAssignment;
  present: boolean;
  busy: boolean;
}
export interface FleetWorkerPort {
  activity(assignment: FleetAssignment): Promise<FleetActivity>;
  prepare(request: FleetPrepareRequest): Promise<FleetReadiness[]>;
  renew(assignment: FleetAssignment): Promise<void>;
  readiness(request: FleetPrepareRequest): Promise<FleetReadiness[]>;
  execute(request: FleetExecuteRequest): Promise<FleetExecuteResponse>;
  release(assignment: FleetAssignment): Promise<void>;
}
export interface FleetEnvelopeResponse {
  identity: McpWakeupIdentity;
  assignment: FleetAssignment;
}
export interface FleetPeerIdentity {
  role: "controller" | "worker";
  nodeId: string;
  nodeIncarnation: string;
  appId: string;
  instanceId: string;
  composeHash: string;
}
export const FLEET_RPC_VERSION = 1;
export const FLEET_LEASE_MS = 30_000;
export const FLEET_RENEW_MS = 10_000;
export const FLEET_READINESS_MAX_AGE_MS = 15_000;
export const UNAVAILABLE_CODE = "UNAVAILABLE";
/** Closed allow-list of reviewed peer-verifier and identity refusals. Nothing a
 * remote worker can influence ever reaches a log line or the status surface. */
const ADMISSION_CODES = new Map([
  ["Peer runtime events rejected", "PEER_EVENTS_REJECTED"],
  ["Peer measurements rejected", "PEER_MEASUREMENTS_REJECTED"],
  ["Peer TCB rejected", "PEER_TCB_REJECTED"],
  ["Peer not admitted", "PEER_NOT_ADMITTED"],
  ["Peer key/challenge binding rejected", "PEER_BINDING_REJECTED"],
  ["Debug TDX forbidden", "PEER_DEBUG_TDX"],
  ["Worker identity mismatch", "IDENTITY_MISMATCH"],
]);
export function admissionCode(error: unknown): string {
  const message = error instanceof Error ? error.message : "";
  return ADMISSION_CODES.get(message) ?? UNAVAILABLE_CODE;
}
/** An allow-listed refusal is a verdict on the member itself, so it is
 * terminal; anything else is a stall or a timeout the caller may retry. Shared
 * with the renew path so one list decides both, e.g. a peer whose measurements
 * were rejected demotes at once, an 8 s RPC deadline gets a grace window. */
export function terminalAdmission(error: unknown): boolean {
  return admissionCode(error) !== UNAVAILABLE_CODE;
}

export function fleetOwnerKey(owner: FleetOwner): string {
  return `${owner.chainId}:${owner.userPsId.toLowerCase()}:${owner.identityEpoch}`;
}
export function sameAssignment(
  a: FleetAssignment,
  b: FleetAssignment,
): boolean {
  return (
    fleetOwnerKey(a) === fleetOwnerKey(b) &&
    a.nodeId === b.nodeId &&
    a.nodeIncarnation === b.nodeIncarnation &&
    a.generation === b.generation &&
    a.controllerTerm === b.controllerTerm
  );
}
