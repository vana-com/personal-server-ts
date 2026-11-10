/** Test adapter for the receive module's timeout and typed refusal boundary. */
export const REPLICA_RECEIVE_TIMEOUT_MS = 30_000;

export class ReplicaObjectRefused extends Error {
  constructor(readonly cause_: "oversize" | "compressed" | "profile") {
    super(`replica object refused: ${cause_}`);
    this.name = "ReplicaObjectRefused";
  }
}
