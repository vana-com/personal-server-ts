/**
 * The gateway's answers to a tombstone that no retry changes. One list: the
 * response parser (`delete-data-port.ts`), the delete status's block reasons
 * (`localdb/delete-status.ts`), the legacy stage's "ask once" rule and the
 * rollback resubmitter all read it, so a code added here reaches every one.
 */
export const GATEWAY_REFUSAL_CODES = [
  /** The owner switched under a policy that admits no legacy delete. */
  "owner_stream_sync_required",
  /** The owner revoked this server's key. */
  "server_revoked",
  /** The owner never registered this server's key. */
  "server_unregistered",
] as const;
export type GatewayRefusalCode = (typeof GATEWAY_REFUSAL_CODES)[number];

export const isGatewayRefusalCode = (
  code: unknown,
): code is GatewayRefusalCode =>
  typeof code === "string" &&
  (GATEWAY_REFUSAL_CODES as readonly string[]).includes(code);

/**
 * The gateway answers a tombstone aimed at a head that is already deleted with
 * HTTP 409 and one of these codes. The scope is retired already: it is no
 * refusal, and no retry is blocked by it. The port reads it as the 410 it
 * already knows (`delete-data-port.ts`), and the legacy stage reads the head
 * again, which is deleted, and confirms the blobs. Add a code here and
 * nowhere else: the port and the stage both read this list.
 */
export const GATEWAY_ALREADY_DELETED_CODES = [
  "owner_stream_head_already_deleted",
] as const satisfies readonly string[];
export type GatewayAlreadyDeletedCode =
  (typeof GATEWAY_ALREADY_DELETED_CODES)[number];

export const isGatewayAlreadyDeletedCode = (
  code: unknown,
): code is GatewayAlreadyDeletedCode =>
  typeof code === "string" &&
  (GATEWAY_ALREADY_DELETED_CODES as readonly string[]).includes(code);

/**
 * The gateway answers a tombstone aimed at a head it never registered with
 * HTTP 409 and one of these codes. It is not terminal: this device's head
 * comes from the gateway's own deletion-aware feed (`legacyHeadFrom`), so the
 * two views disagreeing is a lagging read, not a state no retry changes. The
 * port reads it as the 404 it already knows (`not-registered`): the delete
 * re-reads the registry, and the stage reads the head again (absent is done,
 * live is waiting).
 */
export const GATEWAY_HEAD_ABSENT_CODES = [
  "owner_stream_head_absent",
] as const satisfies readonly string[];
export type GatewayHeadAbsentCode = (typeof GATEWAY_HEAD_ABSENT_CODES)[number];

export const isGatewayHeadAbsentCode = (
  code: unknown,
): code is GatewayHeadAbsentCode =>
  typeof code === "string" &&
  (GATEWAY_HEAD_ABSENT_CODES as readonly string[]).includes(code);

/** Every code the parser turns into a `GatewayRefusalError`. */
export type GatewayAnswerCode = GatewayRefusalCode | GatewayAlreadyDeletedCode;
export const isGatewayAnswerCode = (code: unknown): code is GatewayAnswerCode =>
  isGatewayRefusalCode(code) || isGatewayAlreadyDeletedCode(code);
