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
 * PLACEHOLDER (data-gateway #212). The gateway will answer a tombstone aimed
 * at a head that is already deleted with a distinct code. That answer means
 * the scope is already retired: the legacy stage reads it as `done` (it reads
 * the head again, which is deleted, and confirms the blobs). The code name is
 * not fixed yet, so this list is empty and the answer maps nowhere. When the
 * gateway names the code, add it here and nowhere else: the parser and the
 * stage both read this list.
 */
export const GATEWAY_ALREADY_DELETED_CODES =
  [] as const satisfies readonly string[];
export type GatewayAlreadyDeletedCode =
  (typeof GATEWAY_ALREADY_DELETED_CODES)[number];

export const isGatewayAlreadyDeletedCode = (
  code: unknown,
): code is GatewayAlreadyDeletedCode =>
  typeof code === "string" &&
  (GATEWAY_ALREADY_DELETED_CODES as readonly string[]).includes(code);

/** Every code the parser turns into a `GatewayRefusalError`. */
export type GatewayAnswerCode = GatewayRefusalCode | GatewayAlreadyDeletedCode;
export const isGatewayAnswerCode = (code: unknown): code is GatewayAnswerCode =>
  isGatewayRefusalCode(code) || isGatewayAlreadyDeletedCode(code);
