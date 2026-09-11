/**
 * Enclave-signed access records.
 *
 * The sandbox PS reports every MCP tool call it served or refused; the agent
 * is what makes those reports credible. It resolves the sandbox's access
 * token to the identity the sandbox runs as, stamps the node, and signs each
 * record with that user's enclave key — the same account that signs job
 * result uploads — before relaying the batch to the Gateway.
 *
 * There is no `ownerAddress` in the record on purpose: the Gateway resolves
 * the owner from identity_records by `userPsId`/`epoch`, so the sandbox can
 * never assert an owner the enclave did not derive.
 *
 * The same rule now covers every field the agent can vouch for itself. The
 * enclave key signs what it stamps — identity, node, chain, placement
 * generation and its own clock — and a body that disagrees is refused rather
 * than signed, so a compromised sandbox cannot mint enclave-attested reads on
 * a foreign chain or backdate one out of the owner's view (security #10).
 */

import type { Address, Hex } from "viem";
import type { UserPsId } from "../identity/paths.js";

export const ACCESS_RECORD_ACTION = "read";
/** One request carries at most this many records; the reporter batches to it. */
export const MAX_ACCESS_RECORDS = 50;
/**
 * How far `occurredAt` may sit from the agent clock. A record describes a read
 * the sandbox just served, and the reporter holds a partial batch for at most
 * 5 s, so this is generous — it exists to stop a backdated or post-dated
 * timestamp hiding a read outside the window an owner is looking at.
 */
export const MAX_OCCURRED_AT_SKEW_MS = 5 * 60_000;

export type AccessRecordOutcome = "served" | "denied";
export type AccessRecordSource = "mcp" | "api";

/** What the sandbox PS sends. Everything here is caller-asserted. */
export interface AccessRecordInput {
  action: typeof ACCESS_RECORD_ACTION;
  chainId: number;
  denyReason?: string;
  grantId: string;
  granteeAddress: Address;
  logId: string;
  occurredAt: string;
  outcome: AccessRecordOutcome;
  scope: string;
  source: AccessRecordSource;
  tool?: string;
}

/** The input plus everything only the agent can vouch for. */
export interface AccessRecord extends AccessRecordInput {
  epoch: number;
  /** Placement the sandbox serves under; absent on a non-fleet node. */
  generation?: number;
  nodeId: string;
  /** Agent clock when the record was signed, against the sandbox's claim. */
  recordedAt: string;
  userPsId: UserPsId;
}

/**
 * The wire envelope the Gateway parses: the signed bytes are the canonical
 * JSON of `payload` alone, so nesting keeps the signature over exactly the
 * fields that get stored.
 *
 *   { payload: { action: "read", ... }, signature: "0x.." }
 */
export interface SignedAccessRecord {
  payload: AccessRecord;
  signature: Hex;
}

export interface AccessRecordIdentity {
  userPsId: UserPsId;
  epoch: number;
}

/** What the agent knows independently of anything the sandbox sent. */
export interface AccessRecordContext {
  identity: AccessRecordIdentity;
  nodeId: string;
  /** The node's configured chain, never the body's. */
  chainId: number;
  /** Placement the token's sandbox is currently assigned to, when in a fleet. */
  generation?: number;
}

/** Why a record was refused instead of signed. */
export type AccessRecordRefusal = "chain_mismatch" | "occurred_at_out_of_range";

/**
 * Check the body against what the agent knows, before anything is signed.
 *
 * `chainId` must be the node's own: the result-signing path already compares
 * it, and an enclave signature over a foreign chain id is an audit entry no
 * verifier can place. `occurredAt` must sit inside the skew window, so a read
 * cannot be filed outside the range the owner's feed is showing.
 */
export function refuseAccessRecord(
  input: AccessRecordInput,
  context: AccessRecordContext,
  now: number,
): AccessRecordRefusal | null {
  if (input.chainId !== context.chainId) {
    return "chain_mismatch";
  }

  const occurredAt = Date.parse(input.occurredAt);
  if (Math.abs(occurredAt - now) > MAX_OCCURRED_AT_SKEW_MS) {
    return "occurred_at_out_of_range";
  }

  return null;
}

/**
 * Stamp the agent-known fields over whatever the body claimed. `refuseAccessRecord`
 * has already rejected a body that disagrees, so this is belt and braces —
 * the signed bytes come from the agent for every field it can source itself.
 */
export function buildAccessRecord(
  input: AccessRecordInput,
  context: AccessRecordContext,
  recordedAt: string,
): AccessRecord {
  return {
    ...input,
    chainId: context.chainId,
    epoch: context.identity.epoch,
    ...(context.generation === undefined
      ? {}
      : { generation: context.generation }),
    nodeId: context.nodeId,
    recordedAt,
    userPsId: context.identity.userPsId,
  };
}

/**
 * The exact bytes signed, EIP-191: keys sorted, no whitespace, absent fields
 * omitted, `signature` never included. A verifier rebuilds this string from
 * the stored record and recovers the enclave address from the signature.
 *
 *   {"action":"read","chainId":14800,...,"userPsId":"0x.."}
 */
export function canonicalJson(record: AccessRecord): string {
  const fields = Object.entries(record as unknown as Record<string, unknown>)
    .filter(([key, value]) => key !== "signature" && value !== undefined)
    .sort(([left], [right]) => (left < right ? -1 : 1))
    .map(([key, value]) => `${JSON.stringify(key)}:${JSON.stringify(value)}`);

  return `{${fields.join(",")}}`;
}
