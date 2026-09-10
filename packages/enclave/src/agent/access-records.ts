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
 */

import type { Address, Hex } from "viem";
import type { UserPsId } from "../identity/paths.js";

export const ACCESS_RECORD_ACTION = "read";
/** One request carries at most this many records; the reporter batches to it. */
export const MAX_ACCESS_RECORDS = 50;

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

/** The input plus the identity only the agent can vouch for. */
export interface AccessRecord extends AccessRecordInput {
  epoch: number;
  nodeId: string;
  userPsId: UserPsId;
}

export interface SignedAccessRecord extends AccessRecord {
  signature: Hex;
}

export interface AccessRecordIdentity {
  userPsId: UserPsId;
  epoch: number;
}

export function buildAccessRecord(
  input: AccessRecordInput,
  identity: AccessRecordIdentity,
  nodeId: string,
): AccessRecord {
  return {
    ...input,
    epoch: identity.epoch,
    nodeId,
    userPsId: identity.userPsId,
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
