import type { FleetAssignment } from "../fleet/contracts.js";
/** Agent-local HTTP request and response shapes. */

import type { Address, Hex } from "viem";
import type { UserPsId } from "../identity/paths.js";
import type { ClaimResponse } from "../jobs/types.js";
import type { SealedEnvelope } from "../sealing/envelope.js";

export interface IdentityRequestBody {
  ownerAddress: Address;
  chainId: number;
  epoch: number;
}

export interface SealRequestBody {
  ownerAddress: Address;
  chainId: number;
  epoch: number;
  enclaveAddress: Address;
  ciphertext: Hex;
  minEpoch?: number;
}

export interface ResultSigningRequestBody {
  jobId: string;
  chainId: number;
  owner?: Address;
  byteLength: number;
  /** Canonical Web3Signed body hash: `sha256:<64 lowercase hex>`. */
  bodyHash: string;
}

export type PrewarmRequestBody = ClaimResponse["identity"] & {
  scope: string;
};

export interface ActiveSandboxJob {
  assignment?: FleetAssignment;
  jobId: string;
  chainId: number;
  owner: Address;
  userPsId: UserPsId;
  epoch: number;
  serverAddress: Address;
}

export type SandboxJobLookup =
  | { kind: "unauthorized" }
  | { kind: "inactive" }
  | { kind: "active"; job: ActiveSandboxJob };

export interface SealResult {
  envelope: SealedEnvelope;
  secretHash: Hex;
}

export interface HealthResponse {
  /** The five dstack fields are absent together, and only while `dstack` is
   * set: health answers within its budget whether or not the guest agent did. */
  appId?: string;
  composeHash?: string;
  instanceId?: string;
  nodeId: string | null;
  osImageHash?: string;
  osVersion?: string;
  /** Set to "unreachable" when the dstack guest agent has not answered once. */
  dstack?: string;
  activeSandboxes: number;
  draining: boolean;
  /** Signed-bundle window. Null issuance means this agent runs unsigned;
   * a null expiry on a signed bundle is the deployment-lifetime policy. */
  configIssuedAt: string | null;
  configExpiresAt: string | null;
}
