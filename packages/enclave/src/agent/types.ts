/** Agent-local HTTP request and response shapes. */

import type { Address, Hex } from "viem";
import type { UserPsId } from "../identity/paths.js";
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

export interface ActiveSandboxJob {
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
  appId: string;
  composeHash: string;
  instanceId: string;
  nodeId: string | null;
  osImageHash?: string;
  osVersion?: string;
  activeSandboxes: number;
  draining: boolean;
}
