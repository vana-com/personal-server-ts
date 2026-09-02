/** Agent-local HTTP request and response shapes. */

import type { Address, Hex } from "viem";
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

export interface SealResult {
  envelope: SealedEnvelope;
  secretHash: Hex;
}

export interface HealthResponse {
  appId: string;
  composeHash: string;
  instanceId: string;
  osVersion?: string;
}
