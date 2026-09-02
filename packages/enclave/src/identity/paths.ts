/**
 * Key-agent path layout. Every per-user secret hangs off one userPsId:
 *
 *   userPsId = keccak256("vana.ps-enclave.v1" || chainId || ownerAddress)
 *
 *   users/{userPsId}/wallet/ethereum/secp256k1/v1   -> enclave wallet
 *   users/{userPsId}/secrets/master-signature/v1    -> sealing key
 *
 * dstack scopes derivation to the CVM app_id, then the path, so the same
 * app_id on any node recovers the same keys. Wallet and sealing paths differ,
 * so compromise of one derived key says nothing about the other.
 */

import { encodePacked, getAddress, keccak256 } from "viem";

export const USER_PS_ID_DOMAIN = "vana.ps-enclave.v1";

const USERS_PREFIX = "users";
export const WALLET_PATH_SUFFIX = "wallet/ethereum/secp256k1/v1";
export const SEALING_PATH_SUFFIX = "secrets/master-signature/v1";

// `purpose` labels the key in dstack's signature chain; distinct per use.
export const WALLET_PURPOSE = "vana.ps-enclave.wallet.v1";
export const SEALING_PURPOSE = "vana.ps-enclave.sealing.v1";

/** 0x-prefixed keccak256 digest, 32 bytes. */
export type UserPsId = `0x${string}`;

/**
 * Bytes hashed: utf8(domain) || uint256BE(chainId) || address(20 bytes),
 * i.e. Solidity `abi.encodePacked(string, uint256, address)`.
 */
export function userPsId(
  chainId: number,
  ownerAddress: `0x${string}`,
): UserPsId {
  const packed = encodePacked(
    ["string", "uint256", "address"],
    [USER_PS_ID_DOMAIN, BigInt(chainId), getAddress(ownerAddress)],
  );

  return keccak256(packed);
}

export function walletPath(id: UserPsId): string {
  return `${USERS_PREFIX}/${id}/${WALLET_PATH_SUFFIX}`;
}

export function sealingPath(id: UserPsId): string {
  return `${USERS_PREFIX}/${id}/${SEALING_PATH_SUFFIX}`;
}
