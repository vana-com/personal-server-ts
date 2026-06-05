/**
 * Per-connection MCP grantee key generation + Web3Signed request signing.
 *
 * Each MCP connection gets a fresh secp256k1 keypair. The PS route uses this
 * keypair to sign every read it performs on behalf of the connection so:
 *
 *  1. The data read flows through `authorizeBuilderRead` exactly like any
 *     external builder request.
 *  2. The access log records the per-connection grantee address, not the
 *     owner.
 *  3. Disconnecting one MCP client cannot affect another or the owner.
 *
 * This module does NOT do encryption-at-rest. The caller chooses the storage
 * representation (`McpEncryptedPrivateKey`) — for Node the `plaintext` variant
 * is fine (same trust boundary as the on-disk server key); for Web PS Lite the
 * caller should wrap with the owner-derived master key.
 */

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { buildWeb3SignedHeader } from "@opendatalabs/vana-sdk/browser";
import type { ServerAccount } from "../keys/server-account.js";
import type { McpEncryptedPrivateKey } from "./types.js";

export interface McpGranteeKey {
  address: `0x${string}`;
  publicKey: `0x${string}`;
  encryptedPrivateKey: McpEncryptedPrivateKey;
}

export interface GeneratedMcpGrantee {
  key: McpGranteeKey;
  account: ServerAccount;
}

/**
 * Generate a new MCP grantee keypair and return both the persisted
 * (plaintext-wrapped) form and a ready-to-sign `ServerAccount`.
 */
export function generateMcpGrantee(): GeneratedMcpGrantee {
  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  const serverAccount: ServerAccount = {
    address: account.address,
    publicKey: account.publicKey,
    async signTypedData(params) {
      return account.signTypedData({
        domain: params.domain as Parameters<
          typeof account.signTypedData
        >[0]["domain"],
        types: params.types as Parameters<
          typeof account.signTypedData
        >[0]["types"],
        primaryType: params.primaryType,
        message: params.message,
      });
    },
    async signMessage(message) {
      return account.signMessage({ message });
    },
  };
  return {
    key: {
      address: account.address,
      publicKey: account.publicKey,
      encryptedPrivateKey: { kind: "plaintext", privateKey },
    },
    account: serverAccount,
  };
}

/**
 * Reconstruct a `ServerAccount` from a persisted MCP grantee record.
 * Only `plaintext` is supported here; Web PS Lite must decrypt to plaintext
 * before calling.
 */
export function loadMcpGranteeAccount(key: McpGranteeKey): ServerAccount {
  if (key.encryptedPrivateKey.kind !== "plaintext") {
    throw new Error(
      "loadMcpGranteeAccount: only plaintext keys are supported here; decrypt first",
    );
  }
  const account = privateKeyToAccount(key.encryptedPrivateKey.privateKey);
  return {
    address: account.address,
    publicKey: account.publicKey,
    async signTypedData(params) {
      return account.signTypedData({
        domain: params.domain as Parameters<
          typeof account.signTypedData
        >[0]["domain"],
        types: params.types as Parameters<
          typeof account.signTypedData
        >[0]["types"],
        primaryType: params.primaryType,
        message: params.message,
      });
    },
    async signMessage(message) {
      return account.signMessage({ message });
    },
  };
}

/**
 * Build a Web3Signed Authorization header that authenticates the bearer as the
 * MCP connection's grantee for a given grant id and request URL.
 */
export async function signMcpGranteeRequest(params: {
  account: ServerAccount;
  aud: string;
  method: string;
  uri: string;
  grantId: string;
  body?: Uint8Array;
}): Promise<string> {
  return buildWeb3SignedHeader({
    signMessage: (message: string) => params.account.signMessage(message),
    aud: params.aud,
    method: params.method,
    uri: params.uri,
    body: params.body,
    grantId: params.grantId,
  });
}
