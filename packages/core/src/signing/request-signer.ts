/**
 * RequestSigner — produces Web3Signed Authorization headers for HTTP requests.
 * Used by the Vana Storage adapter for authenticated blob operations.
 */

import { buildWeb3SignedHeader } from "@opendatalabs/vana-sdk/node";
import type { ServerAccount } from "../keys/server-account.js";
import type { RequestSigner } from "../storage/adapters/vana.js";

/**
 * Create a RequestSigner that produces Web3Signed Authorization headers
 * using the server account's EIP-191 signing capability.
 */
export function createRequestSigner(account: ServerAccount): RequestSigner {
  return {
    async signRequest(params: {
      aud: string;
      method: string;
      uri: string;
      body?: Uint8Array;
    }): Promise<string> {
      return buildWeb3SignedHeader({
        signMessage: (message: string) => account.signMessage(message),
        aud: params.aud,
        method: params.method,
        uri: params.uri,
        body: params.body,
      });
    },
  };
}
