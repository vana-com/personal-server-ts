/**
 * E2EE v2 associated data (spec section 6): RFC 8785 JCS bytes binding every
 * ciphertext to its field path and request context. Byte-exact examples are
 * pinned by the spec test vectors in aad.test.ts.
 */

import { canonicalJsonBytes } from "./jcs.js";

export const E2EE_REQUEST_AAD_PURPOSE = "aci.e2ee.request.v2";
export const E2EE_RESPONSE_AAD_PURPOSE = "aci.e2ee.response.v2";

export interface E2eeRequestContext {
  /** The selected service key's `algo`. */
  algo: string;
  /** The request's top-level `model`, byte-exact. */
  model: string;
  /** `X-E2EE-Nonce`, 64 hex characters. */
  nonce: string;
  /** `X-E2EE-Timestamp`, Unix seconds. */
  ts: number;
}

export function requestFieldAad(
  context: E2eeRequestContext,
  field: string,
): Uint8Array {
  return canonicalJsonBytes({
    purpose: E2EE_REQUEST_AAD_PURPOSE,
    algo: context.algo,
    model: context.model,
    field,
    nonce: context.nonce,
    ts: context.ts,
  });
}

export function responseFieldAad(
  context: E2eeRequestContext,
  field: string,
  /** The clear response `id`, or "" when the response has none. */
  id: string,
): Uint8Array {
  return canonicalJsonBytes({
    purpose: E2EE_RESPONSE_AAD_PURPOSE,
    algo: context.algo,
    model: context.model,
    id,
    field,
    nonce: context.nonce,
    ts: context.ts,
  });
}
