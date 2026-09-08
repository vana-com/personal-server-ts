const WEB3_SIGNED_PREFIX = "Web3Signed ";

/**
 * Stable replay id for a Web3Signed proof.
 *
 * Keyed on the SIGNED PAYLOAD (the base64url claims segment) plus the
 * recovered signer — never on the raw header. The signature bytes are
 * malleable: the same secp256k1 signature has many encodings that recover
 * to the same signer (`v` as 27/28 or 0/1, hex case, and the ECDSA (r, n-s)
 * twin), so a guard keyed on the header treats every re-encoding of a
 * captured proof as a fresh proof. The payload cannot be altered without
 * invalidating the signature, so it is the proof's identity.
 *
 * Isomorphic (WebCrypto) so the browser runtime can share it.
 */
export async function web3SignedProofId(
  headerValue: string,
  signer: string,
): Promise<string> {
  const value = headerValue.startsWith(WEB3_SIGNED_PREFIX)
    ? headerValue.slice(WEB3_SIGNED_PREFIX.length)
    : headerValue;
  const dot = value.lastIndexOf(".");
  const payloadSegment = dot === -1 ? value : value.slice(0, dot);
  const bytes = new TextEncoder().encode(
    `${signer.toLowerCase()}\n${payloadSegment}`,
  );
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}
