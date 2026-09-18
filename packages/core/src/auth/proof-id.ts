import { parseWeb3SignedHeader } from "@opendatalabs/vana-sdk";
import { ProtocolError } from "../errors/catalog.js";

const MAX_PROOF_LIFETIME_SEC = 15 * 60;
const PROOF_CLOCK_SKEW_SEC = 60;

/** A verified proof is identified by its signed bytes, not malleable signature bytes. */
export async function web3SignedProofId(
  headerValue: string,
  signer: string,
): Promise<string> {
  const { payloadBase64 } = parseWeb3SignedHeader(headerValue);
  const bytes = new TextEncoder().encode(
    `${signer.toLowerCase()}\n${payloadBase64}`,
  );
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

/** Reject expired proofs before replay entries can be evicted at their expiry. */
export function boundedProofExpiry(
  payload: { iat?: number; exp?: number },
  errorCode: string,
): number {
  const now = Math.floor(Date.now() / 1000);
  const { iat, exp } = payload;
  if (
    typeof iat !== "number" ||
    typeof exp !== "number" ||
    !Number.isSafeInteger(iat) ||
    !Number.isSafeInteger(exp) ||
    exp <= iat ||
    exp <= now ||
    iat > now + PROOF_CLOCK_SKEW_SEC ||
    exp - iat > MAX_PROOF_LIFETIME_SEC ||
    now - iat > MAX_PROOF_LIFETIME_SEC
  ) {
    throw new ProtocolError(
      401,
      errorCode,
      `Proof must be unexpired and valid for at most ${MAX_PROOF_LIFETIME_SEC}s`,
    );
  }
  return exp * 1000;
}
