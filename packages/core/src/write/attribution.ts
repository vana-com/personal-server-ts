/**
 * Builder attribution for delegated writes.
 *
 * The write-session token authorizes a write; it does not PROVE who authored
 * the payload (a bearer token is not a signature). For cryptographic
 * attribution the builder also signs the payload: a Web3Signed proof over the
 * exact write request (aud / method / uri / bodyHash / iat / exp), carried in
 * the `X-Vana-Write-Signature` header and signed by the builder key proven at
 * handshake. The PS verifies the proof recovers to the session's builder and
 * that its bodyHash commits to the received bytes, then stores the proof and
 * the builder identity WITH the record — inside the envelope's `data` under
 * the reserved `$writtenBy` key (same in-`data` marker idiom as `$binary`),
 * so attribution travels through the unchanged encrypt / upload / register
 * path and back out on read. The on-chain shape is untouched.
 *
 * A third party holding the record can verify authorship: decode the stored
 * compact proof, recover the signer over its base64url payload (EIP-191), and
 * check the payload's bodyHash against the original request body bytes.
 */

import {
  parseWeb3SignedHeader,
  verifyWeb3Signed,
} from "@opendatalabs/vana-sdk/browser";
import { ProtocolError } from "../errors/catalog.js";

/** Header carrying the builder's signed-payload proof on a session write. */
export const WRITE_SIGNATURE_HEADER = "x-vana-write-signature";

/**
 * Reserved key inside the envelope's `data` record for builder attribution.
 * Mirrors the `$binary` marker convention (contracts/binary.ts).
 */
export const WRITER_ATTRIBUTION_KEY = "$writtenBy" as const;

export interface WriterAttribution {
  /** The builder address the proof recovered to. */
  builder: `0x${string}`;
  /** The write-grant the record was written under. */
  grantId: string;
  /**
   * The builder's compact Web3Signed proof (`{base64url(payload)}.{sig}`,
   * scheme prefix stripped). Verifiable offline: recover the EIP-191 signer
   * over the base64url payload string; the decoded payload's `bodyHash`
   * commits to the written bytes.
   */
  signature: string;
  /** `bodyHash` claim from the proof (sha-256 of the request body bytes). */
  bodyHash: string;
  /** ISO timestamp the PS accepted the write. */
  writtenAt: string;
}

export interface VerifyWriterAttributionInput {
  request: Request;
  /** The builder address bound to the write session at handshake. */
  builderAddress: `0x${string}`;
  /** The grant the session (and therefore this write) is bound to. */
  grantId: string;
  serverOrigin: string | (() => string);
  now?: () => Date;
}

function resolveOrigin(origin: string | (() => string)): string {
  return typeof origin === "function" ? origin() : origin;
}

/**
 * Verify the `X-Vana-Write-Signature` proof on a session write and produce
 * the attribution record to store with the data. Throws ProtocolError(401)
 * when the proof is missing, malformed, expired, fails EIP-191 recovery /
 * bodyHash binding, or recovers to a different key than the session builder.
 */
export async function verifyWriterAttribution(
  input: VerifyWriterAttributionInput,
): Promise<WriterAttribution> {
  const headerValue =
    input.request.headers.get(WRITE_SIGNATURE_HEADER) ?? undefined;
  if (!headerValue) {
    throw new ProtocolError(
      401,
      "WRITE_ATTRIBUTION_REQUIRED",
      `Session writes must carry a builder-signed payload proof in ${WRITE_SIGNATURE_HEADER}`,
    );
  }

  const url = new URL(input.request.url);
  const bodyBytes = new Uint8Array(await input.request.clone().arrayBuffer());

  let verified;
  try {
    verified = await verifyWeb3Signed({
      headerValue,
      expectedOrigin: resolveOrigin(input.serverOrigin),
      expectedMethod: input.request.method,
      expectedPath: url.pathname,
      bodyBytes,
    });
  } catch (err) {
    throw new ProtocolError(
      401,
      "WRITE_ATTRIBUTION_INVALID",
      err instanceof Error ? err.message : String(err),
    );
  }

  if (verified.signer.toLowerCase() !== input.builderAddress.toLowerCase()) {
    throw new ProtocolError(
      401,
      "WRITE_ATTRIBUTION_SIGNER_MISMATCH",
      "Payload proof is not signed by the session builder",
      { expected: input.builderAddress, actual: verified.signer },
    );
  }

  // Store the compact `{payload}.{signature}` form (scheme prefix stripped)
  // so verifiers don't need to know the header framing.
  const { payloadBase64, signature } = parseWeb3SignedHeader(headerValue);

  return {
    builder: input.builderAddress,
    grantId: input.grantId,
    signature: `${payloadBase64}.${signature}`,
    bodyHash: verified.payload.bodyHash,
    writtenAt: (input.now?.() ?? new Date()).toISOString(),
  };
}

/**
 * Stamp attribution into an envelope `data` record. The reserved key must not
 * appear in the caller's payload — a builder must not be able to forge (or
 * shadow) its own attribution.
 */
export function stampWriterAttribution(
  data: Record<string, unknown>,
  attribution: WriterAttribution,
): Record<string, unknown> {
  return { ...data, [WRITER_ATTRIBUTION_KEY]: attribution };
}

export function hasReservedWriterKey(data: Record<string, unknown>): boolean {
  return Object.prototype.hasOwnProperty.call(data, WRITER_ATTRIBUTION_KEY);
}
