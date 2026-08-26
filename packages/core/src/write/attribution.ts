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
 * A third party holding the record can verify authorship from the record
 * ALONE (verifyStoredWriterAttribution): recover the signer over the stored
 * proof's base64url payload (EIP-191) and re-derive the signed bytes from the
 * stored data. For that to hold, the stored form must re-serialize to exactly
 * the bytes the builder signed, so:
 *   - binary records keep the raw bytes verbatim (base64 in `$binary`);
 *   - JSON records must be sent in compact form, i.e. what JSON.stringify
 *     emits (no insignificant whitespace, keys in the order given). Ingest
 *     stores the parsed object, and JSON.parse/JSON.stringify round-trips
 *     compact JSON byte-for-byte; a body that does not round-trip is rejected
 *     at write time (WRITE_BODY_NOT_CANONICAL) instead of storing an
 *     attribution nobody can check.
 */

import {
  computeBodyHash,
  parseWeb3SignedHeader,
  verifyWeb3Signed,
  type Web3SignedPayload,
} from "@opendatalabs/vana-sdk/browser";
import { recoverMessageAddress } from "viem";
import { ProtocolError } from "../errors/catalog.js";
import {
  decodeBinaryEnvelope,
  isBinaryEnvelope,
  isJsonContentType,
} from "../contracts/binary.js";

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

  if (isJsonContentType(input.request)) {
    assertCanonicalJsonBody(bodyBytes);
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

/**
 * A JSON session write must be the compact serialization of its own parsed
 * value, so the record stored after JSON.parse re-serializes to the signed
 * bytes. Bodies that do not parse are left to the ingest path, which reports
 * the parse error itself.
 */
function assertCanonicalJsonBody(bodyBytes: Uint8Array): void {
  const text = new TextDecoder().decode(bodyBytes);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return;
  }
  if (JSON.stringify(parsed) !== text) {
    throw new ProtocolError(
      400,
      "WRITE_BODY_NOT_CANONICAL",
      "Session writes must send compact JSON (the JSON.stringify form) so the stored record re-serializes to the signed bytes and the attribution bodyHash stays verifiable",
    );
  }
}

/** Proof scheme prefix the compact stored signature was stripped of. */
const WEB3_SIGNED_SCHEME = "Web3Signed";

export class WriterAttributionVerificationError extends Error {
  constructor(
    public readonly reason:
      | "ATTRIBUTION_MISSING"
      | "BODY_HASH_MISMATCH"
      | "PROOF_INVALID"
      | "SIGNER_MISMATCH",
    message: string,
  ) {
    super(message);
    this.name = "WriterAttributionVerificationError";
  }
}

export interface StoredWriterAttributionVerification {
  /** Signer recovered from the stored proof (equals the stored builder). */
  builder: `0x${string}`;
  grantId: string;
  /** Hash re-derived from the stored data; equals the proof's bodyHash. */
  bodyHash: string;
  /** The signed claims (aud / method / uri / bodyHash / iat / exp). */
  payload: Web3SignedPayload;
}

function isWriterAttribution(value: unknown): value is WriterAttribution {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.builder === "string" &&
    v.builder.startsWith("0x") &&
    typeof v.grantId === "string" &&
    typeof v.signature === "string" &&
    typeof v.bodyHash === "string" &&
    typeof v.writtenAt === "string"
  );
}

/**
 * Verify builder attribution from a stored record alone (no request, no
 * server state, no expiry check: the proof is evidence of who wrote the bytes
 * at the time, not a live credential). The bytes the builder signed are
 * re-derived from the record: the decoded content of a `$binary` record, or
 * the compact JSON serialization of the data with `$writtenBy` removed.
 * Throws WriterAttributionVerificationError when the record carries no
 * attribution, the data no longer hashes to the signed bodyHash, the proof is
 * malformed, or the proof's signer is not the stored builder.
 */
export async function verifyStoredWriterAttribution(
  data: Record<string, unknown>,
): Promise<StoredWriterAttributionVerification> {
  const attribution = data[WRITER_ATTRIBUTION_KEY];
  if (!isWriterAttribution(attribution)) {
    throw new WriterAttributionVerificationError(
      "ATTRIBUTION_MISSING",
      `Record carries no ${WRITER_ATTRIBUTION_KEY} attribution`,
    );
  }
  const { [WRITER_ATTRIBUTION_KEY]: _attribution, ...payloadData } = data;

  const signedBytes = isBinaryEnvelope({ data: payloadData })
    ? decodeBinaryEnvelope({ data: payloadData }).bytes
    : new TextEncoder().encode(JSON.stringify(payloadData));
  const bodyHash = computeBodyHash(signedBytes);
  if (bodyHash !== attribution.bodyHash) {
    throw new WriterAttributionVerificationError(
      "BODY_HASH_MISMATCH",
      "Stored data does not hash to the attribution bodyHash",
    );
  }

  let proof: ReturnType<typeof parseWeb3SignedHeader>;
  let signer: `0x${string}`;
  try {
    proof = parseWeb3SignedHeader(
      `${WEB3_SIGNED_SCHEME} ${attribution.signature}`,
    );
    signer = await recoverMessageAddress({
      message: proof.payloadBase64,
      signature: proof.signature,
    });
  } catch (err) {
    throw new WriterAttributionVerificationError(
      "PROOF_INVALID",
      err instanceof Error ? err.message : String(err),
    );
  }
  if (proof.payload.bodyHash !== bodyHash) {
    throw new WriterAttributionVerificationError(
      "BODY_HASH_MISMATCH",
      "Stored proof does not commit to the attribution bodyHash",
    );
  }
  if (signer.toLowerCase() !== attribution.builder.toLowerCase()) {
    throw new WriterAttributionVerificationError(
      "SIGNER_MISMATCH",
      "Stored proof is not signed by the attributed builder",
    );
  }
  return {
    builder: attribution.builder,
    grantId: attribution.grantId,
    bodyHash,
    payload: proof.payload,
  };
}
