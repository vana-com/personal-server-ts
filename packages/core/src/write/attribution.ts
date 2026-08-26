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
 * The proof binds the write to its context, not just its bytes: the signed
 * claims carry the request path (whose last segment is the scope), the
 * method, the audience (this server's origin) and the session's grantId,
 * which the PS requires to match the session at ingest. A stored `$writtenBy`
 * therefore cannot be lifted onto another scope's record or relabelled with a
 * different grant and still verify.
 *
 * What the builder signs is the STORED representation, not the wire body:
 * the compact JSON of the envelope `data` record the PS will write (minus
 * `$writtenBy`). A third party holding the envelope can therefore verify
 * authorship from the envelope ALONE (verifyStoredWriterAttribution): recover
 * the signer over the stored proof's base64url payload (EIP-191), check the
 * signed claims against the envelope's scope and stored grantId, and hash
 * JSON.stringify(data minus $writtenBy) against the signed bodyHash.
 *   - JSON writes: the body IS the stored record, so the builder signs the
 *     body bytes, which must be compact JSON (what JSON.stringify emits: no
 *     insignificant whitespace, keys in the order given). JSON.parse /
 *     JSON.stringify round-trips that byte-for-byte; a body that does not
 *     round-trip is rejected at write time (WRITE_BODY_NOT_CANONICAL) instead
 *     of being stored with an attribution nobody can check.
 *   - Binary writes: the stored record is the `$binary` envelope data (media
 *     type, filename, caller metadata, size, content hash, base64 content),
 *     so the builder signs its compact JSON (binaryWriteSignedBytes). That
 *     binds the caller-controlled representation headers (Content-Type,
 *     X-Filename / Content-Disposition, X-Vana-Metadata) to the signature and
 *     makes a JSON-vs-binary switch of the same bytes fail verification.
 */

import {
  computeBodyHash,
  parseWeb3SignedHeader,
  verifyWeb3Signed,
  type Web3SignedPayload,
} from "@opendatalabs/vana-sdk/browser";
import { recoverMessageAddress } from "viem";
import { ProtocolError } from "../errors/catalog.js";
import { hashConnectionToken as sha256HexOf } from "../mcp/connection-api.js";
import type { WriteProofReplayStore } from "./session.js";
import {
  binaryFilename,
  binaryMimeType,
  buildBinaryEnvelopeData,
  isJsonContentType,
  normalizeBinaryMimeType,
  parseMetadataHeader,
  sha256Hex,
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
  /**
   * Replay guard for the per-write proof. When supplied, a proof is consumed
   * on successful verification (keyed by a digest of the exact header,
   * remembered until the proof's own expiry) and a second write carrying the
   * same proof is rejected: holding the session bearer plus one captured
   * signed request must not allow re-storing it until the proof expires.
   */
  replayStore?: WriteProofReplayStore;
}

/** verifyWriterAttribution's result: the record to store plus a rollback. */
export interface VerifiedWriterAttribution extends WriterAttribution {
  /**
   * Present when a replay store consumed the proof. Callers whose write then
   * FAILS before the record is committed should call it so the builder can
   * retry with the same still-valid proof (a retry after success is a replay).
   */
  releaseProof?: () => Promise<void>;
}

function resolveOrigin(origin: string | (() => string)): string {
  return typeof origin === "function" ? origin() : origin;
}

export interface BinaryWriteSignedBytesInput {
  /** The raw body bytes the write will send. */
  bytes: Uint8Array;
  /** The Content-Type header the write will send (parameters are ignored). */
  contentType: string;
  /** The X-Filename header value the write will send, if any. */
  filename?: string;
  /** The exact X-Vana-Metadata header value the write will send, if any. */
  metadataHeader?: string;
}

/**
 * The bytes a builder signs (as the Web3Signed body) for a BINARY session
 * write: the compact JSON of the `$binary` record the PS stores for these
 * headers and bytes. Mirrors ingest exactly (same media-type normalization,
 * metadata parsing and envelope builder), so the signature covers the stored
 * representation and verifyStoredWriterAttribution can re-derive it.
 */
export async function binaryWriteSignedBytes(
  input: BinaryWriteSignedBytesInput,
): Promise<Uint8Array> {
  const data = buildBinaryEnvelopeData({
    bytes: input.bytes,
    mimeType: normalizeBinaryMimeType(input.contentType),
    filename: input.filename,
    contentHash: await sha256Hex(input.bytes),
    metadata: parseMetadataHeader(input.metadataHeader ?? null),
  });
  return new TextEncoder().encode(JSON.stringify(data));
}

/**
 * The bytes the proof must commit to for this request: the body itself for
 * a JSON write, the stored `$binary` representation for anything else.
 */
async function signedBytesFor(
  request: Request,
  bodyBytes: Uint8Array,
): Promise<Uint8Array> {
  if (isJsonContentType(request)) return bodyBytes;
  return binaryWriteSignedBytes({
    bytes: bodyBytes,
    contentType: binaryMimeType(request),
    filename: binaryFilename(request),
    metadataHeader: request.headers.get("x-vana-metadata") ?? undefined,
  });
}

/**
 * Verify the `X-Vana-Write-Signature` proof on a session write and produce
 * the attribution record to store with the data. Throws ProtocolError(401)
 * when the proof is missing, malformed, expired, fails EIP-191 recovery /
 * bodyHash binding (the hash covers the stored representation, see
 * signedBytesFor), recovers to a different key than the session builder, or
 * does not carry the session's grantId as a signed claim.
 */
export async function verifyWriterAttribution(
  input: VerifyWriterAttributionInput,
): Promise<VerifiedWriterAttribution> {
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
      bodyBytes: await signedBytesFor(input.request, bodyBytes),
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

  // The grant is a signed claim, so the stored attribution's grantId is
  // covered by the builder's signature rather than being a bare label.
  if (verified.payload.grantId !== input.grantId) {
    throw new ProtocolError(
      401,
      "WRITE_ATTRIBUTION_GRANT_MISMATCH",
      "Payload proof must carry the write session's grantId as a signed claim",
      { expected: input.grantId, actual: verified.payload.grantId ?? null },
    );
  }

  if (isJsonContentType(input.request)) {
    assertCanonicalJsonBody(bodyBytes);
  }

  // Replay guard, last: only a proof that passed every check is consumed,
  // so a rejected request never burns a proof.
  let releaseProof: (() => Promise<void>) | undefined;
  if (input.replayStore) {
    const store = input.replayStore;
    const proofId = await sha256HexOf(headerValue);
    const replayed = await store.consume(proofId, verified.payload.exp * 1000);
    if (replayed) {
      throw new ProtocolError(
        401,
        "WRITE_ATTRIBUTION_REPLAY",
        "Payload proof already used; sign a fresh proof for each write",
      );
    }
    releaseProof = async () => {
      await store.release?.(proofId);
    };
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
    ...(releaseProof ? { releaseProof } : {}),
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
      | "SIGNER_MISMATCH"
      | "SCOPE_MISMATCH"
      | "GRANT_MISMATCH"
      | "AUDIENCE_MISMATCH",
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

export interface VerifyStoredWriterAttributionOptions {
  /**
   * When known, the origin of the Personal Server the record was written to;
   * the proof's signed audience must match it. Omit for records whose server
   * is not known to the verifier.
   */
  expectedOrigin?: string;
}

/** Last path segment of the signed request uri, i.e. the scope written to. */
function signedScopeOf(uri: string): string | null {
  const path = uri.split("?")[0] ?? "";
  const segment = path.slice(path.lastIndexOf("/") + 1);
  if (!segment) return null;
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
}

/**
 * Verify builder attribution from a stored envelope alone (no request, no
 * server state, no expiry check: the proof is evidence of who wrote the
 * record at the time, not a live credential). Checks, in order: the envelope
 * carries an attribution; the stored representation (compact JSON of the
 * data minus `$writtenBy`, for JSON and `$binary` records alike) re-hashes
 * to the signed bodyHash; the proof parses and recovers to the attributed
 * builder; and the signed claims bind the proof to THIS record: a POST whose
 * path names the envelope's scope, the stored grantId, and (when given) the
 * server origin. Throws WriterAttributionVerificationError with the reason.
 */
export async function verifyStoredWriterAttribution(
  envelope: { scope: string; data: Record<string, unknown> },
  options: VerifyStoredWriterAttributionOptions = {},
): Promise<StoredWriterAttributionVerification> {
  const data = envelope.data;
  const attribution = data[WRITER_ATTRIBUTION_KEY];
  if (!isWriterAttribution(attribution)) {
    throw new WriterAttributionVerificationError(
      "ATTRIBUTION_MISSING",
      `Record carries no ${WRITER_ATTRIBUTION_KEY} attribution`,
    );
  }
  const { [WRITER_ATTRIBUTION_KEY]: _attribution, ...payloadData } = data;

  const bodyHash = computeBodyHash(
    new TextEncoder().encode(JSON.stringify(payloadData)),
  );
  if (bodyHash !== attribution.bodyHash) {
    throw new WriterAttributionVerificationError(
      "BODY_HASH_MISMATCH",
      "Stored record does not hash to the attribution bodyHash",
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
  // Context binding: the signed claims must describe a write of THIS record.
  if (
    proof.payload.method !== "POST" ||
    signedScopeOf(proof.payload.uri) !== envelope.scope
  ) {
    throw new WriterAttributionVerificationError(
      "SCOPE_MISMATCH",
      `Stored proof is not a write to scope ${envelope.scope}`,
    );
  }
  if (proof.payload.grantId !== attribution.grantId) {
    throw new WriterAttributionVerificationError(
      "GRANT_MISMATCH",
      "Stored grantId is not the grant the builder signed",
    );
  }
  if (
    options.expectedOrigin !== undefined &&
    proof.payload.aud !== options.expectedOrigin
  ) {
    throw new WriterAttributionVerificationError(
      "AUDIENCE_MISMATCH",
      "Stored proof was not addressed to this server",
    );
  }
  return {
    builder: attribution.builder,
    grantId: attribution.grantId,
    bodyHash,
    payload: proof.payload,
  };
}
