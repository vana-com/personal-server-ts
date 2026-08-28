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
 * claims carry the request uri (path AND query, see canonicalSignedUri; the
 * path's last segment is the scope on the ingest route), the method, the
 * audience (this server's origin) and the session's grantId, which the PS
 * requires to match the session at ingest. A stored `$writtenBy` therefore
 * cannot be lifted onto another scope's record or relabelled with a
 * different grant and still verify. A proof may also carry an optional
 * `nonce` claim, which is what makes it unique: without one, two identical
 * requests signed in the same second are byte-identical and the replay guard
 * refuses the second.
 *
 * What the builder signs is the STORED representation, not the wire body:
 * the compact JSON of the envelope `data` record the PS will write (minus
 * `$writtenBy`). A third party holding the envelope can therefore verify
 * authorship from the envelope ALONE (verifyStoredWriterAttribution): recover
 * the signer over the stored proof's base64url payload (EIP-191), check the
 * signed claims against the envelope's scope and stored grantId, and hash
 * JSON.stringify(data minus the server-stamped keys `$writtenBy` and
 * `$lineage`) against the signed bodyHash.
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
import {
  LINEAGE_KEY,
  StoredLineageMalformedError,
  extractLineageField,
  readStoredLineage,
} from "../lineage/lineage.js";
import { isBinaryEnvelope } from "../contracts/binary.js";

/** Header carrying the builder's signed-payload proof on a session write. */
export const WRITE_SIGNATURE_HEADER = "x-vana-write-signature";

/**
 * Upper bound on the optional `nonce` claim (a uuid or a short random
 * string is the intended shape). Bounded so a proof cannot smuggle bulk
 * data into the replay store's keys.
 */
export const MAX_PROOF_NONCE_LENGTH = 128;

/** HTTP methods that never carry a body on this API. */
function isBodylessMethod(method: string): boolean {
  const upper = method.toUpperCase();
  return upper === "GET" || upper === "HEAD" || upper === "DELETE";
}

/**
 * Canonical query string: parameters sorted by name and then value. The
 * signed uri must commit to the query because a query parameter can decide
 * authorization (`GET /v1/derivatives/questions?derivedScope=X` authorizes
 * the caller against that scope), and a proof that does not cover it can be
 * replayed against a different scope. Sorting makes the rule insensitive to
 * the order a client happens to serialize its parameters in.
 */
function canonicalQuery(search: string): string {
  const entries = [...new URLSearchParams(search).entries()].sort((a, b) =>
    a[0] === b[0]
      ? a[1] < b[1]
        ? -1
        : a[1] > b[1]
          ? 1
          : 0
      : a[0] < b[0]
        ? -1
        : 1,
  );
  const canonical = new URLSearchParams();
  for (const [name, value] of entries) canonical.append(name, value);
  return canonical.toString();
}

/**
 * The uri a proof must commit to for a request: the path, plus the canonical
 * query when the request carries one. A request with no query string signs
 * the bare path exactly as before.
 */
export function canonicalSignedUri(pathname: string, search: string): string {
  const query = canonicalQuery(search);
  return query ? `${pathname}?${query}` : pathname;
}

/** The same canonical form applied to a signed `uri` claim. */
export function canonicalizeSignedUri(uri: string): string {
  const mark = uri.indexOf("?");
  if (mark === -1) return uri;
  return canonicalSignedUri(uri.slice(0, mark), uri.slice(mark + 1));
}

function base64UrlDecode(value: string): string {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    "=",
  );
  const binary = atob(padded);
  return new TextDecoder().decode(
    Uint8Array.from(binary, (char) => char.charCodeAt(0)),
  );
}

/**
 * The proof's optional `nonce` claim. Read from the raw signed payload, not
 * from the verified claims: the SDK's parser keeps only the claims it knows,
 * and the nonce is covered by the signature all the same (the signature is
 * over the base64url payload string).
 */
function signedNonce(payloadBase64: string): string | undefined {
  let raw: unknown;
  try {
    raw = JSON.parse(base64UrlDecode(payloadBase64));
  } catch {
    // A payload that does not decode is rejected by verifyWeb3Signed.
    return undefined;
  }
  if (typeof raw !== "object" || raw === null) return undefined;
  const nonce = (raw as Record<string, unknown>).nonce;
  if (nonce === undefined || nonce === null) return undefined;
  if (
    typeof nonce !== "string" ||
    nonce.length === 0 ||
    nonce.length > MAX_PROOF_NONCE_LENGTH
  ) {
    throw new ProtocolError(
      401,
      "WRITE_ATTRIBUTION_INVALID",
      `Payload proof nonce must be a string of 1 to ${MAX_PROOF_NONCE_LENGTH} characters`,
    );
  }
  return nonce;
}

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
  // A bodyless method has no stored representation to sign: the proof
  // commits to the empty body, whatever Content-Type the caller sent.
  if (isBodylessMethod(request.method)) return bodyBytes;
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

  // The proof must commit to the whole request uri, query included. Any
  // signed uri whose canonical form equals the request's canonical form is
  // accepted, so parameter order is the client's business; anything else is
  // handed to verifyWeb3Signed as a URI mismatch against the canonical form.
  const expectedUri = canonicalSignedUri(url.pathname, url.search);
  let expectedPath = expectedUri;
  try {
    const claimedUri = parseWeb3SignedHeader(headerValue).payload.uri;
    if (canonicalizeSignedUri(claimedUri) === expectedUri) {
      expectedPath = claimedUri;
    }
  } catch {
    // Unparseable header: verifyWeb3Signed reports it with its own error.
  }

  let verified;
  try {
    verified = await verifyWeb3Signed({
      headerValue,
      expectedOrigin: resolveOrigin(input.serverOrigin),
      expectedMethod: input.request.method,
      expectedPath,
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

  // The compact `{payload}.{signature}` form (scheme prefix stripped) is what
  // gets stored, so verifiers don't need to know the header framing; the raw
  // payload is also where the optional `nonce` claim is read from.
  const { payloadBase64, signature } = parseWeb3SignedHeader(headerValue);
  const nonce = signedNonce(payloadBase64);

  // Bodyless methods (the derivative read / delete routes) never carry a
  // body: skip the canonical-JSON rule explicitly instead of running it over
  // empty bytes, where isJsonContentType's missing-header default would send
  // it into a swallowed JSON.parse throw.
  if (
    !isBodylessMethod(input.request.method) &&
    bodyBytes.byteLength > 0 &&
    isJsonContentType(input.request)
  ) {
    assertCanonicalJsonBody(bodyBytes);
  }

  // Replay guard, last: only a proof that passed every check is consumed,
  // so a rejected request never burns a proof.
  //
  // Without a `nonce` claim the key is the proof itself, so two identical
  // requests signed in the same second (a naive poll of GET /questions/:id)
  // produce byte-identical proofs and the second is refused. A proof that
  // carries a nonce is keyed by (builder, nonce) instead: the builder makes
  // each call distinct, and re-using a nonce is a replay even if the rest of
  // the payload changed.
  let releaseProof: (() => Promise<void>) | undefined;
  if (input.replayStore) {
    const store = input.replayStore;
    const proofId = await sha256HexOf(
      nonce === undefined
        ? headerValue
        : `nonce:${input.builderAddress.toLowerCase()}:${nonce}`,
    );
    const replayed = await store.consume(proofId, verified.payload.exp * 1000);
    if (replayed) {
      throw new ProtocolError(
        401,
        "WRITE_ATTRIBUTION_REPLAY",
        nonce === undefined
          ? "Payload proof already used; sign a fresh proof for each call (or add a unique nonce claim so repeated reads stay distinct)"
          : "Payload proof nonce already used; each nonce is single use",
      );
    }
    releaseProof = async () => {
      await store.release?.(proofId);
    };
  }

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
      | "AUDIENCE_MISMATCH"
      | "LINEAGE_MISMATCH",
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
 * data minus the server-stamped `$writtenBy` and `$lineage` keys, for JSON
 * and `$binary` records alike) re-hashes
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
  // Every server-stamped reserved key is stripped, not just the attribution:
  // `$lineage` is the server's validated mirror of the caller's `lineage`
  // field (the field itself stays inside the signed bytes), so a derivative
  // record re-hashes to the same signed bodyHash as a root record.
  const {
    [WRITER_ATTRIBUTION_KEY]: _attribution,
    [LINEAGE_KEY]: storedLineage,
    ...payloadData
  } = data;
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
  // The stripped mirror is not unauthenticated for that: it must restate
  // the builder-signed `lineage` field (body top level, or the binary
  // record's metadata object) in both directions, so a `$lineage` edited
  // after the write, or one removed to hide a derivative's sources, is
  // caught even though it is outside the hashed bytes. A signed list
  // (empty included: an explicit root statement) must have its mirror; an
  // absent signed field must have none.
  const signedField = extractLineageField(
    isBinaryEnvelope({ data: payloadData })
      ? payloadData.metadata
      : payloadData,
  );
  // Absent or null means "no statement". Anything else that is not a list
  // of strings is a malformed signed field: an independently constructed
  // record must not pass verification just because its lineage claim is
  // unreadable, so it is a mismatch, never "absent".
  const signedAbsent = signedField === undefined || signedField === null;
  const signedWellFormed =
    Array.isArray(signedField) &&
    signedField.every((id) => typeof id === "string");
  const signed =
    signedAbsent || !signedWellFormed
      ? null
      : (signedField as string[]).map((id) => id.toLowerCase());
  let mirror: ReturnType<typeof readStoredLineage>;
  try {
    mirror = storedLineage === undefined ? null : readStoredLineage(data);
  } catch (error) {
    if (error instanceof StoredLineageMalformedError) {
      throw new WriterAttributionVerificationError(
        "LINEAGE_MISMATCH",
        `stored $lineage mirror is malformed: ${error.message}`,
      );
    }
    throw error;
  }
  const consistent =
    !signedAbsent && !signedWellFormed
      ? false
      : signed === null
        ? storedLineage === undefined
        : mirror !== null &&
          signed.length === mirror.sources.length &&
          signed.every((id, i) => id === mirror.sources[i]);
  if (!consistent) {
    throw new WriterAttributionVerificationError(
      "LINEAGE_MISMATCH",
      "Stored $lineage does not restate the builder-signed lineage field",
    );
  }
  return {
    builder: attribution.builder,
    grantId: attribution.grantId,
    bodyHash,
    payload: proof.payload,
  };
}
