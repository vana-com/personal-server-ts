import { type DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";

/**
 * Binary / unstructured data is carried inside the standard DataFileEnvelope's
 * `data` record (the envelope schema is owned by the SDK and only permits a
 * JSON object there, so the bytes are base64-encoded into a marked record).
 * This keeps the entire encrypt → upload → register → download path unchanged;
 * only ingest and read need to understand the binary shape.
 */
export const BINARY_MARKER = "$binary" as const;
export const BINARY_ENCODING = "base64" as const;

export interface BinaryEnvelopeData extends Record<string, unknown> {
  $binary: true;
  mimeType: string;
  filename?: string;
  /** Plaintext byte length (before base64). */
  sizeBytes: number;
  /** 0x-prefixed SHA-256 of the plaintext bytes. */
  contentHash: `0x${string}`;
  encoding: typeof BINARY_ENCODING;
  content: string;
  /** Free-form caller metadata (e.g. a description). Omitted when absent. */
  metadata?: unknown;
}

/** Build the `data` record for a binary envelope (does not hash — see ingest). */
export function buildBinaryEnvelopeData(params: {
  bytes: Uint8Array;
  mimeType: string;
  filename?: string;
  contentHash: `0x${string}`;
  metadata?: unknown;
}): BinaryEnvelopeData {
  return {
    $binary: true,
    mimeType: params.mimeType,
    ...(params.filename ? { filename: params.filename } : {}),
    sizeBytes: params.bytes.length,
    contentHash: params.contentHash,
    encoding: BINARY_ENCODING,
    content: bytesToBase64(params.bytes),
    ...(params.metadata !== undefined ? { metadata: params.metadata } : {}),
  };
}

export function isBinaryEnvelope(
  envelope: Pick<DataFileEnvelope, "data">,
): boolean {
  const data = envelope.data as Record<string, unknown> | undefined;
  return data?.[BINARY_MARKER] === true;
}

export interface DecodedBinary {
  bytes: Uint8Array;
  mimeType: string;
  filename?: string;
  metadata?: unknown;
}

/** Decode a binary envelope back to raw bytes for serving over HTTP. */
export function decodeBinaryEnvelope(
  envelope: Pick<DataFileEnvelope, "data">,
): DecodedBinary {
  const data = envelope.data as unknown as BinaryEnvelopeData;
  if (data?.[BINARY_MARKER] !== true || typeof data.content !== "string") {
    throw new Error("Envelope does not contain binary data");
  }
  return {
    bytes: base64ToBytes(data.content),
    mimeType:
      typeof data.mimeType === "string"
        ? data.mimeType
        : "application/octet-stream",
    filename: typeof data.filename === "string" ? data.filename : undefined,
    metadata: data.metadata,
  };
}

/**
 * Parse a free-form metadata header value. Best-effort: a value that parses as
 * JSON is stored as the parsed value (object/array/etc); anything else is kept
 * as a plain string (so a bare description "just works"). Returns undefined for
 * absent/blank input.
 */
export function parseMetadataHeader(value: string | null): unknown {
  if (value === null) return undefined;
  const trimmed = value.trim();
  if (trimmed === "") return undefined;
  try {
    return JSON.parse(trimmed);
  } catch {
    return value;
  }
}

/** Serialize metadata for an HTTP response header (string as-is, else JSON). */
export function stringifyMetadataHeader(metadata: unknown): string {
  return typeof metadata === "string" ? metadata : JSON.stringify(metadata);
}

/** 0x-prefixed SHA-256 hex of the given bytes (Web Crypto, browser + node). */
export async function sha256Hex(bytes: Uint8Array): Promise<`0x${string}`> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    bytes as unknown as BufferSource,
  );
  return ("0x" + bytesToHex(new Uint8Array(digest))) as `0x${string}`;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

const BASE64_CHUNK = 0x8000;

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += BASE64_CHUNK) {
    const chunk = bytes.subarray(i, i + BASE64_CHUNK);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
