import { z } from "zod";
import { DataFileEnvelopeSchema } from "@opendatalabs/vana-sdk/browser";
import { sha256, keccak256, stringToHex } from "viem";
import { canonicalJson } from "./envelope.js";
import { ReplicaFramingUnsupported } from "./outcome.js";
import {
  replicaBatchAuthoritySchema,
  type ReplicaBatchFacts,
} from "./writer-identity.js";

/** Reserved across ordinary reads, grants, inventory, MCP and legacy sync. */
import { REPLICA_SCOPE_PREFIX } from "./namespace.js";
export { REPLICA_SCOPE_PREFIX, isReplicaScope } from "./namespace.js";
/** Protocol limit on fragments per batch, and so on entries per manifest. */
export const REPLICA_MAX_FRAGMENTS = 100000;
/** vana-storage DEFAULT_MAX_BLOB_SIZE. Compare the actual encrypted request. */
export const REPLICA_MAX_BLOB_BYTES = 100 * 1024 * 1024;
/**
 * Bytes an encrypted fragment adds to the base64 of its chunk: the envelope,
 * the fragment fields and the OpenPGP framing. Bounds the fragment bytes a
 * manifest may name for its payload length (`replicaFramedBytesBound`).
 */
export const REPLICA_FRAGMENT_OVERHEAD_BYTES = 4096;
/** Nesting that no manifest or fragment reaches. */
export const REPLICA_MAX_JSON_DEPTH = 16;
/**
 * Structural characters (`[`, `{`, `,` and `:`) of a manifest at the
 * fragment limit, with room for its statement. A small document of tiny
 * values allocates far more than its size, so this is bounded before parsing.
 */
export const REPLICA_MAX_JSON_TOKENS = 8 * REPLICA_MAX_FRAGMENTS + 4096;
const token = z.string().regex(/^[a-f0-9]{32}$/);
const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const integer = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
export const predecessorSchema = z.strictObject({ batch: token, digest });
export const replicaFragmentSchema = z.strictObject({
  format: z.literal("vana-pdpp-replica-fragment"),
  /**
   * Version 3 is stored unregistered and is trusted only through the signed
   * manifest that names its digest, so it carries no statement of its own.
   * Versions 1 and 2 were registered one fragment per scope.
   */
  version: z.literal(3),
  owner: z.string().min(1),
  writer: token,
  batch: token,
  sequence: integer.min(1),
  previous: predecessorSchema.nullable(),
  collectedAt: z.string().datetime({ offset: true }),
  digest,
  totalBytes: integer.min(1),
  count: integer.min(1).max(REPLICA_MAX_FRAGMENTS),
  index: integer,
  offset: integer,
  chunkDigest: digest,
  content: z.string(),
});
export type ReplicaFragment = z.infer<typeof replicaFragmentSchema>;
export type Predecessor = z.infer<typeof predecessorSchema>;
/**
 * One fragment's entry in its batch manifest: the sha256 of the exact
 * encrypted object and its length. The digest is also the storage address,
 * so a receiver checks fetched bytes against the finalized manifest before
 * it decrypts them.
 */
export const manifestEntrySchema = z.strictObject({
  digest,
  bytes: integer.min(1).max(REPLICA_MAX_BLOB_BYTES),
});
export type ManifestEntry = z.infer<typeof manifestEntrySchema>;
/**
 * The one registered object of a batch. Its DPv2 slot is the writer's scope at
 * the next free version. It lists every fragment, in index order, by digest
 * and size, and carries the batch statement signed by the writer's server
 * key, which covers every other field and the slot. The version is a
 * publication slot, not the batch sequence: a batch that cannot be framed
 * takes no slot, so its successors still publish.
 */
export const replicaManifestSchema = z.strictObject({
  format: z.literal("vana-pdpp-replica-manifest"),
  version: z.literal(1),
  owner: z.string().min(1),
  writer: token,
  batch: token,
  sequence: integer.min(1),
  previous: predecessorSchema.nullable(),
  collectedAt: z.string().datetime({ offset: true }),
  digest,
  totalBytes: integer.min(1),
  fragments: z.array(manifestEntrySchema).min(1).max(REPLICA_MAX_FRAGMENTS),
  /** The batch statement signed by the writer's server key (host contract §3.3). */
  authority: replicaBatchAuthoritySchema,
});
export type ReplicaManifest = z.infer<typeof replicaManifestSchema>;
/** An unregistered, content-addressed fragment ready for storage. */
export interface PreparedFragment {
  /** The writer scope whose key encrypts the fragment. */
  scope: string;
  index: number;
  plaintext: Uint8Array;
  encrypted: Uint8Array;
  /** sha256 of `encrypted`: the manifest entry and the storage address. */
  digest: string;
}
/** A batch manifest ready for storage and its single registration. */
export interface PreparedManifest {
  scope: string;
  /** The DPv2 version this manifest registers, claimed when the batch is prepared. */
  version: number;
  plaintext: Uint8Array;
  encrypted: Uint8Array;
  dataHash: `0x${string}`;
  metadataHash: `0x${string}`;
}
/** One stable scope per writer. Each batch appends one version to it. */
export function replicaScope(writer: string): string {
  token.parse(writer);
  return `${REPLICA_SCOPE_PREFIX}.${writer}`;
}
/** The writer of a replica scope, or undefined for any other name. */
export function replicaWriterOf(scope: string): string | undefined {
  const writer = scope.slice(REPLICA_SCOPE_PREFIX.length + 1);
  return scope === `${REPLICA_SCOPE_PREFIX}.${writer}` &&
    token.safeParse(writer).success
    ? writer
    : undefined;
}
/** Storage key of a content-addressed fragment. Never registered. */
export function replicaFragmentKey(scope: string, fragmentDigest: string) {
  digest.parse(fragmentDigest);
  return `${scope}/fragments/${fragmentDigest.slice("sha256:".length)}`;
}
/** Storage key of a manifest: the ordinary DPv2 `<scope>/<version>` key. */
export function replicaManifestKey(scope: string, version: number) {
  integer.min(1).parse(version);
  return `${scope}/${version}`;
}
export function replicaDigest(bytes: Uint8Array): string {
  return `sha256:${sha256(bytes).slice(2)}`;
}
export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 8192)
    binary += Reflect.apply(
      String.fromCharCode,
      null,
      bytes.subarray(i, i + 8192),
    );
  return btoa(binary);
}
export function fromBase64(value: string): Uint8Array {
  if (typeof value !== "string") throw new Error("noncanonical base64");
  const binary = atob(value);
  // atob validates the alphabet and padding placement, but accepts whitespace,
  // omitted padding and nonzero unused bits. Reject those without re-encoding
  // the whole decoded object into another binary string and base64 string.
  if (
    value.length !== 4 * Math.ceil(binary.length / 3) ||
    /[\t\n\f\r ]/.test(value)
  )
    throw new Error("noncanonical base64");
  const remainder = binary.length % 3;
  if (remainder) {
    const padding = 3 - remainder;
    const last =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(
        value[value.length - padding - 1]!,
      );
    // Two '=' leave four unused bits; one '=' leaves two unused bits.
    if ((last & (padding === 2 ? 15 : 3)) !== 0)
      throw new Error("noncanonical base64");
  }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++)
    bytes[index] = binary.charCodeAt(index);
  return bytes;
}
export function replicaMetadataHash(
  scope: string,
  collectedAt: string,
  sizeBytes: number,
) {
  return keccak256(
    stringToHex(JSON.stringify({ scope, collectedAt, sizeBytes })),
  );
}
/**
 * A manifest that can never be valid at its slot, with the refusal of the
 * first check it fails. The caller has already matched its bytes to the
 * slot's finalized commitment, so the refusal is terminal.
 */
export class ReplicaManifestRefused extends Error {
  constructor(
    readonly reason:
      | "signature_invalid"
      | "partition_mismatch"
      | "writer_mismatch"
      | "manifest_invalid",
  ) {
    super(`replica manifest refused: ${reason}`);
    this.name = "ReplicaManifestRefused";
  }
}

/** Replica JSON over a bound that no writer reaches. */
export class ReplicaJsonRefused extends Error {
  constructor() {
    super("replica JSON over its depth or token bound");
    this.name = "ReplicaJsonRefused";
  }
}

export interface ParsedReplicaJson {
  encoded: string;
  value: unknown;
}

/**
 * Parse replica JSON. One pass without recursion bounds nesting and
 * structural tokens before `JSON.parse` allocates anything, so the recursive
 * work after it (schemas, `canonicalJson`) stays inside those bounds. Throws
 * ReplicaJsonRefused over a bound, and the parser's own error for bytes that
 * are not UTF-8 JSON.
 */
export function parseReplicaJson(plaintext: Uint8Array): ParsedReplicaJson {
  const encoded = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  let depth = 0;
  let tokens = 0;
  let quoted = false;
  for (let index = 0; index < encoded.length; index++) {
    const code = encoded.charCodeAt(index);
    if (quoted) {
      if (code === 0x5c) index++;
      else if (code === 0x22) quoted = false;
      continue;
    }
    if (code === 0x22) quoted = true;
    else if (code === 0x5d || code === 0x7d) depth--;
    else if (code === 0x5b || code === 0x7b || code === 0x2c || code === 0x3a) {
      if (
        ++tokens > REPLICA_MAX_JSON_TOKENS ||
        ((code === 0x5b || code === 0x7b) && ++depth > REPLICA_MAX_JSON_DEPTH)
      )
        throw new ReplicaJsonRefused();
    }
  }
  return { encoded, value: JSON.parse(encoded) };
}

/**
 * The most encrypted fragment bytes a batch of `totalBytes` needs in `count`
 * fragments: the base64 of every chunk plus a fixed overhead per fragment.
 */
export function replicaFramedBytesBound(totalBytes: number, count: number) {
  return (
    4 * Math.ceil(totalBytes / 3) +
    count * (4 + REPLICA_FRAGMENT_OVERHEAD_BYTES)
  );
}

/** The facts a manifest at `version` claims; its statement must sign exactly these. */
export function replicaManifestFacts(
  manifest: Omit<ReplicaManifest, "authority">,
  version: number,
): ReplicaBatchFacts {
  return {
    version,
    batch: manifest.batch,
    sequence: manifest.sequence,
    previous: manifest.previous,
    collectedAt: manifest.collectedAt,
    digest: manifest.digest,
    totalBytes: manifest.totalBytes,
    fragments: manifest.fragments,
  };
}

export function decodeReplicaFragment(
  plaintext: Uint8Array,
  scope: string,
  owner: string,
): ReplicaFragment {
  return decodeParsedReplicaFragment(parseReplicaJson(plaintext), scope, owner);
}

/** Fragment decoding after the shared receive boundary's bounded parse. */
export function decodeParsedReplicaFragment(
  { encoded, value }: ParsedReplicaJson,
  scope: string,
  owner: string,
): ReplicaFragment {
  const wrapper = DataFileEnvelopeSchema.parse(value);
  const fragment = replicaFragmentSchema.parse(wrapper.data.fragment);
  if (
    canonicalJson(wrapper) !== encoded ||
    wrapper.scope !== scope ||
    wrapper.collectedAt !== fragment.collectedAt ||
    fragment.owner !== owner ||
    scope !== replicaScope(fragment.writer) ||
    fragment.index >= fragment.count ||
    (fragment.sequence === 1) !== (fragment.previous === null)
  )
    throw new Error("invalid replica fragment binding");
  const chunk = fromBase64(fragment.content);
  if (
    !chunk.length ||
    fragment.offset + chunk.length > fragment.totalBytes ||
    replicaDigest(chunk) !== fragment.chunkDigest
  )
    throw new Error("corrupt replica fragment");
  return fragment;
}

/** All returned bytes must be committed before I/O: encryption is randomized. */
/** The single fragment encoder shared by buffered and streaming publishers. */
export async function prepareReplicaFragment(input: {
  owner: string;
  writer: string;
  batch: string;
  sequence: number;
  previous: Predecessor | null;
  collectedAt: string;
  digest: string;
  totalBytes: number;
  count: number;
  index: number;
  offset: number;
  chunk: Uint8Array;
  encrypt: (scope: string, bytes: Uint8Array) => Promise<Uint8Array>;
}): Promise<PreparedFragment> {
  const scope = replicaScope(input.writer);
  const fragment = replicaFragmentSchema.parse({
    format: "vana-pdpp-replica-fragment",
    version: 3,
    owner: input.owner,
    writer: input.writer,
    batch: input.batch,
    sequence: input.sequence,
    previous: input.previous,
    collectedAt: input.collectedAt,
    digest: input.digest,
    totalBytes: input.totalBytes,
    count: input.count,
    index: input.index,
    offset: input.offset,
    chunkDigest: replicaDigest(input.chunk),
    content: toBase64(input.chunk),
  });
  const plaintext = new TextEncoder().encode(
    canonicalJson({
      version: "1.0",
      scope,
      collectedAt: input.collectedAt,
      data: { fragment },
    }),
  );
  // Validate writer/address/order grammar even for locally prepared inputs.
  decodeReplicaFragment(plaintext, scope, input.owner);
  const encrypted = await input.encrypt(scope, plaintext);
  return {
    scope,
    index: input.index,
    plaintext,
    encrypted,
    digest: replicaDigest(encrypted),
  };
}

/**
 * Encode, sign, check and encrypt the manifest of a fully prepared batch for
 * its registration at `version`. `sign` receives the facts of exactly this
 * manifest and slot.
 */
export async function prepareReplicaManifest(input: {
  owner: string;
  writer: string;
  version: number;
  batch: string;
  sequence: number;
  previous: Predecessor | null;
  collectedAt: string;
  digest: string;
  totalBytes: number;
  fragments: readonly ManifestEntry[];
  sign: (facts: ReplicaBatchFacts) => Promise<unknown>;
  encrypt: (scope: string, bytes: Uint8Array) => Promise<Uint8Array>;
}): Promise<PreparedManifest> {
  const scope = replicaScope(input.writer);
  const unsigned = replicaManifestSchema.omit({ authority: true }).parse({
    format: "vana-pdpp-replica-manifest",
    version: 1,
    owner: input.owner,
    writer: input.writer,
    batch: input.batch,
    sequence: input.sequence,
    previous: input.previous,
    collectedAt: input.collectedAt,
    digest: input.digest,
    totalBytes: input.totalBytes,
    fragments: input.fragments.map((f) => ({
      digest: f.digest,
      bytes: f.bytes,
    })),
  });
  const manifest = {
    ...unsigned,
    authority: await input.sign(replicaManifestFacts(unsigned, input.version)),
  };
  const plaintext = new TextEncoder().encode(
    canonicalJson({
      version: "1.0",
      scope,
      collectedAt: input.collectedAt,
      data: { manifest },
    }),
  );
  decodeReplicaManifest(plaintext, scope, input.owner);
  const encrypted = await input.encrypt(scope, plaintext);
  return {
    scope,
    version: integer.min(1).parse(input.version),
    plaintext,
    encrypted,
    dataHash: keccak256(plaintext),
    metadataHash: replicaMetadataHash(
      scope,
      input.collectedAt,
      encrypted.length,
    ),
  };
}

/**
 * Decode manifest plaintext. A received manifest goes through
 * `receiveReplicaManifest`, which matches its bytes to the slot's finalized
 * commitment first. The caller then authorizes its statement against
 * `replicaManifestFacts(manifest, version)`; this check binds only owner and
 * writer scope. Throws ReplicaManifestRefused and nothing else.
 */
export function decodeReplicaManifest(
  plaintext: Uint8Array,
  scope: string,
  owner: string,
): ReplicaManifest {
  let parsed: ParsedReplicaJson;
  try {
    parsed = parseReplicaJson(plaintext);
  } catch {
    throw new ReplicaManifestRefused("manifest_invalid");
  }
  return decodeParsedReplicaManifest(parsed, scope, owner);
}

/** `decodeReplicaManifest` after `parseReplicaJson`. Throws ReplicaManifestRefused and nothing else. */
export function decodeParsedReplicaManifest(
  { encoded, value }: ParsedReplicaJson,
  scope: string,
  owner: string,
): ReplicaManifest {
  try {
    const wrapper = DataFileEnvelopeSchema.safeParse(value);
    if (!wrapper.success || canonicalJson(wrapper.data) !== encoded)
      throw new ReplicaManifestRefused("manifest_invalid");
    if (wrapper.data.scope !== scope)
      throw new ReplicaManifestRefused("writer_mismatch");
    const claimed = wrapper.data.data.manifest;
    const parsed = replicaManifestSchema.safeParse(claimed);
    if (!parsed.success)
      throw new ReplicaManifestRefused(
        typeof claimed === "object" &&
          claimed !== null &&
          !replicaBatchAuthoritySchema.safeParse(
            (claimed as { authority?: unknown }).authority,
          ).success
          ? "signature_invalid"
          : "manifest_invalid",
      );
    const manifest = parsed.data;
    if (manifest.owner !== owner)
      throw new ReplicaManifestRefused("partition_mismatch");
    if (scope !== replicaScope(manifest.writer))
      throw new ReplicaManifestRefused("writer_mismatch");
    if (
      wrapper.data.collectedAt !== manifest.collectedAt ||
      (manifest.sequence === 1) !== (manifest.previous === null) ||
      new Set(manifest.fragments.map((entry) => entry.digest)).size !==
        manifest.fragments.length ||
      manifest.fragments.length > manifest.totalBytes ||
      manifest.fragments.reduce((sum, f) => sum + f.bytes, 0) >
        replicaFramedBytesBound(manifest.totalBytes, manifest.fragments.length)
    )
      throw new ReplicaManifestRefused("manifest_invalid");
    return manifest;
  } catch (error) {
    // Pure checks of authentic bytes: whatever they throw is terminal.
    if (error instanceof ReplicaManifestRefused) throw error;
    throw new ReplicaManifestRefused("manifest_invalid");
  }
}

/**
 * Check a decoded fragment against the entry of its finalized manifest. The
 * fetched bytes already hash to the entry, so a mismatch here is a writer
 * fault, never storage damage.
 */
export function fragmentMatchesManifest(
  fragment: ReplicaFragment,
  manifest: ReplicaManifest,
  index: number,
): boolean {
  return (
    fragment.owner === manifest.owner &&
    fragment.writer === manifest.writer &&
    fragment.batch === manifest.batch &&
    fragment.sequence === manifest.sequence &&
    canonicalJson(fragment.previous) === canonicalJson(manifest.previous) &&
    fragment.collectedAt === manifest.collectedAt &&
    fragment.digest === manifest.digest &&
    fragment.totalBytes === manifest.totalBytes &&
    fragment.count === manifest.fragments.length &&
    fragment.index === index
  );
}

export async function fragmentReplicaPayload(input: {
  owner: string;
  writer: string;
  batch: string;
  sequence: number;
  previous: Predecessor | null;
  bytes: Uint8Array;
  collectedAt: string;
  encrypt: (scope: string, bytes: Uint8Array) => Promise<Uint8Array>;
  maxBlobBytes?: number;
  targetChunkBytes?: number;
}): Promise<PreparedFragment[]> {
  const cap = input.maxBlobBytes ?? REPLICA_MAX_BLOB_BYTES;
  if (
    !Number.isSafeInteger(cap) ||
    cap < 1 ||
    cap > REPLICA_MAX_BLOB_BYTES ||
    !input.bytes.length
  )
    throw new RangeError("invalid replica size limit");
  let chunkSize = input.targetChunkBytes ?? 4 * 1024 * 1024;
  if (!Number.isSafeInteger(chunkSize) || chunkSize < 1)
    throw new RangeError("invalid chunk size");
  const digest = replicaDigest(input.bytes);
  while (true) {
    const count = Math.ceil(input.bytes.length / chunkSize);
    if (count > REPLICA_MAX_FRAGMENTS)
      throw new ReplicaFramingUnsupported(
        count,
        REPLICA_MAX_FRAGMENTS,
        "fragment_count",
      );
    const parts: PreparedFragment[] = [];
    let oversized = 0;
    for (let index = 0; index < count; index++) {
      const offset = index * chunkSize;
      const chunk = input.bytes.subarray(offset, offset + chunkSize);
      const part = await prepareReplicaFragment({
        ...input,
        digest,
        totalBytes: input.bytes.length,
        count,
        index,
        offset,
        chunk,
      });
      if (part.encrypted.length > cap) {
        oversized = part.encrypted.length;
        break;
      }
      parts.push(part);
    }
    if (!oversized) return parts;
    if (chunkSize === 1) throw new ReplicaFramingUnsupported(oversized, cap);
    chunkSize = Math.max(1, Math.floor(chunkSize / 2));
  }
}

/** Missing, duplicate, overlapping or inconsistent fragments never become importable bytes. */
export function assembleReplicaPayload(
  fragments: readonly ReplicaFragment[],
): Uint8Array {
  const first = fragments[0];
  if (!first || fragments.length !== first.count)
    throw new Error("incomplete replica batch");
  const sorted = [...fragments].sort((a, b) => a.index - b.index);
  const chunks = sorted.map((f) => fromBase64(f.content));
  if (chunks.reduce((n, chunk) => n + chunk.length, 0) !== first.totalBytes)
    throw new Error("invalid replica batch length");
  // Check actual retained bytes before allocating any remotely advertised total.
  const bytes = new Uint8Array(first.totalBytes);
  let offset = 0;
  const common = (f: ReplicaFragment) =>
    canonicalJson({
      owner: f.owner,
      writer: f.writer,
      batch: f.batch,
      sequence: f.sequence,
      previous: f.previous,
      collectedAt: f.collectedAt,
      digest: f.digest,
      totalBytes: f.totalBytes,
      count: f.count,
    });
  for (let index = 0; index < sorted.length; index++) {
    const f = sorted[index]!;
    const chunk = chunks[index]!;
    if (
      common(f) !== common(first) ||
      f.index !== index ||
      f.offset !== offset ||
      replicaDigest(chunk) !== f.chunkDigest ||
      offset + chunk.length > bytes.length
    )
      throw new Error("inconsistent replica fragments");
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  if (offset !== bytes.length || replicaDigest(bytes) !== first.digest)
    throw new Error("corrupt replica batch");
  return bytes;
}
