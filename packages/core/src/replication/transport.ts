import { z } from "zod";
import { DataFileEnvelopeSchema } from "@opendatalabs/vana-sdk/browser";
import { sha256, keccak256, stringToHex } from "viem";
import { canonicalJson } from "./envelope.js";

/** Reserved across ordinary reads, grants, inventory, MCP and legacy sync. */
import { REPLICA_SCOPE_PREFIX } from "./namespace.js";
export { REPLICA_SCOPE_PREFIX, isReplicaScope } from "./namespace.js";
/** vana-storage DEFAULT_MAX_BLOB_SIZE. Compare the actual encrypted request. */
export const REPLICA_MAX_BLOB_BYTES = 100 * 1024 * 1024;
const token = z.string().regex(/^[a-f0-9]{32}$/);
const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const integer = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
export const predecessorSchema = z.strictObject({ batch: token, digest });
export const replicaFragmentSchema = z.strictObject({
  format: z.literal("vana-pdpp-replica-fragment"),
  version: z.literal(1),
  owner: z.string().min(1),
  writer: token,
  batch: token,
  sequence: integer.min(1),
  previous: predecessorSchema.nullable(),
  collectedAt: z.string().datetime({ offset: true }),
  digest,
  totalBytes: integer.min(1),
  count: integer.min(1).max(100000),
  index: integer,
  offset: integer,
  chunkDigest: digest,
  content: z.string(),
});
export type ReplicaFragment = z.infer<typeof replicaFragmentSchema>;
export type Predecessor = z.infer<typeof predecessorSchema>;
export interface PreparedFragment {
  scope: string;
  plaintext: Uint8Array;
  encrypted: Uint8Array;
  dataHash: `0x${string}`;
  metadataHash: `0x${string}`;
}
export function replicaScope(
  writer: string,
  batch: string,
  index: number,
): string {
  token.parse(writer);
  token.parse(batch);
  integer.parse(index);
  return `${REPLICA_SCOPE_PREFIX}.${writer}_${batch}.${index}`;
}
export function replicaDigest(bytes: Uint8Array): string {
  return `sha256:${sha256(bytes).slice(2)}`;
}
export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 8192)
    binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(binary);
}
export function fromBase64(value: string): Uint8Array {
  const bytes = Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  if (toBase64(bytes) !== value) throw new Error("noncanonical base64");
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
export function decodeReplicaFragment(
  plaintext: Uint8Array,
  scope: string,
  owner: string,
): ReplicaFragment {
  const encoded = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  const wrapper = DataFileEnvelopeSchema.parse(JSON.parse(encoded));
  const fragment = replicaFragmentSchema.parse(wrapper.data.fragment);
  if (
    canonicalJson(wrapper) !== encoded ||
    wrapper.scope !== scope ||
    wrapper.collectedAt !== fragment.collectedAt ||
    fragment.owner !== owner ||
    scope !== replicaScope(fragment.writer, fragment.batch, fragment.index) ||
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

/** A batch address is reserved by its caller; all returned bytes must be committed before I/O. */
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
    if (count > 100000) throw new RangeError("too many replica fragments");
    const parts: PreparedFragment[] = [];
    let oversized = false;
    for (let index = 0; index < count; index++) {
      const offset = index * chunkSize;
      const chunk = input.bytes.subarray(offset, offset + chunkSize);
      const scope = replicaScope(input.writer, input.batch, index);
      const fragment = replicaFragmentSchema.parse({
        format: "vana-pdpp-replica-fragment",
        version: 1,
        owner: input.owner,
        writer: input.writer,
        batch: input.batch,
        sequence: input.sequence,
        previous: input.previous,
        collectedAt: input.collectedAt,
        digest,
        totalBytes: input.bytes.length,
        count,
        index,
        offset,
        chunkDigest: replicaDigest(chunk),
        content: toBase64(chunk),
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
      if (encrypted.length > cap) {
        oversized = true;
        break;
      }
      parts.push({
        scope,
        plaintext,
        encrypted,
        dataHash: keccak256(plaintext),
        metadataHash: replicaMetadataHash(
          scope,
          input.collectedAt,
          encrypted.length,
        ),
      });
    }
    if (!oversized) return parts;
    if (chunkSize === 1)
      throw new RangeError("encrypted fragment header exceeds storage cap");
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
