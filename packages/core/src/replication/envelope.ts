import { z } from "zod";

const token = z.string().min(1);
const integer = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
export const declarationBindingSchema = z.strictObject({
  digest,
  version: token,
  stream: token,
  semantics: z.enum(["mutable_state", "append_only"]),
  primaryKey: z.array(token).min(1),
  schemaDigest: digest,
});
export type DeclarationBinding = z.infer<typeof declarationBindingSchema>;
/**
 * What a binding contributes to record identity: stream, semantics and
 * ordered primary key. Two bindings of one source with the same shape are
 * versions of one stream (a declaration upgrade). Their operations merge by
 * revision, and each one validates against its own schema.
 */
export function declarationShape(binding: DeclarationBinding): string {
  return canonicalJson([binding.stream, binding.semantics, binding.primaryKey]);
}
const base = {
  owner: token,
  sourceId: token,
  connectionId: token,
  methodId: token,
  generation: integer.min(1),
  revision: z.strictObject({
    counter: integer.min(1),
    writerId: token,
    operationId: token,
    origin: z.strictObject({ writerId: token, operationId: token }).optional(),
  }),
};
const record = {
  ...base,
  declaration: declarationBindingSchema,
  recordKey: z.string(),
  emittedAt: token,
};
type JsonValue =
  null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
const jsonRecordSchema = z.custom<Record<string, JsonValue>>(
  (value) =>
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    isJsonValue(value),
);
const blob = z.strictObject({
  blobId: token,
  sha256: digest,
  mimeType: token,
  sizeBytes: integer,
});
export const replicaOperationSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    ...record,
    kind: z.literal("upsert"),
    data: jsonRecordSchema,
    blobs: z.array(blob),
  }),
  z.strictObject({ ...record, kind: z.literal("delete"), deletedAt: token }),
  z.strictObject({
    ...base,
    kind: z.literal("connection-register"),
    generation: z.literal(1),
  }),
  z.strictObject({
    ...base,
    kind: z.literal("connection-reset"),
    previousGeneration: integer.min(1),
  }),
  z.strictObject({ ...base, kind: z.literal("connection-delete") }),
  z.strictObject({ ...base, kind: z.literal("blob-claim"), blob }),
  z.strictObject({
    ...base,
    kind: z.literal("stream-invalidate"),
    declaration: declarationBindingSchema,
  }),
  z.strictObject({
    ...base,
    kind: z.literal("stream-complete"),
    declaration: declarationBindingSchema,
    sourceCollectedAt: token,
    liveCount: integer,
    snapshotSha256: digest,
    proof: z.discriminatedUnion("kind", [
      z.strictObject({
        kind: z.literal("native"),
        snapshotSha256: digest,
        collectionTimeBasis: z.literal("host_run_finished"),
      }),
      z.strictObject({
        kind: z.literal("producer-asserted"),
        snapshotSha256: z.null(),
        collectionTimeBasis: z.null(),
      }),
    ]),
    dependencies: z.array(
      z.strictObject({ writerId: token, operationId: token, digest }),
    ),
  }),
]);
export type ReplicaOperation = z.infer<typeof replicaOperationSchema>;
export type RecordOperation = Extract<
  ReplicaOperation,
  { kind: "upsert" | "delete" }
>;
export const replicaEnvelopeSchema = z.strictObject({
  format: z.literal("vana-pdpp-replica"),
  version: z.literal(1),
  owner: token,
  batchId: token,
  operations: z.array(replicaOperationSchema).min(1),
});
export type ReplicaEnvelope = z.infer<typeof replicaEnvelopeSchema>;

function isJsonValue(value: unknown): value is JsonValue {
  try {
    exactJson(value);
    return true;
  } catch {
    return false;
  }
}

/** Canonical JSON for the profile, preserving every own key at every depth. */
export function canonicalJson(value: unknown): string {
  return exactJson(value);
}

/** Canonical JSON serializer shared by wire encoding and replication digests. */
export function exactJson(value: unknown): string {
  if (Array.isArray(value)) {
    // `map` skips holes, which would encode `new Array(1)` as `[]`.
    for (let index = 0; index < value.length; index++)
      if (!Object.hasOwn(value, index))
        throw new TypeError(`not a JSON value: array hole at ${index}`);
    return `[${value.map(exactJson).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${exactJson(record[key])}`)
      .join(",")}}`;
  }
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  )
    return JSON.stringify(value);
  throw new TypeError(`not a JSON value: ${typeof value}`);
}

export interface EnvelopeExpectation {
  /** Established by authenticated transport, never taken from the body itself. */
  owner: string;
  declarations: readonly { sourceId: string; binding: DeclarationBinding }[];
}

/** Binding checks are not signature verification; authenticate/decrypt before calling. */
export function decodeReplicaEnvelope(
  encoded: string,
  expected: EnvelopeExpectation,
): ReplicaEnvelope {
  const envelope = replicaEnvelopeSchema.parse(JSON.parse(encoded));
  if (envelope.owner !== expected.owner) throw new Error("wrong owner");
  for (const operation of envelope.operations) {
    if (operation.owner !== expected.owner)
      throw new Error("wrong operation owner");
    if (
      "declaration" in operation &&
      !expected.declarations.some(
        (entry) =>
          entry.sourceId === operation.sourceId &&
          canonicalJson(entry.binding) === canonicalJson(operation.declaration),
      )
    ) {
      throw new Error("declaration binding mismatch");
    }
  }
  if (canonicalJson(envelope) !== encoded)
    throw new Error("noncanonical replica envelope");
  return envelope;
}

export function encodeReplicaEnvelope(
  envelope: ReplicaEnvelope,
  expected: EnvelopeExpectation,
): string {
  return canonicalJson(
    decodeReplicaEnvelope(canonicalJson(envelope), expected),
  );
}

/**
 * UTF-8 bytes per stored part of long replication text (a copy's envelope,
 * a received fragment). A phone's SQL call carries or returns about 1 MiB
 * at most (PS-Lite `LITE_REPLICA_SQL_BYTES`), and Node batches target
 * 32 MiB in 4 MiB fragments, so such text is kept in rows of parts.
 */
export const REPLICA_TEXT_PART_BYTES = 512 * 1024;

/**
 * `text` in order, cut into parts of at most `maxBytes` UTF-8 bytes. A
 * cut never falls inside a surrogate pair, so each part is valid text.
 */
export function replicaTextParts(text: string, maxBytes: number): string[] {
  const parts: string[] = [];
  let start = 0;
  let bytes = 0;
  for (let index = 0; index < text.length;) {
    const code = text.codePointAt(index)!;
    const units = code > 0xffff ? 2 : 1;
    const size = code < 0x80 ? 1 : code < 0x800 ? 2 : code > 0xffff ? 4 : 3;
    if (bytes + size > maxBytes) {
      parts.push(text.slice(start, index));
      start = index;
      bytes = 0;
    }
    bytes += size;
    index += units;
  }
  parts.push(text.slice(start));
  return parts;
}
