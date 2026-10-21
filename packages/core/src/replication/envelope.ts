import { z } from "zod";

const token = z.string().min(1);
const integer = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const timestamp = z.string().datetime({ offset: true });
const revision = z.strictObject({
  wallMs: integer,
  logical: integer,
  writerId: token,
  operationId: token,
});
const upstreamAccount = z.strictObject({ issuer: token, subject: token });
export type UpstreamAccount = z.infer<typeof upstreamAccount>;
export const declarationBindingSchema = z.strictObject({
  digest,
  version: token,
  stream: token,
  semantics: z.enum(["mutable_state", "append_only"]),
  primaryKey: z.array(token).min(1),
  schemaDigest: digest,
  sourceVersionOrder: z
    .enum(["ordered-integer", "ordered-rfc3339", "equality-only"])
    .optional(),
  reobservable: z.boolean().optional(),
  completeScanDeletes: z.boolean().optional(),
});
export type DeclarationBinding = z.infer<typeof declarationBindingSchema>;
const base = {
  owner: token,
  sourceId: token,
  connectionId: token,
  methodId: token,
  upstreamAccount,
  batchId: token,
  frontier: z
    .record(token, z.strictObject({ wallMs: integer, logical: integer }))
    .default({}),
  generation: integer.min(1),
  revision,
};
const record = {
  ...base,
  declaration: declarationBindingSchema,
  recordKey: z.string(),
  emittedAt: timestamp,
  contentHash: digest,
};
const sourceVersion = z.strictObject({
  domain: token,
  incarnation: token,
  value: token,
});
const blob = z.strictObject({
  blobId: token,
  sha256: digest,
  mimeType: token,
  sizeBytes: integer,
});
const ownerRecord = {
  ...base,
  declaration: declarationBindingSchema,
  recordKey: z.string(),
};
const resolvedValue = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("upsert"),
    data: z.record(z.string(), z.json()),
    blobs: z.array(blob),
    contentHash: digest,
  }),
  z.strictObject({ kind: z.literal("source-delete"), contentHash: digest }),
]);
export const replicaOperationSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    ...record,
    kind: z.literal("upsert"),
    data: z.record(z.string(), z.json()),
    blobs: z.array(blob),
    sourceVersion: sourceVersion.optional(),
  }),
  z.strictObject({
    ...record,
    kind: z.literal("source-delete"),
    origin: z.enum(["source-event", "complete-scan"]),
    confirmationOf: token.optional(),
    sourceVersion: sourceVersion.optional(),
  }),
  z.strictObject({
    ...ownerRecord,
    kind: z.literal("owner-hide"),
    parents: z.array(token),
  }),
  z.strictObject({
    ...ownerRecord,
    kind: z.literal("owner-delete"),
    parents: z.array(token),
  }),
  z.strictObject({
    ...ownerRecord,
    kind: z.literal("owner-restore"),
    parents: z.array(token),
  }),
  z.strictObject({
    ...ownerRecord,
    kind: z.literal("owner-resolve"),
    candidates: z.array(token),
    choice: token,
    version: sourceVersion.optional(),
    resolvedValue,
  }),
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
]);
export type ReplicaOperation = z.infer<typeof replicaOperationSchema>;
export type RecordOperation = Extract<
  ReplicaOperation,
  { declaration: DeclarationBinding }
>;
export type SourceObservation = Extract<
  RecordOperation,
  { kind: "upsert" | "source-delete" }
>;
export const replicaEnvelopeSchema = z.strictObject({
  format: z.literal("vana-pdpp-replica"),
  version: z.literal(1),
  owner: token,
  batchId: token,
  frontier: z
    .record(token, z.strictObject({ wallMs: integer, logical: integer }))
    .default({}),
  operations: z.array(replicaOperationSchema).min(1),
});
export type ReplicaEnvelope = z.infer<typeof replicaEnvelopeSchema>;

/** Canonical JSON for this profile: recursive code-unit key ordering, JSON numbers. */
export function canonicalJson(value: unknown): string {
  const json = z.json().parse(value);
  function encode(value: ReturnType<typeof z.json>["_output"]): string {
    if (Array.isArray(value)) return `[${value.map(encode).join(",")}]`;
    if (value !== null && typeof value === "object") {
      return `{${Object.keys(value)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${encode(value[key])}`)
        .join(",")}}`;
    }
    return JSON.stringify(value);
  }
  return encode(json);
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
    if (operation.batchId !== envelope.batchId)
      throw new Error("operation batch binding mismatch");
    if (canonicalJson(operation.frontier) !== canonicalJson(envelope.frontier))
      throw new Error("operation frontier binding mismatch");
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
