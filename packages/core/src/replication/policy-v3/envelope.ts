import { z } from "zod";
import { canonicalJson } from "./canonical.js";
export { canonicalJson } from "./canonical.js";

const token = z.string().min(1);
const integer = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const logicalCounter = z.union([
  integer,
  z
    .string()
    .regex(/^(0|[1-9]\d*)$/)
    .refine((value) => BigInt(value) <= (1n << 64n) - 1n),
]);
const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const timestamp = z.string().datetime({ offset: true });
const revision = z.strictObject({
  wallMs: integer,
  logical: logicalCounter,
  writerId: token,
  operationId: token,
});
/** References stay unambiguous when two writers reuse an operation id. */
const operationReference = z.strictObject({
  writerId: token,
  operationId: token,
});
export type OperationReference = z.infer<typeof operationReference>;
export { operationReferenceOf } from "./references.js";
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
  frontier: z.record(
    token,
    z.strictObject({ wallMs: integer, logical: logicalCounter }),
  ),
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
const jsonRecord = z.custom<Record<string, unknown>>((value) => {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return false;
  try {
    canonicalJson(value);
    return true;
  } catch {
    return false;
  }
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
    data: jsonRecord,
    blobs: z.array(blob),
    contentHash: digest,
  }),
  z.strictObject({ kind: z.literal("source-delete"), contentHash: digest }),
]);
export const replicaOperationSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    ...record,
    kind: z.literal("upsert"),
    data: jsonRecord,
    blobs: z.array(blob),
    sourceVersion: sourceVersion.optional(),
  }),
  z.strictObject({
    ...record,
    kind: z.literal("source-delete"),
    origin: z.enum(["source-event", "complete-scan"]),
    confirmationOf: operationReference.optional(),
    sourceVersion: sourceVersion.optional(),
  }),
  z.strictObject({
    ...ownerRecord,
    kind: z.literal("owner-hide"),
    parents: z.array(operationReference),
  }),
  z.strictObject({
    ...ownerRecord,
    kind: z.literal("owner-delete"),
    parents: z.array(operationReference),
  }),
  z.strictObject({
    ...ownerRecord,
    kind: z.literal("owner-restore"),
    parents: z.array(operationReference),
  }),
  z.strictObject({
    ...ownerRecord,
    kind: z.literal("owner-resolve"),
    candidates: z.array(operationReference),
    choice: operationReference,
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
  // These preserve main's operation contracts. The v3 pure planner holds their
  // effects pending; blob verification and completion projection are step6.
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
export type RecordOperation = Extract<ReplicaOperation, { recordKey: string }>;
export type SourceObservation = Extract<
  RecordOperation,
  { kind: "upsert" | "source-delete" }
>;
export const replicaEnvelopeSchema = z.strictObject({
  format: z.literal("vana-pdpp-replica"),
  version: z.literal(3),
  owner: token,
  batchId: token,
  frontier: z.record(
    token,
    z.strictObject({ wallMs: integer, logical: logicalCounter }),
  ),
  operations: z.array(replicaOperationSchema).min(1),
});
export type ReplicaEnvelope = z.infer<typeof replicaEnvelopeSchema>;

export interface EnvelopeExpectation {
  /** Established by authenticated transport, never taken from the body itself. */
  owner: string;
  /** When transport has authenticated a writer, require that exact identity. */
  writerId?: string;
  declarations: readonly { sourceId: string; binding: DeclarationBinding }[];
}

/** Binding checks are not signature verification; authenticate/decrypt before calling. */
export function decodeReplicaEnvelope(
  encoded: string,
  expected: EnvelopeExpectation,
): ReplicaEnvelope {
  const envelope = replicaEnvelopeSchema.parse(JSON.parse(encoded));
  if (envelope.owner !== expected.owner) throw new Error("wrong owner");
  const writerId =
    expected.writerId ?? envelope.operations[0].revision.writerId;
  if (Object.hasOwn(envelope.frontier, writerId))
    throw new Error("self writer frontier");
  for (const operation of envelope.operations) {
    if (operation.revision.writerId !== writerId)
      throw new Error("wrong operation writer");
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
