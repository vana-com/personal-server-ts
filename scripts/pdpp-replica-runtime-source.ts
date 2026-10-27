/** Dev-only source wiring from a declaration already admitted by the owner's AS.
 * Connector signature verification belongs to the caller; this verifies retained bytes.
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  parseDeclaration,
  type DeclarationSnapshot,
} from "../packages/core/src/pdpp/index.js";
import { canonicalJson } from "../packages/core/src/replication/envelope.js";
import { createSourceStreamDeclarationRegistry } from "../packages/core/src/storage/pdpp-records/stream-declaration.js";
import { createRecordDataValidator } from "../packages/core/src/storage/pdpp-records/schema.js";

/** Serializable over the existing Device IPC. No authority is inferred from names. */
export type ReplicaRuntimeSource = {
  declaration: DeclarationSnapshot;
  /** Exact UTF-8 retained declaration, including its original embedded schemas. */
  document: string;
  methodId: string;
  /** Connection explicitly provisioned by the local owner. Never supplied by a replica. */
  connectionId: string;
};

export function buildReplicaRuntimeSource(descriptor: ReplicaRuntimeSource) {
  assert(descriptor.methodId?.trim(), "Explicit source method is required");
  assert(
    descriptor.connectionId?.trim(),
    "Explicit owner-bound connection is required",
  );
  const parsed = parseDeclaration(
    descriptor.document,
    descriptor.declaration.source_id,
  );
  assert(parsed.ok, "Retained source declaration is invalid");
  assert.deepEqual(
    parsed.snapshot,
    descriptor.declaration,
    "Retained declaration does not match exact document bytes",
  );
  const declaration = parsed.snapshot;
  const sourceId = declaration.source_id;
  const { methodId, connectionId, document } = descriptor;
  const declarations = createSourceStreamDeclarationRegistry([
    {
      sourceId,
      instance: connectionId,
      streams: declaration.streams.map((stream) => {
        assert(stream.schema, "Real-source stream must retain its schema");
        return {
          name: stream.name,
          semantics: stream.semantics ?? "mutable_state",
          primaryKey: stream.primary_key,
          // The normal record store orders by emitted_at, as records-bootstrap does.
          cursorField: "emitted_at",
          consentTimeField: stream.consent_time_field,
          requiredFields: stream.required_fields,
          declaredFields: stream.fields,
          schema: stream.schema,
          ...(stream.selection && { selection: stream.selection }),
        };
      }),
    },
  ]);
  const validateData = createRecordDataValidator(declarations);
  const bindings = declaration.streams.map((stream) => ({
    sourceId,
    binding: {
      digest: `sha256:${declaration.digest}`,
      version: declaration.version,
      stream: stream.name,
      semantics: stream.semantics ?? ("mutable_state" as const),
      primaryKey: stream.primary_key,
      schemaDigest: `sha256:${createHash("sha256").update(canonicalJson(stream.schema)).digest("hex")}`,
    },
    validateData: (data: Record<string, unknown>) =>
      validateData(stream.name, connectionId, data) === null,
  }));
  return {
    declaration,
    document,
    sourceId,
    methodId,
    connectionId,
    declarations,
    bindings,
  };
}
