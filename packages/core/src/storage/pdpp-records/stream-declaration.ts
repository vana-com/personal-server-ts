import type { StreamSemantics } from "./types.js";

/**
 * The minimal per-stream declaration this lane needs from spec-core.md
 * Section 5 "Source Declaration" — NOT a full Source Declaration model (that
 * is Collection Profile / Lane D territory, out of scope here). This lane
 * only needs enough to validate ingest and serve §8 reads: semantics,
 * primary key, the field used for stable list ordering / incremental sync,
 * and which fields are schema-required (always included in a sparse
 * projection per spec §8 "fields" parameter).
 */
export interface StreamDeclaration {
  name: string;
  semantics: StreamSemantics;
  primaryKey: string[];
  cursorField: string;
  /** Fields declared as consent_time_field candidates for time_constraint enforcement. */
  consentTimeField?: string;
  /** Always included in a sparse `fields` projection, even if not requested. */
  requiredFields: string[];
  /**
   * The stream's JSON Schema from the retained declaration (§5).
   *
   * §8 stream metadata carries this so a client can understand record shape
   * without a second lookup. Optional because a deployment may boot from a
   * private-shape declaration that has no schema to carry; the route then
   * falls back to a field-name projection rather than fabricating one.
   */
  schema?: Record<string, unknown>;
  /**
   * The stream's declared selection capabilities (§5), e.g.
   * `{ fields: true, resources: false }`. §8 metadata reports what the source
   * supports so a client knows which selections are even expressible.
   */
  selection?: Record<string, unknown>;
}

export interface StreamDeclarationRegistry {
  get(stream: string): StreamDeclaration | undefined;
  list(): StreamDeclaration[];
}

export function createStreamDeclarationRegistry(
  declarations: StreamDeclaration[],
): StreamDeclarationRegistry {
  const byName = new Map(declarations.map((d) => [d.name, d]));
  return {
    get: (stream: string) => byName.get(stream),
    list: () => declarations,
  };
}

/** Schema-required fields are always included, even under a sparse `fields` request. */
export function withRequiredFields(
  requested: string[] | undefined,
  required: string[],
): string[] | undefined {
  if (!requested) return undefined;
  const merged = new Set(requested);
  for (const field of required) merged.add(field);
  return Array.from(merged);
}
