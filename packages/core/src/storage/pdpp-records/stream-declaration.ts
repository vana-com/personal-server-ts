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
   * Every top-level member the retained declaration declares for this stream.
   *
   * This is the RS's only authority for what a record of this stream MEANS. A
   * v0.2 grant naming a member that is not here cannot be served: the RS
   * cannot tell whether the member is absent from every record, was renamed,
   * or is something the record happens to carry under that key — and each
   * possible answer discloses a different, unverified thing. That read is
   * refused with `disclosure_unavailable` rather than quietly resolved.
   *
   * Optional because a v0.1 deployment may boot from a declaration shape that
   * carries no field list, and a v0.1 grant has no approved projection to
   * check against. Absent means "no check", never "no fields".
   */
  declaredFields?: string[];
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

/**
 * Stream declarations, keyed by source and stream name.
 *
 * Stream names are only unique within one source: two sources may both
 * declare `profile` with different keys and schemas. Every lookup that
 * decides how to validate or disclose a record therefore names the source,
 * directly or through the instance that holds the record.
 */
export interface StreamDeclarationRegistry {
  /**
   * The declaration for `stream`. With `sourceId`, that source's own
   * declaration. Without it, the declaration only when exactly one source
   * declares the name; `undefined` when none or several do.
   */
  get(stream: string, sourceId?: string): StreamDeclaration | undefined;
  /** The declaration that governs `stream` records held in `instance`. */
  forInstance(instance: string, stream: string): StreamDeclaration | undefined;
  /** True when at least one source declares `stream`. */
  declares(stream: string): boolean;
  list(): StreamDeclaration[];
}

/**
 * A registry for a deployment that serves one source, or a test that does
 * not care which source a stream belongs to. Every instance and source
 * resolves to the same declaration for a name.
 */
export function createStreamDeclarationRegistry(
  declarations: StreamDeclaration[],
): StreamDeclarationRegistry {
  const byName = new Map(declarations.map((d) => [d.name, d]));
  return {
    get: (stream: string) => byName.get(stream),
    forInstance: (_instance: string, stream: string) => byName.get(stream),
    declares: (stream: string) => byName.has(stream),
    list: () => declarations,
  };
}

export interface SourceStreamDeclarations {
  sourceId: string;
  /** The instance handle this deployment holds the source's records under. */
  instance: string;
  streams: StreamDeclaration[];
}

/** A registry for several sources, keyed by `(source.id, stream)`. */
export function createSourceStreamDeclarationRegistry(
  sources: SourceStreamDeclarations[],
): StreamDeclarationRegistry {
  const bySource = new Map<string, Map<string, StreamDeclaration>>();
  const sourceByInstance = new Map<string, string>();
  const declaringSources = new Map<string, StreamDeclaration[]>();
  for (const source of sources) {
    bySource.set(
      source.sourceId,
      new Map(source.streams.map((d) => [d.name, d])),
    );
    sourceByInstance.set(source.instance, source.sourceId);
    for (const stream of source.streams) {
      const list = declaringSources.get(stream.name) ?? [];
      list.push(stream);
      declaringSources.set(stream.name, list);
    }
  }
  return {
    get(stream, sourceId) {
      if (sourceId !== undefined) return bySource.get(sourceId)?.get(stream);
      const candidates = declaringSources.get(stream) ?? [];
      return candidates.length === 1 ? candidates[0] : undefined;
    },
    forInstance(instance, stream) {
      const sourceId = sourceByInstance.get(instance);
      return sourceId === undefined
        ? undefined
        : bySource.get(sourceId)?.get(stream);
    },
    declares: (stream) => declaringSources.has(stream),
    list: () => sources.flatMap((source) => source.streams),
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
