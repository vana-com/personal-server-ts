import type { LegacyScopeBindingProvenance } from "./provenance.js";

/** A PDPP selection: one source, one or more streams, no field filter (phase 1 always requests full records). */
export interface PdppSelection {
  source: string;
  streams: string[];
}

/** One raw PDPP record as returned by a Personal Server read, for one stream. */
export interface PdppRecord {
  data: Record<string, unknown>;
  stream: string;
}

export type LegacyScopeLookupError =
  | { kind: "unknown_scope"; scope: string }
  | { kind: "unsupported_profile"; scope: string; profileKey: string }
  | { kind: "test_debris_scope"; scope: string; reason: string }
  | {
      kind: "gap";
      scope: string;
      reason: string;
      provenanceChecked: LegacyScopeBindingProvenance[];
    };

export interface LegacyScopeLookupOk {
  ok: true;
  selection: PdppSelection;
}
export interface LegacyScopeLookupErr {
  error: LegacyScopeLookupError;
  ok: false;
}
export type LegacyScopeLookupResult =
  LegacyScopeLookupOk | LegacyScopeLookupErr;

export type ProjectionError =
  | { kind: "unknown_scope"; scope: string }
  | { kind: "unsupported_profile"; scope: string; profileKey: string }
  | { kind: "missing_stream"; scope: string; expectedStream: string }
  | { kind: "invalid_value"; scope: string; reason: string }
  | { kind: "incomplete_scope"; scope: string; reason: string }
  | { kind: "gap"; scope: string; reason: string }
  | { kind: "empty_singleton"; scope: string };

export interface ProjectionOk {
  diagnostics?: ProjectionDiagnostic[];
  ok: true;
  payload: Record<string, unknown>;
}
/**
 * `records_skipped` makes the whole projection `incomplete_scope`.
 * `records_dropped` and `stream_missing` do not: the payload is served
 * without the named rows, and the diagnostic says how many were left out.
 */
export type ProjectionDiagnostic =
  | {
      count: number;
      kind: "records_skipped";
      missingFields: string[];
      scope: string;
    }
  | {
      count: number;
      kind: "records_dropped";
      reasons: string[];
      scope: string;
      stream: string;
    }
  | { kind: "stream_missing"; scope: string; stream: string };
export interface ProjectionErr {
  error: ProjectionError;
  ok: false;
}
export type ProjectionResult = ProjectionOk | ProjectionErr;

/**
 * Which streams a caller actually fetched for this request, distinct from
 * which of those streams produced records. A stream absent from this list
 * was never fetched (`missing_stream`); a stream present in this list with
 * zero matching records in `records` legitimately had zero rows. This is
 * how "fetched, zero rows" is expressed without a fake marker record.
 */
export interface ProjectPdppRecordsOptions {
  fetchedStreams: string[];
  /** Selected signed connector key. Omitted for the original PAT binding. */
  profileKey?: string;
  /**
   * ISO timestamp for generated fields (`fetched_at`, `fetchedAt`, a null
   * memory `created_at`). Pass it to make the same records project to the
   * same bytes. Defaults to the wall clock.
   */
  now?: string;
  /**
   * A stream absent from `fetchedStreams` normally fails with
   * `missing_stream`. When this is true, a binding that can still produce a
   * useful payload without a join stream does so and reports
   * `stream_missing` instead. Today only `chatgpt.conversations` can (it
   * projects conversations with `messages: []`). For read-time callers whose
   * join stream has no stored version yet.
   */
  allowMissingJoinStreams?: boolean;
  /**
   * Feed rows to the binding sorted by (stream, primary key) instead of in
   * input order, so the output does not depend on the order rows were
   * stored in. Top-level arrays then follow key order, not source order.
   */
  orderByPrimaryKey?: boolean;
}

/**
 * One legacy scope's binding. `project` and `requiredStreams` are absent for
 * a scope this phase declares a gap for (see LEGACY_SCOPE_GAPS) — a gap has
 * no binding entry at all, by design: "no entry, no fabricated mapping."
 */
export interface LegacyScopeBinding {
  /**
   * Per bound stream, the exact set of declared field names `project()`
   * reads off that stream's records. Checked by the self-check against the
   * vendored declaration's own `schema.properties` keys — deleting or
   * renaming a field here in the declaration must make this list disagree
   * and fail the self-check (S1).
   */
  fieldsRead: Record<string, string[]>;
  /** Legacy JSON Schema path this binding's output must validate against, relative to ./legacy-schemas. */
  legacySchemaPath: string;
  /**
   * Every legacy field this binding drops, derives, reformats, or defaults,
   * relative to the legacy connector source at the pin — not "not yet
   * implemented", the permanent, documented shape of this projection.
   */
  lossy: string[];
  /** The PDPP source id (`connector_id`), e.g. "https://registry.pdpp.dev/connectors/meta" — never the short connector key. */
  pdppSource: string;
  pdppStreams: string[];
  /**
   * Per bound stream, the exact primary-key field list `project()` relies on
   * for joins/dedup (e.g. amazon's order_items→orders join key). Checked by
   * the self-check for exact equality with the vendored declaration's own
   * `primary_key` — a binding that names a declared-but-wrong key must fail.
   */
  primaryKey: Record<string, string[]>;
  project: (
    records: PdppRecord[],
    options: ProjectPdppRecordsOptions,
  ) => ProjectionResult;
  provenance: LegacyScopeBindingProvenance[];
  scope: string;
}
