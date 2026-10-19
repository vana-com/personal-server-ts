// biome-ignore lint/performance/noBarrelFile: re-exported through @vana-unity/app-runtime/sources
import {
  GROCERY_INVALID_ORDER,
  LEGACY_SCOPE_BINDINGS,
  LEGACY_SCOPE_GAPS,
} from "./bindings.js";
import { GITHUB_BROWSER_BINDINGS } from "./github-browser-bindings.js";
import { META_040_BINDINGS } from "./meta-040-bindings.js";
import { OURA_BROWSER_BINDINGS } from "./oura-browser-bindings.js";
import { classifyAsTestDebris } from "./test-debris.js";
import {
  decodeDeclaredRecordsForProjection,
  DeclaredTextError,
} from "./declared-text.js";
import type {
  LegacyScopeBinding,
  LegacyScopeLookupResult,
  PdppRecord,
  ProjectionDiagnostic,
  ProjectPdppRecordsOptions,
  ProjectionResult,
} from "./types.js";

export { LEGACY_SCOPE_BINDINGS } from "./bindings.js";
export { LEGACY_SCOPE_GAPS } from "./bindings.js";
export { GITHUB_BROWSER_BINDINGS } from "./github-browser-bindings.js";
export { META_040_BINDINGS } from "./meta-040-bindings.js";
export { OURA_BROWSER_BINDINGS } from "./oura-browser-bindings.js";
export type { LegacyScopeBindingProvenance } from "./provenance.js";
export { classifyAsTestDebris } from "./test-debris.js";
export type {
  LegacyScopeBinding,
  LegacyScopeLookupError,
  LegacyScopeLookupResult,
  PdppRecord,
  PdppSelection,
  ProjectionDiagnostic,
  ProjectionOmission,
  ProjectionError,
  ProjectionResult,
  ProjectPdppRecordsOptions,
} from "./types.js";

const ALTERNATE_PROFILE_BINDINGS: ReadonlyMap<
  string,
  ReadonlyMap<string, LegacyScopeBinding>
> = new Map([
  ["github-browser", GITHUB_BROWSER_BINDINGS],
  ["meta", META_040_BINDINGS],
  ["oura-browser", OURA_BROWSER_BINDINGS],
]);

export function hasAlternateLegacyProfile(profileKey: string): boolean {
  return ALTERNATE_PROFILE_BINDINGS.has(profileKey);
}

/** Only declaration-reviewed profile keys may project into retained scopes. */
export function legacyBindingsForProfile(
  profileKey: string,
): ReadonlyMap<string, LegacyScopeBinding> {
  const alternate = ALTERNATE_PROFILE_BINDINGS.get(profileKey);
  if (alternate) return alternate;
  return new Map(
    [...LEGACY_SCOPE_BINDINGS].filter(([, binding]) =>
      binding.pdppSource.endsWith(`/${profileKey}`),
    ),
  );
}

/**
 * Translate an exact legacy scope string to the PDPP selection an already
 * deployed app should now be served from. Exact string match only — a known
 * gap is distinct from an unknown scope, and neither is guessed.
 */
export function legacyScopeToPdppSelection(
  scope: string,
  options: { profileKey?: string } = {},
): LegacyScopeLookupResult {
  const debrisReason = classifyAsTestDebris(scope);
  if (debrisReason) {
    return {
      ok: false,
      error: { kind: "test_debris_scope", scope, reason: debrisReason },
    };
  }

  const binding = bindingFor(scope, options.profileKey);
  if (!binding) {
    if (LEGACY_SCOPE_BINDINGS.has(scope) && options.profileKey) {
      return {
        ok: false,
        error: {
          kind: "unsupported_profile",
          scope,
          profileKey: options.profileKey,
        },
      };
    }
    const gap = LEGACY_SCOPE_GAPS.get(scope);
    if (gap) {
      return {
        ok: false,
        error: {
          kind: "gap",
          scope,
          reason: gap.reason,
          provenanceChecked: gap.provenanceChecked,
        },
      };
    }
    return { ok: false, error: { kind: "unknown_scope", scope } };
  }

  return {
    ok: true,
    selection: { source: binding.pdppSource, streams: binding.pdppStreams },
  };
}

/**
 * Project PDPP records back to the payload shape an existing app receives
 * today for `scope`. `records` must already be scoped to the single source
 * the binding names; this function does not itself call a Personal Server.
 *
 * `options.fetchedStreams` must list every stream the caller actually asked
 * the Personal Server for, independent of whether any record came back for
 * it. A stream missing from `fetchedStreams` is `missing_stream`. A stream
 * present in `fetchedStreams` with zero matching `records` is a real,
 * legitimate empty result (e.g. zero starred repos), not an error.
 */
export function projectPdppRecordsToLegacyPayload(
  scope: string,
  records: PdppRecord[],
  options: ProjectPdppRecordsOptions,
): ProjectionResult {
  const binding = bindingFor(scope, options.profileKey);
  if (!binding) {
    if (LEGACY_SCOPE_BINDINGS.has(scope) && options.profileKey) {
      return {
        ok: false,
        error: {
          kind: "unsupported_profile",
          scope,
          profileKey: options.profileKey,
        },
      };
    }
    const gap = LEGACY_SCOPE_GAPS.get(scope);
    if (gap) {
      return { ok: false, error: { kind: "gap", scope, reason: gap.reason } };
    }
    return { ok: false, error: { kind: "unknown_scope", scope } };
  }
  let decodeDiagnostics: ProjectionDiagnostic[] = [];
  try {
    const decoded = decodeDeclaredRecordsForProjection(
      records,
      options.streamSchemas,
      scope,
    );
    records = decoded.records;
    decodeDiagnostics = decoded.diagnostics;
  } catch (error) {
    if (!(error instanceof DeclaredTextError)) throw error;
    return { ok: false, error: error.projectionError(scope) };
  }
  const result = binding.project(
    options.orderByPrimaryKey
      ? inPrimaryKeyOrder(records, binding.primaryKey)
      : records,
    options,
  );
  if (!result.ok) return result;
  if (decodeDiagnostics.length > 0) {
    result.diagnostics = [...decodeDiagnostics, ...(result.diagnostics ?? [])];
  }
  if (scope.startsWith("oura.") && options.profileKey !== "oura-browser") {
    assertOuraLegacyScoresAreIntegers(scope, result.payload);
  }

  // These bindings drop and count malformed rows themselves (see their
  // records_dropped diagnostics) instead of failing the whole scope.
  if (DROP_AND_COUNT_SCOPES.has(scope)) return result;

  // An order dropped and counted for its unusable id may pass the key check;
  // every other malformed key stays fatal.
  let reportedInvalidOrders = (result.diagnostics ?? []).reduce(
    (total, diagnostic) =>
      diagnostic.kind === "records_dropped" &&
      diagnostic.stream === "orders" &&
      diagnostic.reasons.includes(GROCERY_INVALID_ORDER)
        ? total + diagnostic.count
        : total,
    0,
  );
  for (const record of records) {
    if (!binding.pdppStreams.includes(record.stream)) continue;
    if (
      record.data === null ||
      typeof record.data !== "object" ||
      Array.isArray(record.data)
    ) {
      return {
        ok: false,
        error: {
          kind: "incomplete_scope",
          scope,
          reason: `${record.stream} record is unavailable`,
        },
      };
    }
    for (const key of binding.primaryKey[record.stream] ?? []) {
      const value = record.data[key];
      if (
        value === null ||
        value === undefined ||
        (typeof value === "string" && !value.trim())
      ) {
        if (record.stream === "orders" && reportedInvalidOrders > 0) {
          reportedInvalidOrders -= 1;
          break;
        }
        return {
          ok: false,
          error: {
            kind: "incomplete_scope",
            scope,
            reason: `${record.stream}.${key} is unavailable`,
          },
        };
      }
    }
  }

  // A schema-valid subset is still incomplete. A fetched stream with zero
  // source rows remains a valid empty success.
  const skipped = result.diagnostics?.filter(
    (diagnostic): diagnostic is RecordsSkipped =>
      diagnostic.kind === "records_skipped" && diagnostic.count > 0,
  );
  if (skipped?.length) {
    return {
      ok: false,
      error: {
        kind: "incomplete_scope",
        scope,
        reason: skipped
          .map(
            ({ count, missingFields }) =>
              `${count} source records missing ${missingFields.join(", ")}`,
          )
          .join("; "),
      },
    };
  }
  return result;
}

const DROP_AND_COUNT_SCOPES: ReadonlySet<string> = new Set([
  "chatgpt.conversations",
]);

/** Keep OpenPet's Go `*int` score decoding safe for every Oura projection. */
export function assertOuraLegacyScoresAreIntegers(
  scope: string,
  payload: Record<string, unknown>,
): void {
  for (const collection of ["days", "dailyScores"] as const) {
    const rows = payload[collection];
    if (!Array.isArray(rows)) continue;
    for (const [index, row] of rows.entries()) {
      if (row === null || typeof row !== "object") continue;
      // `score` is required on every daily score row: absent and undefined
      // (dropped by JSON serialization) are both rejected.
      const score = (row as Record<string, unknown>).score;
      if (
        score === null ||
        (typeof score === "number" && Number.isInteger(score))
      )
        continue;
      throw new Error(
        `${scope}.${collection}[${index}].score must be an integer or null`,
      );
    }
  }
}

type RecordsSkipped = Extract<
  ProjectionDiagnostic,
  { kind: "records_skipped" }
>;

/**
 * Stable sort by (stream, primary-key values). Rows with equal keys, or of a
 * stream without a declared key, keep their input order.
 */
function inPrimaryKeyOrder(
  records: PdppRecord[],
  primaryKey: Record<string, string[]>,
): PdppRecord[] {
  const keyOf = (record: PdppRecord): string => {
    const data = record.data as Record<string, unknown> | null | undefined;
    const fields = primaryKey[record.stream] ?? [];
    return JSON.stringify(
      fields.map((field) =>
        data && typeof data === "object" ? (data[field] ?? null) : null,
      ),
    );
  };
  return records
    .map((record, index) => ({ record, index, key: keyOf(record) }))
    .sort((a, b) => {
      if (a.record.stream !== b.record.stream)
        return a.record.stream < b.record.stream ? -1 : 1;
      if (a.key !== b.key) return a.key < b.key ? -1 : 1;
      return a.index - b.index;
    })
    .map(({ record }) => record);
}

function bindingFor(scope: string, profileKey?: string) {
  const original = LEGACY_SCOPE_BINDINGS.get(scope);
  if (!original || !profileKey) return original;
  return legacyBindingsForProfile(profileKey).get(scope);
}
