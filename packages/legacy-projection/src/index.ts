// biome-ignore lint/performance/noBarrelFile: re-exported through @vana-unity/app-runtime/sources
import { LEGACY_SCOPE_BINDINGS, LEGACY_SCOPE_GAPS } from "./bindings.js";
import { GITHUB_BROWSER_BINDINGS } from "./github-browser-bindings.js";
import { META_040_BINDINGS } from "./meta-040-bindings.js";
import { OURA_BROWSER_BINDINGS } from "./oura-browser-bindings.js";
import { classifyAsTestDebris } from "./test-debris.js";
import type {
  LegacyScopeBinding,
  LegacyScopeLookupResult,
  PdppRecord,
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
  const result = binding.project(records, options);
  if (!result.ok) return result;

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
    (diagnostic) =>
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

function bindingFor(scope: string, profileKey?: string) {
  const original = LEGACY_SCOPE_BINDINGS.get(scope);
  if (!original || !profileKey) return original;
  return legacyBindingsForProfile(profileKey).get(scope);
}
