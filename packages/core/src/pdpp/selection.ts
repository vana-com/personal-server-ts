/**
 * PDPP Core §6 selection-request validation.
 *
 * This is the shape gate that runs before consent. It answers one question:
 * is this request expressible against the retained declaration snapshot? It
 * does not resolve anything — `resolve.ts` does that, and only against the
 * same snapshot this module validated against.
 *
 * "Fails neutrally" in §6 means the both/neither `streams`/`selection_preset`
 * failure is a Source validation failure the binding maps to an error code; it
 * must not leak which of the two the client got wrong, and it must not depend
 * on any owner-specific state. We return a binding-neutral failure and let the
 * OAuth/RAR layer map it to RFC 9396 `invalid_authorization_details`.
 */

import {
  PDPP_DATA_ACCESS_TYPE,
  type DeclarationSnapshot,
  type SelectionRequest,
  type StreamRequest,
} from "./types.js";

/**
 * Binding-neutral validation failure codes. The OAuth/RAR binding maps these
 * to wire errors in `../../../server/src/routes/pdpp-authorize.ts`; Core
 * itself stays binding-neutral (§9 AS item 5).
 */
export type SelectionFailureCode =
  /** Both or neither of `streams` and `selection_preset`. */
  | "source_validation_failed"
  | "unknown_stream"
  | "unknown_preset"
  | "unknown_view"
  | "unknown_field"
  | "unsupported_selection_parameter"
  | "invalid_resource_key"
  | "invalid_request";

export interface SelectionFailure {
  code: SelectionFailureCode;
  message: string;
}

export type SelectionValidation =
  { ok: true } | { ok: false; failure: SelectionFailure };

function fail(
  code: SelectionFailureCode,
  message: string,
): SelectionValidation {
  return { ok: false, failure: { code, message } };
}

/**
 * Canonical key strings: a plain string for a simple key, a minified JSON
 * array for a compound key (§6 `resources`). We validate arity and type
 * against the declaration's `primary_key` here so an unsatisfiable resource
 * list is rejected at issuance rather than silently matching nothing at the RS.
 */
function validateResourceKey(raw: string, primaryKey: string[]): string | null {
  if (primaryKey.length <= 1) {
    // A simple key is a plain string. A JSON array here is an arity error.
    if (raw.startsWith("[")) {
      return "expected a simple key string, got a compound key array";
    }
    return raw.length > 0 ? null : "resource key must not be empty";
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return "compound resource key must be a minified JSON array";
  }
  if (!Array.isArray(parsed)) {
    return "compound resource key must be a JSON array";
  }
  if (parsed.length !== primaryKey.length) {
    return `compound resource key has ${parsed.length} parts, declaration primary_key has ${primaryKey.length}`;
  }
  if (!parsed.every((part) => typeof part === "string")) {
    return "compound resource key parts must be strings";
  }
  return null;
}

function validateStreamRequest(
  stream: StreamRequest,
  snapshot: DeclarationSnapshot,
): SelectionValidation {
  // A wildcard is checked by the caller (it must be the sole entry) and
  // expands during resolution, so there is no declared stream to match yet.
  if (stream.name === "*") {
    if (stream.view !== undefined) {
      return fail(
        "unsupported_selection_parameter",
        "view cannot be combined with a wildcard stream selection",
      );
    }
    return { ok: true };
  }

  const declared = snapshot.streams.find((s) => s.name === stream.name);
  if (!declared) {
    return fail(
      "unknown_stream",
      `stream '${stream.name}' is not declared by the retained snapshot`,
    );
  }

  if (stream.view !== undefined && stream.fields !== undefined) {
    return fail(
      "invalid_request",
      `stream '${stream.name}' specifies both view and fields, which are mutually exclusive`,
    );
  }

  if (stream.view !== undefined) {
    const view = snapshot.views?.find((v) => v.name === stream.view);
    if (!view) {
      return fail(
        "unknown_view",
        `view '${stream.view}' is not defined for this source`,
      );
    }
    // §9 AS item 12: a view naming a field absent from the retained schema is
    // not resolvable, and we reject rather than silently dropping the field.
    const absent = view.fields.filter((f) => !declared.fields.includes(f));
    if (absent.length > 0) {
      return fail(
        "unknown_field",
        `view '${stream.view}' names fields absent from stream '${stream.name}': ${absent.join(", ")}`,
      );
    }
  }

  if (stream.fields !== undefined) {
    if (stream.fields.length === 0) {
      return fail(
        "invalid_request",
        `stream '${stream.name}' specifies an empty fields list`,
      );
    }
    const absent = stream.fields.filter((f) => !declared.fields.includes(f));
    if (absent.length > 0) {
      return fail(
        "unknown_field",
        `stream '${stream.name}' requests fields absent from the retained schema: ${absent.join(", ")}`,
      );
    }
  }

  if (stream.time_range !== undefined) {
    // §6: the declaration's consent_time_field is the authoritative signal
    // that a stream is time-range-capable. No field, no time_range.
    if (!declared.consent_time_field) {
      return fail(
        "unsupported_selection_parameter",
        `stream '${stream.name}' declares no consent_time_field and cannot accept time_range`,
      );
    }
    const { since, until } = stream.time_range;
    if (since === undefined && until === undefined) {
      return fail(
        "invalid_request",
        `stream '${stream.name}' has an empty time_range`,
      );
    }
    for (const [label, value] of [
      ["since", since],
      ["until", until],
    ] as const) {
      if (value !== undefined && Number.isNaN(Date.parse(value))) {
        return fail(
          "invalid_request",
          `stream '${stream.name}' time_range.${label} is not a valid ISO 8601 instant`,
        );
      }
    }
    if (since !== undefined && until !== undefined) {
      if (Date.parse(since) >= Date.parse(until)) {
        return fail(
          "invalid_request",
          `stream '${stream.name}' time_range.since must precede time_range.until`,
        );
      }
    }
  }

  if (stream.resources !== undefined) {
    if (stream.resources.length === 0) {
      return fail(
        "invalid_request",
        `stream '${stream.name}' specifies an empty resources list`,
      );
    }
    for (const raw of stream.resources) {
      const problem = validateResourceKey(raw, declared.primary_key);
      if (problem) {
        return fail(
          "invalid_resource_key",
          `stream '${stream.name}' resource '${raw}': ${problem}`,
        );
      }
    }
  }

  return { ok: true };
}

/**
 * Validate one selection request against the retained declaration snapshot.
 *
 * The caller must have already retrieved and pinned `snapshot`; this function
 * never fetches. §9 AS item 16 requires that the same snapshot carry through
 * consent and issuance, so passing a freshly fetched declaration here and a
 * different one to `resolveGrant` would defeat the whole guarantee.
 */
export function validateSelectionRequest(
  request: SelectionRequest,
  snapshot: DeclarationSnapshot,
): SelectionValidation {
  if (request.type !== PDPP_DATA_ACCESS_TYPE) {
    return fail(
      "invalid_request",
      `authorization detail type must be ${PDPP_DATA_ACCESS_TYPE}`,
    );
  }

  if (request.source.id !== snapshot.source_id) {
    return fail(
      "invalid_request",
      "request source.id does not match the retained declaration snapshot",
    );
  }

  // §6: the purpose code must be a syntactically valid absolute URI, and that
  // is the only syntactic gate. §9 AS item 6 forbids rejecting a code merely
  // for being absent from the registry — an unregistered code renders from its
  // description or raw URI instead.
  if (!isAbsoluteUri(request.purpose_code)) {
    return fail("invalid_request", "purpose_code must be an absolute URI");
  }

  if (
    request.access_mode !== "single_use" &&
    request.access_mode !== "continuous"
  ) {
    return fail(
      "invalid_request",
      "access_mode must be single_use or continuous",
    );
  }

  if (request.retention !== undefined) {
    const { on_expiry } = request.retention;
    if (on_expiry !== "delete" && on_expiry !== "anonymize") {
      // `archive` was dropped in v0.1 and is the likely wrong value here.
      return fail(
        "invalid_request",
        "retention.on_expiry must be delete or anonymize",
      );
    }
  }

  const hasStreams = request.streams !== undefined;
  const hasPreset = request.selection_preset !== undefined;
  if (hasStreams === hasPreset) {
    // Both or neither. Deliberately one message for both cases: the failure
    // is about the pair, and distinguishing them tells a probing client which
    // half the server accepted.
    return fail(
      "source_validation_failed",
      "exactly one of streams or selection_preset is required",
    );
  }

  if (hasPreset) {
    const preset = snapshot.selection_presets?.find(
      (p) => p.name === request.selection_preset,
    );
    if (!preset) {
      return fail(
        "unknown_preset",
        `selection preset '${request.selection_preset}' is not defined by the retained snapshot`,
      );
    }
    // The preset's own streams still have to be expressible against the
    // snapshot; a declaration that ships a preset naming a dropped stream is
    // invalid and we would rather fail here than resolve an empty grant.
    for (const stream of preset.streams) {
      const result = validateStreamRequest(stream, snapshot);
      if (!result.ok) return result;
    }
    return { ok: true };
  }

  const streams = request.streams ?? [];
  if (streams.length === 0) {
    return fail("invalid_request", "streams must not be empty");
  }

  const wildcards = streams.filter((s) => s.name === "*");
  if (wildcards.length > 0 && streams.length > 1) {
    return fail(
      "invalid_request",
      "a wildcard stream entry must be the only entry in streams",
    );
  }

  const seen = new Set<string>();
  for (const stream of streams) {
    if (seen.has(stream.name)) {
      return fail(
        "invalid_request",
        `stream '${stream.name}' appears more than once`,
      );
    }
    seen.add(stream.name);

    const result = validateStreamRequest(stream, snapshot);
    if (!result.ok) return result;
  }

  return { ok: true };
}

function isAbsoluteUri(value: string): boolean {
  try {
    // URL rejects relative references, which is exactly the check we want.
    new URL(value);
    return true;
  } catch {
    return false;
  }
}
